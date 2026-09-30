'use strict';
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { execFile, spawn } = require('node:child_process');
const { promisify } = require('node:util');
const { randomUUID } = require('node:crypto');
const run = promisify(execFile);

function appExecutable(candidate, platform = process.platform) {
  if (!candidate || !path.isAbsolute(candidate)) return null;
  if (platform === 'darwin' && candidate.endsWith('.app')) candidate = ['Codex', 'ChatGPT'].map(name => path.join(candidate, 'Contents/MacOS', name)).find(p => fs.existsSync(p)) || '';
  if (platform === 'win32' && (!/^(codex|chatgpt)\.exe$/i.test(path.basename(candidate)) || !fs.existsSync(path.join(path.dirname(candidate), 'resources', 'app.asar')))) return null;
  if (platform === 'linux' && (!/^(codex|chatgpt)$/i.test(path.basename(candidate)) || !fs.existsSync(path.join(path.dirname(candidate), 'resources', 'app.asar')))) return null;
  // Recent Store builds use a small Codex.exe compatibility launcher. The
  // registered ChatGPT.exe is the actual GUI and inherits our isolated env.
  if (platform === 'win32' && /^codex\.exe$/i.test(path.basename(candidate)) && fs.existsSync(path.join(path.dirname(candidate), 'ChatGPT.exe'))) candidate = path.join(path.dirname(candidate), 'ChatGPT.exe');
  try { return fs.statSync(candidate).isFile() ? candidate : null; } catch { return null; }
}
async function discoverApp(preferred) {
  let executable = appExecutable(preferred);
  if (executable && !/[\\/]WindowsApps[\\/]/i.test(executable)) return { installed: true, binary: executable };
  const candidates = process.platform === 'darwin'
    ? ['/Applications/Codex.app', '/Applications/ChatGPT.app', path.join(os.homedir(), 'Applications/Codex.app'), path.join(os.homedir(), 'Applications/ChatGPT.app')]
    : process.platform === 'linux'
      ? ['/opt/Codex/codex','/opt/codex/codex',path.join(os.homedir(),'.local/share/Codex/codex')]
      : [path.join(process.env.LOCALAPPDATA || os.homedir(), 'Programs/Codex/Codex.exe'), path.join(process.env.LOCALAPPDATA || os.homedir(), 'Codex/Codex.exe')];
  if (process.platform === 'win32') {
    try {
      const { stdout } = await run('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', '[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Get-AppxPackage -Name OpenAI.Codex | Sort-Object Version -Descending | ForEach-Object { Join-Path $_.InstallLocation "app/Codex.exe" }'], { windowsHide: true, timeout: 7000, encoding: 'utf8' });
      candidates.push(...stdout.trim().split(/\r?\n/));
    } catch { /* Manual picker supports nonstandard installations. */ }
  }
  if (preferred) candidates.push(preferred);
  for (const candidate of candidates) if ((executable = appExecutable(candidate))) return { installed: true, binary: executable };
  return { installed: false, binary: '', error: process.platform === 'linux' ? '未检测到兼容的 Codex 图形程序；Linux 可使用 Codex CLI，或手动指定已有图形客户端' : '未找到 Codex App，请安装官方客户端或手动选择应用路径' };
}
function launchEnvironment(home, key, env = process.env, mode = 'isolated') {
  const clean = Object.fromEntries(Object.entries(env).filter(([k]) => !/^(CODEX_|GPTBRIDGE_|ELECTRON_|NODE_OPTIONS$|OPENAI_API_KEY$|OPENAI_BASE_URL$)/i.test(k)));
  const identity = path.join(home, 'bridge-identity.json');
  if (fs.existsSync(identity)) clean.CODEX_AUTHAPI_BASE_URL = JSON.parse(fs.readFileSync(identity, 'utf8')).auth_api_url;
  return { ...clean, CODEX_HOME: home, ...(mode === 'isolated' ? {CODEX_ELECTRON_USER_DATA_PATH:path.join(home,'app-data')} : {}), GPTBRIDGE_CODEX_KEY: key };
}
const psQuote = value => "'" + value.replaceAll("'", "''") + "'";
async function launchStoreApp(executable, home, configPath, mode) {
  const resultFile = path.join(home, `app-launch-${randomUUID()}.json`);
  // Packaged Windows APIs require package identity. Shell AppsFolder would
  // discard the selected profile, so run a hidden helper inside this package.
  const inner = `$ErrorActionPreference='Stop'
try {
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = ${psQuote(executable)}
  $psi.UseShellExecute = $false
  $psi.WorkingDirectory = ${psQuote(os.homedir())}
  $psi.Arguments = ${psQuote(mode === 'isolated' ? '"--user-data-dir=' + path.join(home, 'app-data') + '"' : '')}
  foreach ($k in @($psi.EnvironmentVariables.Keys)) { if ($k -match '^(CODEX_|GPTBRIDGE_|ELECTRON_|NODE_OPTIONS$|OPENAI_API_KEY$|OPENAI_BASE_URL$)') { $psi.EnvironmentVariables.Remove($k) } }
  $psi.EnvironmentVariables['CODEX_HOME'] = ${psQuote(home)}
  ${mode === 'isolated' ? "$psi.EnvironmentVariables['CODEX_ELECTRON_USER_DATA_PATH'] = " + psQuote(path.join(home, 'app-data')) : ''}
  $identity = ${psQuote(path.join(home, 'bridge-identity.json'))}
  if (Test-Path -LiteralPath $identity) { $psi.EnvironmentVariables['CODEX_AUTHAPI_BASE_URL'] = (Get-Content -Raw -LiteralPath $identity | ConvertFrom-Json).auth_api_url }
  $psi.EnvironmentVariables['GPTBRIDGE_CODEX_KEY'] = (Get-Content -Raw -LiteralPath ${psQuote(configPath)} | ConvertFrom-Json).api_key
  $child = [System.Diagnostics.Process]::Start($psi)
  Start-Sleep -Milliseconds 1800
  if ($child.HasExited -and $child.ExitCode -ne 0) { throw ('App exit: ' + $child.ExitCode) }
  @{pid=$child.Id} | ConvertTo-Json | Set-Content -Encoding UTF8 -LiteralPath ${psQuote(resultFile)}
} catch { @{error=$_.Exception.Message} | ConvertTo-Json | Set-Content -Encoding UTF8 -LiteralPath ${psQuote(resultFile)} }`;
  const encoded = Buffer.from(inner, 'utf16le').toString('base64');
  const outer = `$ErrorActionPreference='Stop'; $location=${psQuote(path.dirname(path.dirname(executable)))}; $pkg=Get-AppxPackage -Name OpenAI.Codex | Where-Object { $_.InstallLocation -eq $location } | Select-Object -First 1; if (-not $pkg) { throw 'Registered Codex package not found' }; $id=((Get-AppxPackageManifest -Package $pkg).Package.Applications.Application | Select-Object -First 1).Id; Invoke-CommandInDesktopPackage -PackageFamilyName $pkg.PackageFamilyName -AppId $id -Command 'powershell.exe' -Args '-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand ${encoded}'`;
  try {
    await run('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(outer, 'utf16le').toString('base64')], { windowsHide: true, timeout: 12000, encoding: 'utf8' });
    for (let i=0;i<80;i++) {
      if (fs.existsSync(resultFile)) { let result; try { result=JSON.parse(fs.readFileSync(resultFile,'utf8').replace(/^\uFEFF/,'')); } catch { /* helper may still be writing */ }
        if (result) { if (result.error) throw new Error(result.error); return { pid: result.pid, app_data: mode === 'isolated' ? path.join(home,'app-data') : '', app_mode:mode, packaged: true }; }
      }
      await new Promise(resolve=>setTimeout(resolve,150));
    }
    throw new Error('Codex 商店版启动未确认，请检查安装状态');
  } finally { fs.rmSync(resultFile, { force: true }); }
}
async function launchApp(binary, home, key, configPath, mode = 'isolated') {
  if (!['main','isolated'].includes(mode)) throw new Error('App 模式无效');
  const executable = appExecutable(binary);
  if (!executable) throw new Error('Codex App 路径已失效，请重新选择');
  const appData = path.join(home, 'app-data');
  if (mode === 'isolated') fs.mkdirSync(appData, { recursive: true, mode: 0o700 });
  if (process.platform === 'win32' && /[\\/]WindowsApps[\\/]/i.test(executable)) return launchStoreApp(executable, home, configPath || path.resolve(home, '../..', 'config.json'), mode);
  const child = spawn(executable, launchArguments(home,mode), { env: launchEnvironment(home,key,process.env,mode), cwd: os.homedir(), detached: true, stdio: 'ignore', windowsHide: false });
  await new Promise((resolve, reject) => {
    let timer;
    child.once('error', reject);
    child.once('spawn', () => { timer = setTimeout(resolve, 1600); });
    child.once('exit', code => { clearTimeout(timer); code && code !== 0 ? reject(new Error(`Codex App 启动失败 (${code})`)) : resolve(); });
  });
  child.unref();
  return { pid: child.pid, app_data: mode === 'isolated' ? appData : '', app_mode:mode };
}
function launchArguments(home,mode) { return mode === 'main' ? [] : ['--user-data-dir='+path.join(home,'app-data')]; }
function isMainProcess(command, platform=process.platform, env=process.env) {
  if (/(?:^|\s)--type=/.test(command)) return false;
  const match = command.match(/"--user-data-dir=([^"]+)"|--user-data-dir="([^"]+)"|--user-data-dir(?:=|\s+)([^\s"]+)/);
  if (!match) return true;
  const value=match[1]||match[2]||match[3];
  const base=platform==='win32' ? env.APPDATA : platform==='linux' ? (env.XDG_CONFIG_HOME || path.join(os.homedir(),'.config')) : path.join(os.homedir(),'Library/Application Support');
  if (!base) return false;
  const normalize=v=>platform==='win32' ? path.win32.normalize(v).toLowerCase() : path.posix.normalize(v);
  const join=platform==='win32' ? path.win32.join : path.posix.join;
  return ['Codex','ChatGPT'].some(name=>normalize(value)===normalize(join(base,name)));
}
async function mainProcesses(binary) {
  const executable=appExecutable(binary);
  if (!executable) throw new Error('Codex App 路径已失效');
  if(process.platform==='win32') {
    const script="[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; @(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -eq "+psQuote(executable)+" } | Select-Object ProcessId,CommandLine,CreationDate) | ConvertTo-Json -Compress";
    const {stdout}=await run('powershell.exe',['-NoLogo','-NoProfile','-NonInteractive','-Command',script],{windowsHide:true,timeout:10000,encoding:'utf8'});
    const parsed=JSON.parse(stdout.trim()||'[]');
    return (Array.isArray(parsed)?parsed:[parsed]).filter(p=>isMainProcess(p.CommandLine||'')).map(p=>({pid:p.ProcessId,started:p.CreationDate}));
  }
  const {stdout}=await run('/bin/ps',['-axo','pid=,command='],{timeout:5000,encoding:'utf8'});
  return stdout.split('\n').flatMap(line=>{const m=line.match(/^\s*(\d+)\s+([\s\S]+)$/);return m && (m[2]===executable || m[2].startsWith(executable+' ')) && isMainProcess(m[2]) ? [{pid:Number(m[1])}] : [];});
}
async function closeMainProcesses(binary,expected) {
  const current=await mainProcesses(binary);
  const targets=expected.filter(p=>current.some(c=>c.pid===p.pid && c.started===p.started));
  for(const entry of targets) {
    if(process.platform==='win32') {
      await run('powershell.exe',['-NoLogo','-NoProfile','-NonInteractive','-Command',"$p=Get-Process -Id "+entry.pid+" -ErrorAction SilentlyContinue; if($p){[void]$p.CloseMainWindow()}"],{windowsHide:true,timeout:5000});
    } else {try{process.kill(entry.pid,'SIGTERM');}catch(e){if(e.code!=='ESRCH')throw e;}}
  }
  for(let attempt=0;attempt<20;attempt++) {
    const live=await mainProcesses(binary);
    if(!live.length)return;
    await new Promise(resolve=>setTimeout(resolve,350));
  }
  throw new Error('主 Codex App 尚未退出，请保存任务并完全退出后重试；本次没有切换配置');
}
module.exports = { discoverApp, appExecutable, launchEnvironment, launchApp, launchArguments, isMainProcess, mainProcesses, closeMainProcesses };
