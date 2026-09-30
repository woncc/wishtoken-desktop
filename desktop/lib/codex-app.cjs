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
    : [path.join(process.env.LOCALAPPDATA || os.homedir(), 'Programs/Codex/Codex.exe'), path.join(process.env.LOCALAPPDATA || os.homedir(), 'Codex/Codex.exe')];
  if (process.platform === 'win32') {
    try {
      const { stdout } = await run('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', '[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Get-AppxPackage -Name OpenAI.Codex | Sort-Object Version -Descending | ForEach-Object { Join-Path $_.InstallLocation "app/Codex.exe" }'], { windowsHide: true, timeout: 7000, encoding: 'utf8' });
      candidates.push(...stdout.trim().split(/\r?\n/));
    } catch { /* Manual picker supports nonstandard installations. */ }
  }
  if (preferred) candidates.push(preferred);
  for (const candidate of candidates) if ((executable = appExecutable(candidate))) return { installed: true, binary: executable };
  return { installed: false, binary: '', error: '未找到 Codex App，请安装官方客户端或手动选择应用路径' };
}
function launchEnvironment(home, key, env = process.env) {
  const clean = Object.fromEntries(Object.entries(env).filter(([k]) => !/^(CODEX_|GPTBRIDGE_|ELECTRON_|NODE_OPTIONS$|OPENAI_API_KEY$|OPENAI_BASE_URL$)/i.test(k)));
  const identity = path.join(home, 'bridge-identity.json');
  if (fs.existsSync(identity)) clean.CODEX_AUTHAPI_BASE_URL = JSON.parse(fs.readFileSync(identity, 'utf8')).auth_api_url;
  return { ...clean, CODEX_HOME: home, CODEX_ELECTRON_USER_DATA_PATH: path.join(home, 'app-data'), GPTBRIDGE_CODEX_KEY: key };
}
const psQuote = value => "'" + value.replaceAll("'", "''") + "'";
async function launchStoreApp(executable, home, configPath) {
  const resultFile = path.join(home, `app-launch-${randomUUID()}.json`);
  // Packaged Windows APIs require package identity. Shell AppsFolder would
  // discard the selected profile, so run a hidden helper inside this package.
  const inner = `$ErrorActionPreference='Stop'
try {
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = ${psQuote(executable)}
  $psi.UseShellExecute = $false
  $psi.WorkingDirectory = ${psQuote(os.homedir())}
  $psi.Arguments = ${psQuote('"--user-data-dir=' + path.join(home, 'app-data') + '"')}
  foreach ($k in @($psi.EnvironmentVariables.Keys)) { if ($k -match '^(CODEX_|GPTBRIDGE_|ELECTRON_|NODE_OPTIONS$|OPENAI_API_KEY$|OPENAI_BASE_URL$)') { $psi.EnvironmentVariables.Remove($k) } }
  $psi.EnvironmentVariables['CODEX_HOME'] = ${psQuote(home)}
  $psi.EnvironmentVariables['CODEX_ELECTRON_USER_DATA_PATH'] = ${psQuote(path.join(home, 'app-data'))}
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
        if (result) { if (result.error) throw new Error(result.error); return { pid: result.pid, app_data: path.join(home, 'app-data'), packaged: true }; }
      }
      await new Promise(resolve=>setTimeout(resolve,150));
    }
    throw new Error('Codex 商店版启动未确认，请检查安装状态');
  } finally { fs.rmSync(resultFile, { force: true }); }
}
async function launchApp(binary, home, key, configPath) {
  const executable = appExecutable(binary);
  if (!executable) throw new Error('Codex App 路径已失效，请重新选择');
  const appData = path.join(home, 'app-data');
  fs.mkdirSync(appData, { recursive: true, mode: 0o700 });
  if (process.platform === 'win32' && /[\\/]WindowsApps[\\/]/i.test(executable)) return launchStoreApp(executable, home, configPath || path.resolve(home, '../..', 'config.json'));
  const child = spawn(executable, [`--user-data-dir=${appData}`], { env: launchEnvironment(home, key), cwd: os.homedir(), detached: true, stdio: 'ignore', windowsHide: false });
  await new Promise((resolve, reject) => {
    let timer;
    child.once('error', reject);
    child.once('spawn', () => { timer = setTimeout(resolve, 1600); });
    child.once('exit', code => { clearTimeout(timer); code && code !== 0 ? reject(new Error(`Codex App 启动失败 (${code})`)) : resolve(); });
  });
  child.unref();
  return { pid: child.pid, app_data: appData };
}
module.exports = { discoverApp, appExecutable, launchEnvironment, launchApp };
