'use strict';
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const http = require('node:http');
const { spawn } = require('node:child_process');

const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
// A fixed "*.tmp" name can be planted as a symlink. Create an exclusive file
// in the destination directory and rename it over the path instead.
function atomicJSON(file, data) {
  const dir = path.dirname(file);
  const tmp = path.join(dir, `.${path.basename(file)}.${crypto.randomBytes(8).toString('hex')}.tmp`);
  const flags = fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | (fs.constants.O_NOFOLLOW || 0);
  const fd = fs.openSync(tmp, flags, 0o600);
  try {
    if (!fs.fstatSync(fd).isFile()) throw new Error('临时文件不是普通文件');
    fs.writeFileSync(fd, JSON.stringify(data, null, 2) + '\n');
    fs.fchmodSync(fd, 0o600);
    fs.closeSync(fd);
  } catch (error) {
    try { fs.closeSync(fd); } catch { /* The write may already have closed it. */ }
    fs.rmSync(tmp, { force: true });
    throw error;
  }
  try {
    const written = fs.lstatSync(tmp);
    if (written.isSymbolicLink() || !written.isFile()) throw new Error('临时文件不是普通文件');
    fs.renameSync(tmp, file);
  } catch (error) {
    fs.rmSync(tmp, { force: true });
    throw error;
  }
}
function openAppend(file) {
  if (typeof file !== 'string' || file.trim() === '') throw new Error('服务日志路径无效');
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  let info;
  try { info = fs.lstatSync(file); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  if (info?.isSymbolicLink()) fs.unlinkSync(file);
  else if (info && !info.isFile()) throw new Error('服务日志不是普通文件');
  const flags = fs.constants.O_CREAT | fs.constants.O_APPEND | fs.constants.O_WRONLY | (fs.constants.O_NOFOLLOW || 0);
  let fd;
  try { fd = fs.openSync(file, flags, 0o600); }
  catch (error) {
    if (error.code === 'ELOOP') throw new Error('服务日志是符号链接，已停止写入');
    throw error;
  }
  try {
    const opened = fs.fstatSync(fd);
    const current = fs.lstatSync(file);
    if (current.isSymbolicLink() || !current.isFile() || !opened.isFile()) throw new Error('服务日志是符号链接，已停止写入');
    fs.fchmodSync(fd, 0o600);
    return fd;
  } catch (error) {
    fs.closeSync(fd);
    throw error;
  }
}
// Rotation uses lstat so a symlink is not treated as a large log and renamed aside.
function openServiceLog(file) {
  let info;
  try { info = fs.lstatSync(file); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  if (info?.isFile() && info.size > 2 * 1024 * 1024) fs.renameSync(file, file + '.1');
  return openAppend(file);
}
class BridgeService {
  constructor({ home, binary, env = process.env }) {
    this.home = path.resolve(home);
    this.binary = binary;
    this.env = env;
    this.child = null;
    this.starting = null;
    this.stopping = false;
    this.config = null;
    this.logPath = path.join(this.home, 'service.log');
  }
  async request(route, method = 'GET', body, timeout = 35000, signal) {
    if (!this.config) throw new Error('本地服务尚未启动');
    // fetch/undici has a separate five-minute response-header deadline.
    // Generation returns one final JSON, so use an explicit full-request clock.
    const deadline = AbortSignal.timeout(timeout);
    const combined = signal ? AbortSignal.any([signal, deadline]) : deadline;
    const payload = body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body);
    return new Promise((resolve, reject) => {
      const req = http.request(`http://${this.config.listen}${route}`, { method, signal: combined, headers: { Authorization: `Bearer ${this.config.api_key}`, 'Content-Type': 'application/json', ...(payload === undefined ? {} : { 'Content-Length': Buffer.byteLength(payload) }) } }, response => {
        const chunks = []; let size = 0;
        response.on('data', chunk => { size += chunk.length; if (size > 20 * 1024 * 1024) req.destroy(new Error('response too large')); else chunks.push(chunk); });
        response.on('error', () => reject(new Error(signal?.aborted ? '测试已取消' : deadline.aborted ? '请求超时' : '本地服务响应中断，请重试')));
        response.on('end', () => {
          try {
            const data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
            if (response.statusCode < 200 || response.statusCode >= 300) reject(new Error(data.error?.message || `本地服务返回 ${response.statusCode}`));
            else resolve(data);
          } catch { reject(new Error('本地服务返回了无效数据')); }
        });
      });
      req.on('error', () => reject(new Error(signal?.aborted ? '测试已取消' : deadline.aborted ? '请求超时，请稍后重试或检查网络代理' : '无法连接本地服务，请重新连接或查看服务日志')));
      req.end(payload);
    });
  }
  async sameService() {
    try {
      const status = await this.request('/api/status', 'GET', undefined, 1200);
      return status.desktop_mode === true && path.resolve(status.home) === this.home;
    } catch { return false; }
  }
  async start() {
    if (this.starting) return this.starting;
    this.starting = this.startInner();
    try { return await this.starting; } finally { this.starting = null; }
  }
  async startInner() {
    this.stopping = false;
    await fsp.mkdir(this.home, { recursive: true, mode: 0o700 });
    const file = path.join(this.home, 'config.json');
    let prior = {};
    try { prior = JSON.parse(await fsp.readFile(file, 'utf8')); }
    catch (error) { if (error.code !== 'ENOENT') throw new Error('本地配置无法读取，请检查数据目录中的 config.json'); }
    this.config = {
      ...prior, listen: /^127\.0\.0\.1:\d{2,5}$/.test(prior.listen || '') ? prior.listen : '127.0.0.1:8792',
      api_key: prior.api_key || crypto.randomBytes(32).toString('hex'), desktop_mode: true,
      cockpit_key: prior.cockpit_key || crypto.randomBytes(32).toString('hex'),
      route_policy: 'bps_only', native_fallback: false, allow_remote: false, web_ui: false
    };
    if (await this.sameService()) return { reused: true };
    if (!fs.existsSync(this.binary)) throw new Error('缺少 GPTBridge 服务程序，请重新解压完整客户端');
    // Save before spawning, never put secrets in process arguments.
    atomicJSON(file, this.config);
    const log = openServiceLog(this.logPath);
    const env = Object.fromEntries(Object.entries(this.env).filter(([key]) => !/^GPTBRIDGE_/i.test(key) && !['CODEX_HOME', 'CODEX_AUTHAPI_BASE_URL'].includes(key)));
    env.GPTBRIDGE_HOME = this.home;
    if (this.env.GPTBRIDGE_CODEX_BIN) env.GPTBRIDGE_CODEX_BIN = this.env.GPTBRIDGE_CODEX_BIN;
    let failure;
    try {
      this.child = spawn(this.binary, ['serve', '--no-ui'], { cwd: this.home, env, windowsHide: true, stdio: ['ignore', log, log] });
      this.child.once('error', err => { failure = err; });
      this.child.once('exit', code => { failure = new Error(`服务退出 (${code})；请检查端口 ${this.config.listen} 是否被占用及服务日志`); });
    } finally { fs.closeSync(log); }
    for (let attempt = 0; attempt < 60; attempt++) {
      if (failure) throw failure;
      if (await this.sameService()) return { reused: false };
      await pause(150);
    }
    if (this.child?.exitCode === null) this.child.kill();
    throw new Error('本地服务启动超时，请查看服务日志');
  }
  async stop() {
    this.stopping = true;
    if (await this.sameService()) {
      await this.request('/api/shutdown', 'POST', {}, 2000).catch(() => {});
      for (let i = 0; i < 30 && this.child?.exitCode === null; i++) await pause(100);
    }
    if (this.child?.exitCode === null) this.child.kill();
    this.child = null;
  }
}
module.exports = { BridgeService, atomicJSON, openServiceLog };
