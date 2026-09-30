'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const fsSync = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const net = require('node:net');
const http = require('node:http');
const { BridgeService, atomicJSON, openServiceLog } = require('../lib/service.cjs');
const binaryPlatform = { win32: 'win', darwin: 'mac', linux: 'linux' }[process.platform];
const binary = path.resolve(__dirname, '..', 'backend', `${binaryPlatform}-${process.arch}`, process.platform === 'win32' ? 'gptbridge.exe' : 'gptbridge');
async function freePort() { const server = net.createServer(); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); const port = server.address().port; await new Promise(resolve => server.close(resolve)); return port; }
test('real sidecar lifecycle, authenticated reuse, strict routing and isolated profile', async t => {
  await fs.access(binary);
  const home = await fs.mkdtemp(path.join(os.tmpdir(), 'gptbridge-desktop-test-'));
  const config = { listen: `127.0.0.1:${await freePort()}`, api_key: 'test-only-local-key', desktop_mode: true, auto_refresh: false, usage_probe: false };
  await fs.writeFile(path.join(home, 'config.json'), JSON.stringify(config));
  const service = new BridgeService({ home, binary });
  t.after(async () => { await service.stop(); await fs.rm(home, { recursive: true, force: true }); });
  assert.equal((await service.start()).reused, false);
  assert.equal((await service.start()).reused, true);
  const unauth = await fetch(`http://${config.listen}/api/accounts`);
  assert.equal(unauth.status, 401);
  const status = await service.request('/api/status');
  assert.equal(status.desktop_mode, true); assert.equal(status.route_policy, 'bps_only');
  await service.request('/api/settings', 'PUT', { desktop_mode: false, route_policy: 'codex_only', api_key: 'different', native_fallback: true, listen: '0.0.0.0:9999' });
  const locked = await service.request('/api/status');
  assert.equal(locked.listen, config.listen); assert.equal(locked.route_policy, 'bps_only'); assert.equal(locked.native_fallback, false);
  const imported = await service.request('/api/accounts/import?refresh=0', 'POST', [{ access_token: 'fake-for-local-test', account_id: 'workspace-a', email: 'alice@example.test' }, { access_token: 'other-fake', account_id: 'workspace-a', email: 'bob@example.test' }]);
  assert.equal(imported.imported, 2);
  const accounts = await service.request('/api/accounts');
  assert.equal(accounts.accounts.length, 2); assert.equal(accounts.accounts[0].access_token, undefined);
  const request = { account_id: imported.ids[0], model: 'gpt-6-astra', effort: 'xhigh', directory: home, prepare_only: true };
  const prepared = await service.request('/api/codex/launch', 'POST', request);
  assert.ok(prepared.home.startsWith(path.join(home, 'codex-instances')));
  const profile = await fs.readFile(path.join(prepared.home, 'config.toml'), 'utf8');
  assert.ok(profile.includes(imported.ids[0])); assert.ok(!profile.includes(config.api_key));
  const other = await service.request('/api/codex/launch', 'POST', { ...request, account_id: imported.ids[1] });
  assert.notEqual(other.home, prepared.home);
  const appProfile = await service.request('/api/codex/launch', 'POST', { ...request, target: 'app', directory: '' });
  const appAgain = await service.request('/api/codex/launch', 'POST', { ...request, target: 'app', directory: 'not-required' });
  assert.equal(appProfile.home, appAgain.home); assert.notEqual(appProfile.home, prepared.home);
  const native = await service.request('/api/codex/launch', 'POST', { ...request, target: 'app', directory: '', channel: 'codex', model: 'gpt-5.6-terra' });
  assert.notEqual(native.home, appProfile.home); assert.equal(native.channel, 'codex');
  assert.equal((await service.request('/api/codex/launch')).model, 'gpt-6-astra');
  assert.match(await fs.readFile(path.join(native.home, 'config.toml'), 'utf8'), /"X-GPTBridge-Channel" = "codex"/);
  assert.match(await fs.readFile(path.join(appProfile.home, 'config.toml'), 'utf8'), /"X-GPTBridge-Channel" = "bps"/);
  const nativeModels = JSON.parse(await fs.readFile(path.join(native.home, 'models.json'), 'utf8'));
  assert.ok(nativeModels.models.some(m => m.slug === 'gpt-5.6-terra'));
  assert.ok(nativeModels.models.every(m => !m.prefer_websockets && !m.use_responses_lite));
  await assert.rejects(service.request('/api/codex/launch', 'POST', { ...request, channel: 'bps', model: 'gpt-5.6-terra' }));
  await assert.rejects(service.request('/api/codex/launch', 'POST', { ...request, channel: 'random' }));
  await service.request('/api/codex/select', 'POST', { account_id: imported.ids[1] });
  assert.equal((await service.request('/api/codex/launch')).active_account_id, imported.ids[1]);
  await assert.rejects(service.request('/api/codex/select', 'POST', { account_id: 'acc-missing' }));
  await service.stop();
  assert.equal(await service.sameService(), false);
});
test('port collision never adopts or shuts down a foreign server', async t => {
  const home = await fs.mkdtemp(path.join(os.tmpdir(), 'gptbridge-port-test-'));
  let shutdown = false;
  const foreign = http.createServer((req, res) => { if (req.url === '/api/shutdown') shutdown = true; res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ desktop_mode: true, home: '/different/home' })); });
  await new Promise(resolve => foreign.listen(0, '127.0.0.1', resolve));
  await fs.writeFile(path.join(home, 'config.json'), JSON.stringify({ listen: `127.0.0.1:${foreign.address().port}`, api_key: 'test-key' }));
  const service = new BridgeService({ home, binary });
  t.after(async () => { await service.stop(); await new Promise(resolve => foreign.close(resolve)); await fs.rm(home, { recursive: true, force: true }); });
  await assert.rejects(service.start());
  await service.stop();
  assert.equal(shutdown, false);
});

test('config replacement does not follow a planted symlink', t => {
  const home = fsSync.mkdtempSync(path.join(os.tmpdir(), 'gptbridge-atomic-'));
  t.after(() => fsSync.rmSync(home, { recursive: true, force: true }));
  const stolen = path.join(home, 'stolen.json');
  const planted = path.join(home, 'config.json.tmp');
  const dest = path.join(home, 'config.json');
  fsSync.writeFileSync(stolen, 'keep');
  try {
    fsSync.symlinkSync(stolen, dest);
    fsSync.symlinkSync(stolen, planted);
  } catch (error) {
    t.skip(error.message);
    return;
  }
  atomicJSON(dest, { api_key: 'synthetic-local-key', desktop_mode: true });
  assert.equal(fsSync.readFileSync(stolen, 'utf8'), 'keep');
  assert.equal(fsSync.lstatSync(dest).isSymbolicLink(), false);
  assert.equal(fsSync.statSync(dest).mode & 0o777, 0o600);
  assert.equal(JSON.parse(fsSync.readFileSync(dest, 'utf8')).api_key, 'synthetic-local-key');
  assert.equal(fsSync.lstatSync(planted).isSymbolicLink(), true);
  assert.equal(fsSync.readFileSync(planted, 'utf8'), 'keep');
  const leftovers = fsSync.readdirSync(home).filter(name => name.startsWith('.config.json.') && name.endsWith('.tmp'));
  assert.deepEqual(leftovers, []);
});

test('service log append replaces a symlink and still rotates a normal log', t => {
  const home = fsSync.mkdtempSync(path.join(os.tmpdir(), 'gptbridge-log-'));
  t.after(() => fsSync.rmSync(home, { recursive: true, force: true }));
  const log = path.join(home, 'service.log');
  fsSync.writeFileSync(log, 'old\n', { mode: 0o644 });
  const kept = openServiceLog(log);
  fsSync.writeSync(kept, 'new\n');
  fsSync.closeSync(kept);
  assert.equal(fsSync.readFileSync(log, 'utf8'), 'old\nnew\n');
  assert.equal(fsSync.statSync(log).mode & 0o777, 0o600);

  const bulky = Buffer.alloc(2 * 1024 * 1024 + 1, 97);
  fsSync.writeFileSync(log, bulky);
  const rotated = openServiceLog(log);
  fsSync.writeSync(rotated, 'next\n');
  fsSync.closeSync(rotated);
  assert.equal(fsSync.readFileSync(log, 'utf8'), 'next\n');
  assert.equal(fsSync.readFileSync(log + '.1').equals(bulky), true);
  assert.throws(() => openServiceLog(home), /普通文件/);
  assert.throws(() => openServiceLog('  '), /路径无效/);
});

test('service log append does not follow a symlink', t => {
  const home = fsSync.mkdtempSync(path.join(os.tmpdir(), 'gptbridge-log-link-'));
  t.after(() => fsSync.rmSync(home, { recursive: true, force: true }));
  const stolen = path.join(home, 'stolen.log');
  const log = path.join(home, 'service.log');
  const secret = Buffer.alloc(2 * 1024 * 1024 + 1, 98);
  fsSync.writeFileSync(stolen, secret);
  try { fsSync.symlinkSync(stolen, log); }
  catch (error) {
    t.skip(error.message);
    return;
  }
  const replaced = openServiceLog(log);
  fsSync.writeSync(replaced, 'local\n');
  fsSync.closeSync(replaced);
  assert.equal(fsSync.readFileSync(stolen).equals(secret), true);
  assert.equal(fsSync.lstatSync(log).isSymbolicLink(), false);
  assert.equal(fsSync.readFileSync(log, 'utf8'), 'local\n');
  assert.equal(fsSync.existsSync(log + '.1'), false);
  assert.equal(fsSync.statSync(log).mode & 0o777, 0o600);
});
