'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { cleanSettings, cleanLaunch, cleanProbe, cleanPreferences, applyPreferences, appliedTheme, redactPublic, withoutSecrets, requireID, safeError, publicSnapshot, publicLogs, publicProbe, publicImport, publicLaunch, publicRestore, publicAccountAction, publicUsageResult, publicSettings, publicPreferences, publicApp, publicServiceState, publicAbout, publicSelection, rendererPayload } = require('../lib/policy.cjs');
test('renderer cannot change local key, listener, route or fallback', () => {
  assert.deepEqual(cleanSettings({ api_key: 'attacker', listen: '0.0.0.0:1', native_fallback: true, route_policy: 'codex_only', desktop_mode: false, auto_refresh: false, proxy_url: ' http://127.0.0.1:7890 ' }), { auto_refresh: false, proxy_url: 'http://127.0.0.1:7890' });
  assert.throws(() => cleanSettings({ usage_probe: 'false' }));
});
test('launch cannot select arbitrary homes or prepare-only from renderer', () => {
  const request = { account_id: 'acc-abcdef123', directory: '/tmp/项目', model: 'gpt-6-astra', effort: 'xhigh', home: '/Users/test/.codex', prepare_only: true, resume: true };
  const result = cleanLaunch(request);
  assert.equal(result.resume, true);
  assert.equal(result.channel, 'bps');
  assert.equal(result.speed, 'standard');
  assert.equal(cleanLaunch({ ...request, channel: 'codex', speed: 'fast' }).speed, 'fast');
  assert.throws(() => cleanLaunch({ ...request, speed: 'fast' }));
  assert.throws(() => cleanLaunch({ ...request, channel: 'codex', speed: 'ultrafast' }));
  assert.equal(cleanLaunch({ ...request, channel: 'codex' }).channel, 'codex');
  assert.throws(() => cleanLaunch({ ...request, channel: 'automatic' }));
  assert.equal(result.home, undefined);
  assert.equal(result.prepare_only, undefined);
  assert.equal(cleanLaunch({ ...request, target: 'app', directory: '' }).app_mode, 'main');
  assert.equal(cleanLaunch({ ...request, target: 'app', app_mode: 'isolated' }).app_mode, 'isolated');
  assert.throws(() => cleanLaunch({ ...request, target: 'app', app_mode: '../../' }));
  assert.throws(() => cleanLaunch({ ...request, effort: 'max' }));
  assert.throws(() => cleanLaunch({ ...request, directory: '' }));
  assert.throws(() => cleanLaunch({ ...request, compact_limit: NaN }));
});
test('account IDs cannot escape the endpoint path; credential errors are redacted', () => {
  for (const id of ['../../settings', 'acc-abc/refresh', 'acc-abc?x=1', '', null]) assert.throws(() => requireID(id));
  assert.equal(safeError(new Error('invalid eyJabc.xyz.def credential')), 'invalid [凭据已隐藏] credential');
});

test('connection probe rejects a substitute model, effort, or missing channel', () => {
  assert.deepEqual(cleanProbe({ account_id: 'acc-abcdef123', model: 'gpt-5.6-terra', effort: 'low', channel: 'codex' }), { account_id: 'acc-abcdef123', model: 'gpt-5.6-terra', effort: 'low', channel: 'codex' });
  assert.throws(() => cleanProbe({ account_id: 'acc-abcdef123', model: 'gpt-5.6-terra', effort: 'max', channel: 'bps' }));
  assert.throws(() => cleanProbe({ account_id: 'acc-abcdef123', model: '', effort: 'high' }));
  assert.throws(() => cleanProbe({ account_id: 'acc-abcdef123', model: 'not a model', effort: 'high' }));
  assert.throws(() => cleanProbe({ account_id: 'acc-abcdef123', model: 'gpt-5.6-terra', effort: 'high' }));
  assert.throws(() => cleanProbe({ account_id: 'acc-abcdef123', model: 'gpt-5.6-terra', effort: 'high', channel: null }));
});
test('renderer payloads drop oauth fields and embedded JWTs', () => {
  const account = redactPublic({ id: 'acc-1', email: 'a@example.test', access_token: 'secret-token-value', refresh_token: 'refresh-token-value', has_refresh_token: true, usage: { note: 'bad eyJaaaaaaaaaa.bbbbbbbbbb.cccccccccc token' } });
  assert.equal(account.access_token, undefined);
  assert.equal(account.refresh_token, undefined);
  assert.equal(account.has_refresh_token, true);
  assert.equal(account.email, 'a@example.test');
  assert.match(account.usage.note, /凭据已隐藏/);
  assert.equal(redactPublic('plain'), 'plain');
});

test('renderer payloads drop camelCase oauth fields and credential-shaped text', () => {
  const jwt = 'eyJaaaaaaaaaa.bbbbbbbbbb.cccccccccc';
  assert.equal(redactPublic('prefix ' + jwt + ' suffix'), 'prefix [凭据已隐藏] suffix');
  const value = redactPublic({
    accessToken: 'not-a-jwt-but-secret',
    personal_access_token: 'pat-value',
    note: 'Authorization: Bearer ' + 'a'.repeat(24) + ' rt_refreshvalue',
    url: 'http://127.0.0.1:8792/cockpit-auth/' + 'ab'.repeat(20) + '/whoami',
    email: 'member@example.test',
    model: 'gpt-5.6-terra'
  });
  assert.equal(value.accessToken, undefined);
  assert.equal(value.personal_access_token, undefined);
  assert.match(value.note, /Bearer \[凭据已隐藏\]/);
  assert.doesNotMatch(value.note, /rt_refresh/);
  assert.match(value.url, /cockpit-auth\/\[凭据已隐藏\]/);
  assert.equal(value.email, 'member@example.test');
  assert.equal(value.model, 'gpt-5.6-terra');
  assert.equal(redactPublic({ response_id: 'resp_0123456789abcdef', responseId: 'resp_fedcba9876543210', ok: 1 }).response_id, undefined);
  assert.equal(redactPublic({ responseId: 'resp_fedcba9876543210', ok: 1 }).responseId, undefined);
  assert.equal(redactPublic('upstream response_id=resp_0123456789abcdef done').includes('resp_0123456789abcdef'), false);
  assert.match(redactPublic('upstream response_id=resp_0123456789abcdef done'), /response_id=\[凭据已隐藏\]/);
  assert.equal(redactPublic('proxy http://user:s3cret-token@127.0.0.1:7890/path'), 'proxy http://127.0.0.1:7890/path');
  assert.equal(redactPublic('http://127.0.0.1:7890'), 'http://127.0.0.1:7890');
  assert.equal(redactPublic('socks5://alice:hunter2@10.0.0.8:1080'), 'socks5://10.0.0.8:1080');
  const clean = redactPublic(JSON.parse('{"__proto__":{"polluted":true},"ok":1}'));
  assert.equal(clean.ok, 1);
  assert.equal(clean.polluted, undefined);
  assert.equal(Object.prototype.polluted, undefined);
  assert.equal(safeError(new Error('bad ' + jwt + ' and rt_refreshvalue')), 'bad [凭据已隐藏] and [凭据已隐藏]');
});
test('preference updates cannot clear an explicit channel or smuggle secrets', () => {
  const applied = applyPreferences({ channel: 'codex', api_key: 'local-key', account_speeds: { 'acc-a': 'fast' } }, { pelican_channel: 'bps', pelican_model: 'gpt-5.6-sol', pelican_effort: 'low', api_key: 'attacker', theme: 'dark' });
  assert.equal(applied.prefs.channel, 'codex');
  assert.equal(applied.prefs.pelican_channel, 'bps');
  assert.equal(applied.prefs.pelican_model, 'gpt-5.6-sol');
  assert.equal(applied.prefs.pelican_effort, 'low');
  assert.equal(applied.prefs.api_key, undefined);
  assert.equal(applied.prefs.account_speeds['acc-a'], 'fast');
  assert.equal(applied.theme, 'dark');
  assert.equal(appliedTheme('dark'), 'dark');
  assert.equal(appliedTheme(undefined), 'system');
  assert.equal(appliedTheme('contrast'), 'system');
  assert.deepEqual(cleanPreferences({ account_speed: { id: 'acc-abcdef123', speed: 'fast' } }), { account_speed: { id: 'acc-abcdef123', speed: 'fast' } });
  assert.throws(() => cleanPreferences({ pelican_channel: null }));
  assert.throws(() => cleanPreferences({ pelican_model: 'not a model' }));
  assert.throws(() => cleanPreferences({ pelican_effort: 'max' }));
  assert.equal(withoutSecrets({ nested: { refreshToken: 'x', ok: 1 } }).nested.refreshToken, undefined);
  assert.equal(withoutSecrets({ nested: { refreshToken: 'x', ok: 1 } }).nested.ok, 1);
});

test('renderer snapshot keeps ui fields and drops credential payloads', () => {
  const jwt = 'eyJaaaaaaaaaa.bbbbbbbbbb.cccccccccc';
  const view = publicSnapshot({
    status: { home: '/tmp/desktop-home', listen: '127.0.0.1:8792', api_key_set: true, codex_config: { base_url: 'http://127.0.0.1:8792/cockpit-auth/' + 'ab'.repeat(20), experimental_bearer_token: 'local-key' } },
    accounts: [{ id: 'acc-1', email: 'a@example.test', access_token: 'raw-token', refreshToken: 'refresh-value', has_refresh_token: true, usage: { primary: { used_percent: 12, window_seconds: 18000, reset_at: '2026-10-02T00:00:00Z', access_token: 'nested' }, limit_reached: false }, last_error: 'bad ' + jwt }],
    codex: { installed: true, binary: '/usr/bin/codex', home: '/tmp/codex-home', api_key: 'local-key', active_account_id: 'acc-1', model: 'gpt-6-astra', effort: 'xhigh', app: { installed: false, binary: '' }, main_app: { active: true, home: '/tmp/main', backup: '/tmp/backup', account_id: 'acc-1' }, history: [{ id: 'hist', account_id: 'acc-1', directory: '/work', model: 'gpt-6-astra', effort: 'high', channel: 'codex', speed: 'fast', target: 'app', app_mode: 'main', home: '/tmp/instance', last_used: '2026-10-01T00:00:00Z' }] },
    models: { catalog: [{ id: 'gpt-6-astra', display_name: 'GPT-6 Astra', secret: 'nope' }], native_catalog: [{ id: 'gpt-5.6-terra' }], bps_models: ['gpt-6-astra'], efforts: ['low'] },
    settings: { proxy_url: 'http://127.0.0.1:7890', auto_refresh: true, usage_probe: false, api_key: 'local-key' },
    preferences: { channel: 'codex', pelican_model: 'gpt-5.6-sol', app_path: '/secret/Codex', account_speeds: { 'acc-1': 'fast', 'acc-2': 'ultra' }, api_key: 'local-key' },
    platform: 'linux', version: '0.8.2'
  });
  assert.equal(view.status.home, '/tmp/desktop-home');
  assert.equal(view.status.codex_config, undefined);
  assert.equal(view.status.listen, undefined);
  assert.equal(view.accounts[0].email, 'a@example.test');
  assert.equal(view.accounts[0].access_token, undefined);
  assert.equal(view.accounts[0].refreshToken, undefined);
  assert.equal(view.accounts[0].has_refresh_token, true);
  assert.equal(view.accounts[0].usage.primary.used_percent, 12);
  assert.equal(view.accounts[0].usage.primary.access_token, undefined);
  assert.match(view.accounts[0].last_error, /凭据已隐藏/);
  assert.equal(view.codex.home, undefined);
  assert.equal(view.codex.api_key, undefined);
  assert.equal(view.codex.main_app.backup, undefined);
  assert.equal(view.codex.main_app.home, '/tmp/main');
  assert.equal(view.codex.history[0].home, undefined);
  assert.equal(view.codex.history[0].speed, 'fast');
  assert.equal(view.models.catalog[0].secret, undefined);
  assert.equal(view.models.catalog[0].display_name, 'GPT-6 Astra');
  assert.deepEqual(view.models.bps_models, ['gpt-6-astra']);
  assert.equal(view.settings.api_key, undefined);
  assert.equal(view.settings.auto_refresh, true);
  assert.equal(view.settings.proxy_url, 'http://127.0.0.1:7890');
  assert.equal(view.preferences.app_path, undefined);
  assert.equal(view.preferences.api_key, undefined);
  assert.equal(view.preferences.pelican_model, 'gpt-5.6-sol');
  assert.deepEqual(view.preferences.account_speeds, { 'acc-1': 'fast' });
  const logs = publicLogs({ records: [{ model: 'gpt-6-astra', effort: 'high', route: 'bps', status: 200, duration_ms: 10, error: 'Bearer ' + 'a'.repeat(20), access_token: 'raw-token', account: 'hidden' }] });
  assert.equal(logs.records[0].access_token, undefined);
  assert.equal(logs.records[0].account, undefined);
  assert.match(logs.records[0].error, /Bearer \[凭据已隐藏\]/);
  const probe = publicProbe({ ok: true, model: 'gpt-6-astra', effort: 'low', route: 'codex', duration_ms: 12, text: 'CONNECTION OK ' + jwt, account: 'raw-token', response_id: 'resp_0123456789abcdef' });
  assert.equal(probe.text, undefined);
  assert.equal(probe.account, undefined);
  assert.equal(probe.response_id, undefined);
  assert.equal(probe.route, 'codex');
  assert.equal(probe.ok, true);
  const unreported = publicProbe({ ok: true, model: 'gpt-6-astra', effort: 'high', response_model: 'gpt-5.6-terra' });
  assert.equal(unreported.route, '');
  assert.notEqual(unreported.route, 'bps');
  assert.equal(unreported.response_model, undefined);
  const imported = publicImport({ imported: 1, merged: 0, skipped: 1, ids: ['acc-1'], warnings: ['skipped an entry without access_token or refresh_token', 'bad ' + jwt], accounts: [{ access_token: 'raw-token' }] });
  assert.equal(imported.accounts, undefined);
  assert.match(imported.warnings[0], /access_token or refresh_token/);
  assert.match(imported.warnings[1], /凭据已隐藏/);
  assert.equal(publicImport(null), null);
});

test('action responses keep explicit mode and drop profile paths and service internals', () => {
  const jwt = 'eyJaaaaaaaaaa.bbbbbbbbbb.cccccccccc';
  const launch = publicLaunch({
    ok: true, pid: 42, home: '/tmp/instance', directory: '/work', account_id: 'acc-1', backup: '/tmp/main-backup',
    app_data: '/tmp/instance/app-data', app_mode: 'isolated', api_key: 'local-key', warning: 'record failed near ' + jwt
  }, { target: 'app', app_mode: 'main' });
  assert.equal(launch.ok, true);
  assert.equal(launch.app_mode, 'main');
  assert.equal(launch.home, undefined);
  assert.equal(launch.backup, undefined);
  assert.equal(launch.app_data, undefined);
  assert.equal(launch.pid, undefined);
  assert.equal(launch.api_key, undefined);
  assert.match(launch.warning, /凭据已隐藏/);
  assert.deepEqual(publicLaunch({ cancelled: true, home: '/tmp/instance', app_mode: 'main' }, { target: 'app', app_mode: 'main' }), { cancelled: true });
  assert.equal(publicLaunch({ home: '/tmp/main', app_mode: 'main' }, { target: 'app', app_mode: 'isolated' }).app_mode, 'isolated');
  assert.equal(publicLaunch({ home: '/tmp/instance', pid: 9, app_mode: 'main' }, { target: 'cli' }).app_mode, undefined);
  const restored = publicRestore({ home: '/tmp/main', backup: '/tmp/main-backup', restored: true, warning: '请手动打开 Codex App', api_key: 'local-key' });
  assert.equal(restored.restored, true);
  assert.equal(restored.home, undefined);
  assert.equal(restored.backup, undefined);
  assert.equal(restored.api_key, undefined);
  assert.equal(restored.warning, '请手动打开 Codex App');
  assert.deepEqual(publicRestore({ cancelled: true, home: '/tmp/main' }), { cancelled: true });
  const account = publicAccountAction({ id: 'acc-1', email: 'a@example.test', access_token: 'raw-token', proxy_url: 'http://user:secret@127.0.0.1:7890', stats: { requests: 4 }, source: 'import', has_refresh_token: true, last_error: 'bad ' + jwt });
  assert.equal(account.email, 'a@example.test');
  assert.equal(account.has_refresh_token, true);
  assert.equal(account.access_token, undefined);
  assert.equal(account.proxy_url, undefined);
  assert.equal(account.stats, undefined);
  assert.equal(account.source, undefined);
  assert.match(account.last_error, /凭据已隐藏/);
  assert.deepEqual(publicAccountAction({ ok: true }), { ok: true });
  const usage = publicUsageResult({ primary: { used_percent: 10, window_seconds: 18000, reset_at: '2026-10-02T00:00:00Z', access_token: 'nested' }, limit_reached: false, access_token: 'raw-token' });
  assert.equal(usage.ok, true);
  assert.equal(usage.primary.used_percent, 10);
  assert.equal(usage.primary.access_token, undefined);
  assert.equal(usage.access_token, undefined);
  const settings = publicSettings({ proxy_url: 'http://127.0.0.1:7890', auto_refresh: true, usage_probe: false, config_path: '/tmp/config.json', listen: '0.0.0.0:9', api_key: 'local-key', api_key_set: true });
  assert.deepEqual(settings, { proxy_url: 'http://127.0.0.1:7890', auto_refresh: true, usage_probe: false });
  const authed = publicSettings({ proxy_url: 'http://user:s3cret-token@127.0.0.1:7890', auto_refresh: false, usage_probe: true });
  assert.equal(authed.proxy_url, 'http://user:s3cret-token@127.0.0.1:7890');
  const snap = publicSnapshot({ settings: { proxy_url: 'http://user:s3cret-token@127.0.0.1:7890', auto_refresh: false, usage_probe: false }, accounts: [{ id: 'acc-1', last_error: 'via http://user:s3cret-token@10.1.1.1:8080 failed' }] });
  assert.equal(snap.settings.proxy_url, 'http://user:s3cret-token@127.0.0.1:7890');
  assert.equal(snap.accounts[0].last_error, 'via http://10.1.1.1:8080 failed');
  const logs = publicLogs({ records: [{ model: 'gpt-6-astra', error: 'proxy http://user:s3cret-token@127.0.0.1:7890 refused' }] });
  assert.equal(logs.records[0].error, 'proxy http://127.0.0.1:7890 refused');
  assert.deepEqual(publicApp({ installed: true, binary: '/secret/Codex.app', error: '' }), { installed: true });
  assert.equal(publicApp({ installed: false, binary: '', error: 'missing ' + jwt }).error.includes('凭据已隐藏'), true);
  assert.deepEqual(publicServiceState({ reused: false, config: { api_key: 'local-key' } }), { reused: false });
  assert.deepEqual(publicAbout({ version: '0.8.2', platform: 'linux', arch: 'x64', home: '/tmp/desktop-home', log: '/tmp/service.log' }), { version: '0.8.2', platform: 'linux', arch: 'x64' });
  assert.deepEqual(publicSelection('acc-1'), { account_id: 'acc-1' });
  const prefs = publicPreferences({ channel: 'codex', app_path: '/secret/Codex', api_key: 'local-key', account_speeds: { 'acc-1': 'fast', 'acc-2': 'ultra' } });
  assert.equal(prefs.app_path, undefined);
  assert.equal(prefs.api_key, undefined);
  assert.deepEqual(prefs.account_speeds, { 'acc-1': 'fast' });
});

test('final IPC redaction keeps the proxy editor and still strips other userinfo', () => {
  const proxy = 'http://user:s3cret-token@127.0.0.1:7890';
  const projected = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true, api_key: 'local-key' },
    accounts: [{ id: 'acc-1', last_error: 'via http://user:s3cret-token@10.1.1.1:8080 failed' }]
  });
  const delivered = rendererPayload(projected);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.settings.api_key, undefined);
  assert.equal(delivered.accounts[0].last_error, 'via http://10.1.1.1:8080 failed');
  assert.equal(projected.settings.proxy_url, proxy);
  const saved = rendererPayload(publicSettings({ proxy_url: proxy, auto_refresh: true, usage_probe: false, api_key: 'local-key', listen: '0.0.0.0:9' }));
  assert.deepEqual(saved, { proxy_url: proxy, auto_refresh: true, usage_probe: false });
  const unrelated = rendererPayload({ proxy_url: proxy, error: 'via http://user:s3cret-token@10.0.0.1:9', api_key: 'local-key' });
  assert.equal(unrelated.proxy_url, 'http://127.0.0.1:7890');
  assert.equal(unrelated.error, 'via http://10.0.0.1:9');
  assert.equal(unrelated.api_key, undefined);
  assert.equal(rendererPayload('socks5://alice:hunter2@10.0.0.8:1080'), 'socks5://10.0.0.8:1080');
  assert.equal(rendererPayload(null), null);
});

test('renderer text drops proxy passwords that a URL parser would reject', () => {
  const password = 's3cret proxy';
  const cases = [
    [`http://user:${password}@127.0.0.1:7890`, 'http://127.0.0.1:7890'],
    ['http://user:s3cret%zz@127.0.0.1:7890', 'http://127.0.0.1:7890'],
    ['http://user:s3cret\nproxy@127.0.0.1:1', 'http://127.0.0.1:1'],
    ['http://user:p@ss@127.0.0.1:7890/x', 'http://127.0.0.1:7890/x'],
    ['user:s3cret-token@127.0.0.1:7890', '127.0.0.1:7890'],
    ['//user:s3cret-token@127.0.0.1:7890', '//127.0.0.1:7890'],
    [`via user:${password}@10.1.1.1:8080 failed`, 'via 10.1.1.1:8080 failed'],
    ['http://user:secret@[::1]:8792/path', 'http://[::1]:8792/path']
  ];
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.includes('s3cret'), false);
    assert.equal(got.includes('p@ss'), false);
  }
  assert.equal(redactPublic('http://user@127.0.0.1:7890'), 'http://user@127.0.0.1:7890');
  assert.equal(redactPublic('member@example.test'), 'member@example.test');
  assert.equal(redactPublic('http://example.com/foo:bar@baz'), 'http://example.com/foo:bar@baz');
  assert.equal(redactPublic('Build v1:2@beta'), 'Build v1:2@beta');
  const proxy = `http://user:${password}@127.0.0.1:7890`;
  const snap = publicSnapshot({ settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true }, accounts: [{ id: 'acc-1', last_error: `via ${proxy} failed` }] });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].last_error, 'via http://127.0.0.1:7890 failed');
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops schemeless proxy passwords on a single-label host', () => {
  const cases = [
    ['user:s3cret-token@my-proxy:7890', 'my-proxy:7890'],
    ['via user:s3cret proxy@my_proxy:1080 failed', 'via my_proxy:1080 failed'],
    ['note user:p@ss@router:8080/path', 'note router:8080/path'],
    ['plan socks5://alice:hunter2@prx:1080', 'plan socks5://prx:1080']
  ];
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(got.includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('p@ss'), false);
  }
  assert.equal(redactPublic('Build v1:2@beta'), 'Build v1:2@beta');
  assert.equal(redactPublic('member@example.test'), 'member@example.test');
  assert.equal(redactPublic('user:s3cret@internal'), 'user:s3cret@internal');
  const snap = publicSnapshot({
    accounts: [{ id: 'acc-1', name: 'note user:s3cret-token@my-proxy:7890', email: 'a@example.test', plan_type: 'team user:s3cret-token@router:8080', last_error: 'dial user:s3cret-token@my-proxy:7890' }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.accounts[0].name, 'note my-proxy:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].plan_type, 'team router:8080');
  assert.equal(delivered.accounts[0].last_error, 'dial my-proxy:7890');
  assert.equal(delivered.accounts[0].name.includes('s3cret'), false);
});

test('renderer text drops proxy passwords hidden by an encoded colon', () => {
  const cases = [
    ['http://user%3As3cret-token@127.0.0.1:7890', 'http://127.0.0.1:7890'],
    ['http://user%3as3cret-token@127.0.0.1:7890', 'http://127.0.0.1:7890'],
    ['user%3As3cret-token@127.0.0.1:7890', '127.0.0.1:7890'],
    ['//user%3As3cret-token@my-proxy:7890', '//my-proxy:7890'],
    ['note http://user%3As3cret proxy@10.1.1.1:8080 failed', 'note http://10.1.1.1:8080 failed'],
    ['socks5://alice%3Ahunter2@10.0.0.8:1080', 'socks5://10.0.0.8:1080']
  ];
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.toLowerCase().includes('%3a'), false);
    assert.equal(got.includes('hunter2'), false);
  }
  assert.equal(redactPublic('http://user@127.0.0.1:7890'), 'http://user@127.0.0.1:7890');
  assert.equal(redactPublic('http://user%3A@127.0.0.1:7890'), 'http://user%3A@127.0.0.1:7890');
  const proxy = 'http://user%3As3cret-token@127.0.0.1:7890';
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note ${proxy}`, email: 'a@example.test', plan_type: 'team', last_error: `dial ${proxy}` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note http://127.0.0.1:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial http://127.0.0.1:7890');
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops schemeless proxy passwords before trailing punctuation', () => {
  const cases = [
    ['(user:s3cret-token@127.0.0.1:7890)', '(127.0.0.1:7890)'],
    ['"user:s3cret-token@127.0.0.1:7890"', '"127.0.0.1:7890"'],
    ["'user:s3cret-token@my-proxy:7890'", "'my-proxy:7890'"],
    ['<user:s3cret-token@10.0.0.8:1080>', '<10.0.0.8:1080>'],
    ['see [user:s3cret-token@127.0.0.1:7890]', 'see [127.0.0.1:7890]'],
    ['see {user:s3cret-token@my-proxy:7890}', 'see {my-proxy:7890}'],
    ['dial user:s3cret-token@127.0.0.1:7890。', 'dial 127.0.0.1:7890。'],
    ['note user:s3cret-token@router:8080.', 'note router:8080.'],
    ['list user:s3cret-token@example.com, next', 'list example.com, next'],
    ['end user:s3cret-token@[::1]:8792)', 'end [::1]:8792)'],
    ['user%3As3cret-token@127.0.0.1:7890)', '127.0.0.1:7890)'],
    ['via user:s3cret proxy@my-proxy:7890.', 'via my-proxy:7890.'],
    ['two user:s3cret-token@127.0.0.1:7890) and user:other-secret@10.0.0.8:1080.', 'two 127.0.0.1:7890) and 10.0.0.8:1080.'],
    ['user:p@ss@127.0.0.1:7890).', '127.0.0.1:7890).'],
    ['「user:s3cret-token@my-proxy:7890」', '「my-proxy:7890」'],
    ['（user:s3cret-token@127.0.0.1:7890）', '（127.0.0.1:7890）']
  ];
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('other-secret'), false);
    assert.equal(got.includes('p@ss'), false);
  }
  assert.equal(redactPublic('Build v1:2@beta.'), 'Build v1:2@beta.');
  assert.equal(redactPublic('member@example.test.'), 'member@example.test.');
  assert.equal(redactPublic('user:s3cret@internal.'), 'user:s3cret@internal.');
  assert.equal(redactPublic('user:s3cret@internal。'), 'user:s3cret@internal。');
  assert.equal(redactPublic('see (http://127.0.0.1:7890)'), 'see (http://127.0.0.1:7890)');
  const proxy = 'http://user:s3cret-token@127.0.0.1:7890';
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: 'note (user:s3cret-token@my-proxy:7890)', email: 'a@example.test', last_error: 'dial user:s3cret-token@127.0.0.1:7890。' }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note (my-proxy:7890)');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial 127.0.0.1:7890。');
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by an encoded at-sign', () => {
  const cases = [
    ['http://user:s3cret-token%40127.0.0.1:7890', 'http://127.0.0.1:7890'],
    ['http://user%3As3cret-token%40127.0.0.1:7890', 'http://127.0.0.1:7890'],
    ['user:s3cret-token%40127.0.0.1:7890', '127.0.0.1:7890'],
    ['user:s3cret-token%40my-proxy:7890).', 'my-proxy:7890).'],
    ['//user:s3cret-token%4010.0.0.8:1080', '//10.0.0.8:1080'],
    ['socks5://alice:hunter2%4010.0.0.8:1080', 'socks5://10.0.0.8:1080'],
    ['via user:s3cret token%4010.1.1.1:8080 failed', 'via 10.1.1.1:8080 failed'],
    ['(user:s3cret-token%40router:8080)', '(router:8080)'],
    ['http://user:p%40ss@127.0.0.1:7890/x', 'http://127.0.0.1:7890/x'],
    ['user:p@ss%40127.0.0.1:7890', '127.0.0.1:7890'],
    ['two user:s3cret%40127.0.0.1:7890) and user:other-secret%4010.0.0.8:1080.', 'two 127.0.0.1:7890) and 10.0.0.8:1080.']
  ];
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
    assert.equal(got.includes('p%40ss') || got.includes('p@ss'), false);
  }
  assert.equal(redactPublic('http://user@127.0.0.1:7890'), 'http://user@127.0.0.1:7890');
  assert.equal(redactPublic('http://user%40127.0.0.1:7890'), 'http://user%40127.0.0.1:7890');
  assert.equal(redactPublic('http://user%3A@127.0.0.1:7890'), 'http://user%3A@127.0.0.1:7890');
  assert.equal(redactPublic('http://user%3A%40127.0.0.1:7890'), 'http://user%3A%40127.0.0.1:7890');
  assert.equal(redactPublic('Build v1:2%40beta'), 'Build v1:2%40beta');
  assert.equal(redactPublic('member%40example.test'), 'member%40example.test');
  assert.equal(redactPublic('user:s3cret%40internal'), 'user:s3cret%40internal');
  assert.equal(redactPublic('note 100%40off sale'), 'note 100%40off sale');
  assert.equal(redactPublic('http://example.com/foo:bar%40baz'), 'http://example.com/foo:bar%40baz');
  const proxy = 'http://user:s3cret-token%40127.0.0.1:7890';
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: 'note user:s3cret-token%40my-proxy:7890', email: 'a@example.test', last_error: 'dial http://user%3As3cret-token%40127.0.0.1:7890 failed' }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my-proxy:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial http://127.0.0.1:7890 failed');
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops schemeless proxy passwords on an encoded port or an alternate numeric host', () => {
  const cases = [
    ['user:s3cret-token@127.0.0.1%3A7890', '127.0.0.1%3A7890'],
    ['user:s3cret-token@127.0.0.1%3a7890', '127.0.0.1%3a7890'],
    ['(user:s3cret-token@127.0.0.1%3A7890)', '(127.0.0.1%3A7890)'],
    ['user:s3cret-token%40my-proxy%3A7890).', 'my-proxy%3A7890).'],
    ['//user:s3cret-token@10.0.0.8%3A1080', '//10.0.0.8%3A1080'],
    ['via user:s3cret proxy@127.0.0.1%3A8080 failed', 'via 127.0.0.1%3A8080 failed'],
    ['via user:s3cret proxy%4010.1.1.1%3A8080 failed', 'via 10.1.1.1%3A8080 failed'],
    ['user:p@ss@127.0.0.1%3A7890', '127.0.0.1%3A7890'],
    ['note user:s3cret-token@[::1]%3A8792', 'note [::1]%3A8792'],
    ['user:s3cret-token@127.1:7890', '127.1:7890'],
    ['(user:s3cret-token@127.0.1:80)', '(127.0.1:80)'],
    ['dial user:s3cret-token@10.1:8080 failed', 'dial 10.1:8080 failed'],
    ['user:s3cret-token@0x7f000001:7890', '0x7f000001:7890'],
    ['user:s3cret-token@0X7F000001:7890', '0X7F000001:7890'],
    ['user:s3cret-token@2130706433:7890', '2130706433:7890'],
    ['user:s3cret-token@0177.0.0.1:7890', '0177.0.0.1:7890'],
    ['user:s3cret-token@0x7f.0.0.1:7890', '0x7f.0.0.1:7890'],
    ['two user:s3cret-token@127.1:7890) and user:other-secret@10.0.0.8%3A1080.', 'two 127.1:7890) and 10.0.0.8%3A1080.'],
    ['http://user:s3cret-token@127.1:7890/x', 'http://127.1:7890/x'],
    ['socks5://alice:hunter2@2130706433:1080', 'socks5://2130706433:1080']
  ];
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('other-secret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('p@ss'), false);
  }
  assert.equal(redactPublic('Build v1:2@beta'), 'Build v1:2@beta');
  assert.equal(redactPublic('Build v1:2%40beta'), 'Build v1:2%40beta');
  assert.equal(redactPublic('user:s3cret@internal'), 'user:s3cret@internal');
  assert.equal(redactPublic('user:s3cret%40internal'), 'user:s3cret%40internal');
  assert.equal(redactPublic('user:s3cret@127.1'), 'user:s3cret@127.1');
  assert.equal(redactPublic('user:s3cret@10.1'), 'user:s3cret@10.1');
  assert.equal(redactPublic('user:s3cret@2130706433'), 'user:s3cret@2130706433');
  assert.equal(redactPublic('user:s3cret@0x7f000001'), 'user:s3cret@0x7f000001');
  assert.equal(redactPublic('score 1:2@10.5'), 'score 1:2@10.5');
  assert.equal(redactPublic('member@example.test'), 'member@example.test');
  assert.equal(redactPublic('note 100%40off sale'), 'note 100%40off sale');
  assert.equal(redactPublic('http://user@127.0.0.1%3A7890'), 'http://user@127.0.0.1%3A7890');
  assert.equal(redactPublic('http://user%3A@127.0.0.1%3A7890'), 'http://user%3A@127.0.0.1%3A7890');
  const proxy = 'http://user:s3cret-token@127.0.0.1:7890';
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: 'note user:s3cret-token@127.1:7890', email: 'a@example.test', last_error: 'dial user:s3cret-token@127.0.0.1%3A7890 failed' }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note 127.1:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial 127.0.0.1%3A7890 failed');
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords embedded in a query, path, or fragment', () => {
  const cases = [
    ['http://example.com/?x=user:s3cret-token@10.0.0.8:1080', 'http://example.com/?x=10.0.0.8:1080'],
    ['http://example.com/?user:s3cret-token@10.0.0.8:1080', 'http://example.com/?10.0.0.8:1080'],
    ['http://example.com/user:s3cret-token@10.0.0.8:1080', 'http://example.com/10.0.0.8:1080'],
    ['http://127.0.0.1:7890#user:s3cret-token@10.0.0.8:1080', 'http://127.0.0.1:7890#10.0.0.8:1080'],
    ['a=1&user:s3cret-token@my-proxy:7890', 'a=1&my-proxy:7890'],
    ['proxy=user:s3cret-token@127.0.0.1:7890', 'proxy=127.0.0.1:7890'],
    ['see proxy=user:s3cret-token@127.0.0.1%3A7890', 'see proxy=127.0.0.1%3A7890'],
    ['http://example.com/?x=user:s3cret%40my-proxy%3A7890', 'http://example.com/?x=my-proxy%3A7890'],
    ['path/user:p@ss@127.0.0.1:7890', 'path/127.0.0.1:7890'],
    ['note (http://example.com/?user:s3cret-token@127.1:7890).', 'note (http://example.com/?127.1:7890).'],
    ['http://example.com/foo:bar@baz.com', 'http://example.com/baz.com']
  ];
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('p@ss'), false);
  }
  assert.equal(redactPublic('http://example.com/foo:bar@baz'), 'http://example.com/foo:bar@baz');
  assert.equal(redactPublic('http://example.com/foo:bar%40baz'), 'http://example.com/foo:bar%40baz');
  assert.equal(redactPublic('http://user@127.0.0.1:7890'), 'http://user@127.0.0.1:7890');
  assert.equal(redactPublic('member@example.test'), 'member@example.test');
  assert.equal(redactPublic('note 100%40off sale'), 'note 100%40off sale');
  assert.equal(redactPublic('Build v1:2@beta'), 'Build v1:2@beta');
  assert.equal(redactPublic('user:s3cret@internal'), 'user:s3cret@internal');
  const proxy = 'http://user:s3cret-token@127.0.0.1:7890';
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: true, usage_probe: false },
    accounts: [{ id: 'acc-1', name: 'via http://example.com/?x=user:s3cret-token@10.0.0.8:1080', email: 'a@example.test', last_error: 'dial a=1&user:s3cret-token@my-proxy:7890' }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'via http://example.com/?x=10.0.0.8:1080');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial a=1&my-proxy:7890');
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords that contain a slash, question mark, or hash', () => {
  const cases = [
    ['http://user:s3cret/token@127.0.0.1:7890', 'http://127.0.0.1:7890'],
    ['http://user:s3cret?x@127.0.0.1:7890', 'http://127.0.0.1:7890'],
    ['http://user:s3cret#x@127.0.0.1:7890', 'http://127.0.0.1:7890'],
    ['user:s3cret/token@10.0.0.8:1080', '10.0.0.8:1080'],
    ['(user:s3cret/token@my-proxy:7890)', '(my-proxy:7890)'],
    ['http://example.com/?x=user:s3cret/token@10.0.0.8:1080', 'http://example.com/?x=10.0.0.8:1080'],
    ['http://example.com/user:s3cret?x@127.1:7890', 'http://example.com/127.1:7890'],
    ['http://127.0.0.1:9#user:s3cret#token@127.0.0.1%3A7890', 'http://127.0.0.1:9#127.0.0.1%3A7890'],
    ['via user:s3cret /token@my-proxy:7890 failed', 'via my-proxy:7890 failed'],
    ['socks5://alice:hun/ter2@10.0.0.8:1080', 'socks5://10.0.0.8:1080'],
    ['http://user:p@ss/word@127.0.0.1:7890/x', 'http://127.0.0.1:7890/x'],
    ['http://user:s3cret%2Ftoken@127.0.0.1:7890', 'http://127.0.0.1:7890'],
    ['http://user:s3cret%3Ftoken@10.0.0.8:1080', 'http://10.0.0.8:1080'],
    ['http://user:s3cret%23token@my-proxy:7890', 'http://my-proxy:7890'],
    ['two user:s3cret/token@127.0.0.1:7890) and user:other?secret@10.0.0.8:1080.', 'two 127.0.0.1:7890) and 10.0.0.8:1080.'],
    ['invalid proxy url "http://user:s3cret/token@127.0.0.1:7890": parse "http://user:s3cret/token@127.0.0.1:7890": invalid port ":s3cret" after host', 'invalid proxy url "http://127.0.0.1:7890": parse "http://127.0.0.1:7890": invalid port ":[凭据已隐藏]" after host']
  ];
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hun/ter2'), false);
    assert.equal(got.includes('other?secret'), false);
    assert.equal(got.includes('p@ss'), false);
  }
  assert.equal(redactPublic('http://example.com/foo:bar@baz'), 'http://example.com/foo:bar@baz');
  assert.equal(redactPublic('http://example.com/foo:bar/baz@qux'), 'http://example.com/foo:bar/baz@qux');
  assert.equal(redactPublic('http://example.com/foo:bar%40baz'), 'http://example.com/foo:bar%40baz');
  assert.equal(redactPublic('http://127.0.0.1:7890/path?q=1#frag'), 'http://127.0.0.1:7890/path?q=1#frag');
  assert.equal(redactPublic('see (http://127.0.0.1:7890)'), 'see (http://127.0.0.1:7890)');
  assert.equal(redactPublic('Build v1:2@beta'), 'Build v1:2@beta');
  assert.equal(redactPublic('user:s3cret@internal'), 'user:s3cret@internal');
  assert.equal(redactPublic('member@example.test'), 'member@example.test');
  assert.equal(redactPublic('invalid port ":8080" after host'), 'invalid port ":8080" after host');
  const proxy = 'http://user:s3cret/token@127.0.0.1:7890';
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: 'note user:s3cret?x@my-proxy:7890', email: 'a@example.test', last_error: 'invalid proxy url "http://user:s3cret/token@10.0.0.8:1080": invalid port ":s3cret" after host' }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my-proxy:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'invalid proxy url "http://10.0.0.8:1080": invalid port ":[凭据已隐藏]" after host');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by a colon lookalike', () => {
  const marks = ['\uFE13', '\uFE55', '\uFF1A', '\u2236', '\u02D0', '\uA789', '\u02F8', '\u0703', '\u0704', '\u0589'];
  const password = 's3cret-token';
  const nest = (value, layers) => {
    let out = value;
    for (let layer = 0; layer < layers; layer += 1) out = out.replace(/%/g, '%25');
    return out;
  };
  const cases = [];
  for (const mark of marks) {
    const encoded = encodeURIComponent(mark);
    cases.push([`http://user${mark}${password}@127.0.0.1:7890`, 'http://127.0.0.1:7890']);
    cases.push([`user${mark}${password}@my-proxy:7890`, 'my-proxy:7890']);
    cases.push([`(user${mark}${password}@10.0.0.8:1080)`, '(10.0.0.8:1080)']);
    cases.push([`http://user${encoded}${password}@127.0.0.1:7890`, 'http://127.0.0.1:7890']);
    cases.push([`user${nest(encoded, 1).toLowerCase()}${password}@127.1:7890`, '127.1:7890']);
    cases.push([`//user${nest(encoded, 3)}${password}@[::1]:8792`, '//[::1]:8792']);
  }
  cases.push(
    [`http://user%253A${password}@127.0.0.1:7890`, 'http://127.0.0.1:7890'],
    [`user%25253A${password}@my-proxy:7890`, 'my-proxy:7890'],
    [`http://user%2525253a${password}@10.0.0.8:1080/x`, 'http://10.0.0.8:1080/x'],
    [`via user\uFF1A${password} proxy@10.1.1.1:8080 failed`, 'via 10.1.1.1:8080 failed'],
    ['socks5://alice\uFF1Ahunter2@10.0.0.8:1080', 'socks5://10.0.0.8:1080'],
    [`http://example.com/?x=user\uFF1A${password}@10.0.0.8:1080`, 'http://example.com/?x=10.0.0.8:1080'],
    [`http://user\uFF1A${password}/token@127.0.0.1:7890`, 'http://127.0.0.1:7890'],
    [`http://user\uFF1Ap%40ss@127.0.0.1:7890/x`, 'http://127.0.0.1:7890/x'],
    [`user:${password}@127.0.0.1\uFF1A7890`, '127.0.0.1\uFF1A7890'],
    [`user:${password}@my-proxy%EF%BC%9A7890`, 'my-proxy%EF%BC%9A7890'],
    [`http://127.0.0.1:9#user\uFF1As3cret#token@127.0.0.1%3A7890`, 'http://127.0.0.1:9#127.0.0.1%3A7890'],
    [`http://example.com/foo\uFF1Abar@baz.com`, 'http://example.com/baz.com'],
    ['two user\uFF1As3cret-token@127.0.0.1:7890) and user\u2236other-secret@10.0.0.8:1080.', 'two 127.0.0.1:7890) and 10.0.0.8:1080.'],
    ['invalid proxy url "http://user\uFF1As3cret/token@127.0.0.1:7890": parse "http://user\uFF1As3cret/token@127.0.0.1:7890": invalid port "\uFF1As3cret" after host', 'invalid proxy url "http://127.0.0.1:7890": parse "http://127.0.0.1:7890": invalid port ":[凭据已隐藏]" after host']
  );
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
    assert.equal(got.includes('p%40ss') || got.includes('p@ss'), false);
  }
  assert.equal(redactPublic('http://user\uFF1A@127.0.0.1:7890'), 'http://user\uFF1A@127.0.0.1:7890');
  assert.equal(redactPublic('http://user%253A@127.0.0.1:7890'), 'http://user%253A@127.0.0.1:7890');
  assert.equal(redactPublic('http://user%25EF%25BC%259A@127.0.0.1:7890'), 'http://user%25EF%25BC%259A@127.0.0.1:7890');
  assert.equal(redactPublic('Build v1\uFF1A2@beta'), 'Build v1\uFF1A2@beta');
  assert.equal(redactPublic('user\uFF1As3cret@internal'), 'user\uFF1As3cret@internal');
  assert.equal(redactPublic('member@example.test'), 'member@example.test');
  assert.equal(redactPublic('note 100%40off sale'), 'note 100%40off sale');
  assert.equal(redactPublic('http://user@127.0.0.1\uFF1A7890'), 'http://user@127.0.0.1\uFF1A7890');
  assert.equal(redactPublic('http://example.com/foo\uFF1Abar@baz'), 'http://example.com/foo\uFF1Abar@baz');
  assert.equal(redactPublic('\u6CE8\u610F\uFF1A\u7A0D\u540E\u91CD\u8BD5'), '\u6CE8\u610F\uFF1A\u7A0D\u540E\u91CD\u8BD5');
  assert.equal(redactPublic('invalid port ":8080" after host'), 'invalid port ":8080" after host');
  const proxy = `http://user\uFF1A${password}@127.0.0.1:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note user\u2236${password}@my-proxy:7890`, email: 'a@example.test', last_error: `dial user%253A${password}@127.0.0.1:7890 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my-proxy:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial 127.0.0.1:7890 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by an at-sign lookalike', () => {
  const marks = ['\uFE6B', '\uFF20'];
  const password = 's3cret-token';
  const nest = (value, layers) => {
    let out = value;
    for (let layer = 0; layer < layers; layer += 1) out = out.replace(/%/g, '%25');
    return out;
  };
  const cases = [];
  for (const mark of marks) {
    const encoded = encodeURIComponent(mark);
    cases.push([`http://user:${password}${mark}127.0.0.1:7890`, 'http://127.0.0.1:7890']);
    cases.push([`user:${password}${mark}my-proxy:7890`, 'my-proxy:7890']);
    cases.push([`(user:${password}${mark}10.0.0.8:1080)`, '(10.0.0.8:1080)']);
    cases.push([`http://user:${password}${encoded}127.0.0.1:7890`, 'http://127.0.0.1:7890']);
    cases.push([`user:${password}${nest(encoded, 1).toLowerCase()}127.1:7890`, '127.1:7890']);
    cases.push([`//user:${password}${nest(encoded, 3)}[::1]:8792`, '//[::1]:8792']);
  }
  cases.push(
    [`http://user:${password}%2540127.0.0.1:7890`, 'http://127.0.0.1:7890'],
    [`user:${password}%252540my-proxy:7890`, 'my-proxy:7890'],
    [`http://user:${password}%2525254010.0.0.8:1080/x`, 'http://10.0.0.8:1080/x'],
    [`via user:${password} proxy\uFF2010.1.1.1:8080 failed`, 'via 10.1.1.1:8080 failed'],
    ['socks5://alice:hunter2\uFE6B10.0.0.8:1080', 'socks5://10.0.0.8:1080'],
    [`http://example.com/?x=user:${password}\uFF2010.0.0.8:1080`, 'http://example.com/?x=10.0.0.8:1080'],
    [`http://user:${password}/token\uFF20127.0.0.1:7890`, 'http://127.0.0.1:7890'],
    [`http://user:p%40ss\uFF20127.0.0.1:7890/x`, 'http://127.0.0.1:7890/x'],
    [`http://user\uFF1A${password}\uFF20127.0.0.1:7890`, 'http://127.0.0.1:7890'],
    [`http://127.0.0.1:9#user:s3cret#token\uFF2010.0.0.8:1080`, 'http://127.0.0.1:9#10.0.0.8:1080'],
    ['two user:s3cret-token\uFF20127.0.0.1:7890) and user:other-secret\uFE6B10.0.0.8:1080.', 'two 127.0.0.1:7890) and 10.0.0.8:1080.'],
    ['invalid proxy url "http://user:s3cret/token\uFF20127.0.0.1:7890": invalid port ":s3cret" after host', 'invalid proxy url "http://127.0.0.1:7890": invalid port ":[凭据已隐藏]" after host']
  );
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
    assert.equal(got.includes('p%40ss') || got.includes('p@ss'), false);
  }
  assert.equal(redactPublic('http://user\uFF20127.0.0.1:7890'), 'http://user\uFF20127.0.0.1:7890');
  assert.equal(redactPublic('http://user%2540127.0.0.1:7890'), 'http://user%2540127.0.0.1:7890');
  assert.equal(redactPublic('http://user%40127.0.0.1:7890'), 'http://user%40127.0.0.1:7890');
  assert.equal(redactPublic('member\uFF20example.test'), 'member\uFF20example.test');
  assert.equal(redactPublic('Build v1:2\uFF20beta'), 'Build v1:2\uFF20beta');
  assert.equal(redactPublic('user:s3cret\uFF20internal'), 'user:s3cret\uFF20internal');
  assert.equal(redactPublic('note 100%40off sale'), 'note 100%40off sale');
  assert.equal(redactPublic('note 100%2540off sale'), 'note 100%2540off sale');
  assert.equal(redactPublic('http://user@127.0.0.1:7890'), 'http://user@127.0.0.1:7890');
  assert.equal(redactPublic('member@example.test'), 'member@example.test');
  const proxy = `http://user:${password}\uFF20127.0.0.1:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: true, usage_probe: false },
    accounts: [{ id: 'acc-1', name: `note user:${password}\uFE6Bmy-proxy:7890`, email: 'a@example.test', last_error: `dial user:${password}%2540127.0.0.1:7890 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my-proxy:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial 127.0.0.1:7890 failed');
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords when a host dot is encoded or a lookalike', () => {
  const marks = ['\uFF0E', '\uFE52', '\u2024'];
  const password = 's3cret-token';
  const nest = (value, layers) => {
    let out = value;
    for (let layer = 0; layer < layers; layer += 1) out = out.replace(/%/g, '%25');
    return out;
  };
  const fw = value => value.replace(/[0-9]/g, digit => String.fromCodePoint(digit.charCodeAt(0) + 0xFEE0));
  const cases = [];
  for (const mark of marks) {
    const encoded = encodeURIComponent(mark);
    cases.push([`user:${password}@127${mark}0${mark}0${mark}1:7890`, `127${mark}0${mark}0${mark}1:7890`]);
    cases.push([`user:${password}@my${mark}proxy:7890`, `my${mark}proxy:7890`]);
    cases.push([`(user:${password}@example${mark}com)`, `(example${mark}com)`]);
    cases.push([`user:${password}@10${encoded}0${encoded}0${encoded}8:1080`, `10${encoded}0${encoded}0${encoded}8:1080`]);
    cases.push([`user:${password}@my${nest(encoded, 1).toLowerCase()}proxy:7890`, `my${nest(encoded, 1).toLowerCase()}proxy:7890`]);
    cases.push([`//user:${password}@router${nest(encoded, 3)}example:8080`, `//router${nest(encoded, 3)}example:8080`]);
  }
  const fwHost = `${fw('127')}\uFF0E${fw('0')}\uFF0E${fw('0')}\uFF0E${fw('1')}:7890`;
  cases.push(
    [`user:${password}@127%2E0%2E0%2E1:7890`, '127%2E0%2E0%2E1:7890'],
    [`user:${password}@127%2e0%2e0%2e1:7890`, '127%2e0%2e0%2e1:7890'],
    [`(user:${password}@127%252E0%252E0%252E1:7890)`, '(127%252E0%252E0%252E1:7890)'],
    [`user:${password}@my%2Eproxy:7890`, 'my%2Eproxy:7890'],
    [`user:${password}@example%2Ecom`, 'example%2Ecom'],
    [`user:${password}@0x7f%2E0%2E0%2E1:7890`, '0x7f%2E0%2E0%2E1:7890'],
    [`user:${password}@127.0%2E0.1:7890`, '127.0%2E0.1:7890'],
    [`user:${password}@10%2E1:8080`, '10%2E1:8080'],
    [`via user:${password} proxy@127%2E0%2E0%2E1:7890 failed`, 'via 127%2E0%2E0%2E1:7890 failed'],
    [`http://example.com/?x=user:${password}@10%2E0%2E0%2E8:1080`, 'http://example.com/?x=10%2E0%2E0%2E8:1080'],
    [`http://user:${password}@127%2E0%2E0%2E1:7890/x`, 'http://127%2E0%2E0%2E1:7890/x'],
    [`socks5://alice:hunter2@10%2E0%2E0%2E8:1080`, 'socks5://10%2E0%2E0%2E8:1080'],
    [`user:${password}/token@example%2Ecom`, 'example%2Ecom'],
    [`http://user:${password}/token@127%2E0%2E0%2E1:7890`, 'http://127%2E0%2E0%2E1:7890'],
    [`user\uFF1A${password}@127%2E0%2E0%2E1:7890`, '127%2E0%2E0%2E1:7890'],
    [`user:${password}\uFF20127%2E0%2E0%2E1:7890`, '127%2E0%2E0%2E1:7890'],
    [`user:${password}@${fwHost}`, fwHost],
    [`user:${password}@${fw('2130706433')}:7890`, `${fw('2130706433')}:7890`],
    [`two user:${password}@127%2E0%2E0%2E1:7890) and user:other-secret@my\uFF0Eproxy:7890.`, 'two 127%2E0%2E0%2E1:7890) and my\uFF0Eproxy:7890.'],
    ['invalid proxy url "http://user:s3cret/token@127%2E0%2E0%2E1:7890": invalid port ":s3cret" after host', 'invalid proxy url "http://127%2E0%2E0%2E1:7890": invalid port ":[凭据已隐藏]" after host']
  );
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  assert.equal(redactPublic('Build v1:2@beta'), 'Build v1:2@beta');
  assert.equal(redactPublic('Build v1:2@beta.'), 'Build v1:2@beta.');
  assert.equal(redactPublic('user:s3cret@internal'), 'user:s3cret@internal');
  assert.equal(redactPublic('user:s3cret@internal\uFF0E'), 'user:s3cret@internal\uFF0E');
  assert.equal(redactPublic('user:s3cret@127%2E1'), 'user:s3cret@127%2E1');
  assert.equal(redactPublic('user:s3cret@10%2E1'), 'user:s3cret@10%2E1');
  assert.equal(redactPublic('score 1:2@10%2E5'), 'score 1:2@10%2E5');
  assert.equal(redactPublic('ratio:1@v1%2E2'), 'ratio:1@v1%2E2');
  assert.equal(redactPublic('ratio:1@v1\uFF0E2'), 'ratio:1@v1\uFF0E2');
  assert.equal(redactPublic('member@example%2Etest'), 'member@example%2Etest');
  assert.equal(redactPublic('member@example\uFF0Etest'), 'member@example\uFF0Etest');
  assert.equal(redactPublic('note 100%2E0 sale'), 'note 100%2E0 sale');
  assert.equal(redactPublic('http://user@127%2E0%2E0%2E1:7890'), 'http://user@127%2E0%2E0%2E1:7890');
  assert.equal(redactPublic('http://example.com/foo:bar@baz'), 'http://example.com/foo:bar@baz');
  assert.equal(redactPublic('http://example.com/foo:bar@baz%2E'), 'http://example.com/foo:bar@baz%2E');
  assert.equal(redactPublic('a..com stays user:s3cret@a..com'), 'a..com stays a..com');
  const proxy = 'http://user:s3cret-token@127%2E0%2E0%2E1:7890';
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note user:${password}@my%2Eproxy:7890`, email: 'a@example.test', last_error: `dial user:${password}@127\uFF0E0\uFF0E0\uFF0E1:7890 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my%2Eproxy:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial 127\uFF0E0\uFF0E0\uFF0E1:7890 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords when the port digits are encoded', () => {
  const password = 's3cret-token';
  const fw = value => value.replace(/[0-9]/g, digit => String.fromCodePoint(digit.charCodeAt(0) + 0xFEE0));
  const cases = [
    [`user:${password}@127.0.0.1%3A%37%38%39%30`, '127.0.0.1%3A%37%38%39%30'],
    [`user:${password}@127.0.0.1%3a%37%38%39%30`, '127.0.0.1%3a%37%38%39%30'],
    [`(user:${password}@my-proxy%3A%37%38%39%30)`, '(my-proxy%3A%37%38%39%30)'],
    [`user:${password}@10.1%3A%38%30%38%30`, '10.1%3A%38%30%38%30'],
    [`user:${password}@2130706433:%37%38%39%30`, '2130706433:%37%38%39%30'],
    [`user:${password}@my-proxy%3A%2537%2538%2539%2530`, 'my-proxy%3A%2537%2538%2539%2530'],
    [`user:${password}@127.0.0.1%3A%252537%252538%252539%252530`, '127.0.0.1%3A%252537%252538%252539%252530'],
    [`user:${password}@router:${fw('8080')}`, `router:${fw('8080')}`],
    [`user:${password}@127.0.0.1:${fw('7890')}`, `127.0.0.1:${fw('7890')}`],
    [`via user:${password} proxy@10.0.0.8%3A%31%30%38%30 failed`, 'via 10.0.0.8%3A%31%30%38%30 failed'],
    [`http://example.com/?x=user:${password}@my-proxy%3A%37%38%39%30`, 'http://example.com/?x=my-proxy%3A%37%38%39%30'],
    [`http://user:${password}@127.0.0.1%3A%37%38%39%30/x`, 'http://127.0.0.1%3A%37%38%39%30/x'],
    [`socks5://alice:hunter2@10%2E0%2E0%2E8%3A%31%30%38%30`, 'socks5://10%2E0%2E0%2E8%3A%31%30%38%30'],
    [`user:${password}/token@my-proxy%3A%37%38%39%30`, 'my-proxy%3A%37%38%39%30'],
    [`user\uFF1A${password}@127.0.0.1%3A%37%38%39%30`, '127.0.0.1%3A%37%38%39%30'],
    [`//user:${password}@127%2E1%3A%38%37%39%32`, '//127%2E1%3A%38%37%39%32'],
    [`two user:${password}@my-proxy%3A%37%38%39%30) and user:other-secret@10.1:${fw('8080')}.`, `two my-proxy%3A%37%38%39%30) and 10.1:${fw('8080')}.`],
    ['invalid proxy url "http://user:s3cret/token@127.0.0.1%3A%37%38%39%30": invalid port ":s3cret" after host', 'invalid proxy url "http://127.0.0.1%3A%37%38%39%30": invalid port ":[凭据已隐藏]" after host']
  ];
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  assert.equal(redactPublic(`user:${password}@my-proxy%3A9`), `user:${password}@my-proxy%3A9`);
  assert.equal(redactPublic(`user:${password}@10.1%3A8`), `user:${password}@10.1%3A8`);
  assert.equal(redactPublic(`user:${password}@my-proxy:%37%38%39%30%31%32`), `user:${password}@my-proxy:%37%38%39%30%31%32`);
  assert.equal(redactPublic(`user:${password}@my-proxy:7`), `user:${password}@my-proxy:7`);
  assert.equal(redactPublic(`user:${password}@my-proxy:789012`), `user:${password}@my-proxy:789012`);
  assert.equal(redactPublic('Build v1:2@beta'), 'Build v1:2@beta');
  assert.equal(redactPublic(`user:${password}@internal`), `user:${password}@internal`);
  assert.equal(redactPublic('score 1:2@10.5'), 'score 1:2@10.5');
  assert.equal(redactPublic('member@example.test'), 'member@example.test');
  assert.equal(redactPublic('note 100%37 off'), 'note 100%37 off');
  assert.equal(redactPublic('http://user@127.0.0.1%3A%37%38%39%30'), 'http://user@127.0.0.1%3A%37%38%39%30');
  assert.equal(redactPublic(`user:${password}@127.0.0.1:7890`), '127.0.0.1:7890');
  const proxy = `http://user:${password}@127.0.0.1%3A%37%38%39%30`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: true, usage_probe: false },
    accounts: [{ id: 'acc-1', name: `note user:${password}@my-proxy:${fw('7890')}`, email: 'a@example.test', last_error: `dial user:${password}@10.1%3A%38%30%38%30 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, `note my-proxy:${fw('7890')}`);
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial 10.1%3A%38%30%38%30 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords before a shell or path mark', () => {
  const password = 's3cret-token';
  const cases = [
    [`user:${password}@my-proxy:7890\`next`, 'my-proxy:7890`next'],
    [`note \`user:${password}@my-proxy:7890\` next`, 'note `my-proxy:7890` next'],
    [`user:${password}@my-proxy:7890\uFF40next`, 'my-proxy:7890\uFF40next'],
    [`dial user:${password}@router:8080|next`, 'dial router:8080|next'],
    [`a|user:${password}@router:8080|b`, 'a|router:8080|b'],
    [`dial user:${password}@10.1:8080\uFF5Cnext`, 'dial 10.1:8080\uFF5Cnext'],
    [`path user:${password}@10.1:8080\\tmp`, 'path 10.1:8080\\tmp'],
    [`path user:${password}@2130706433:7890\uFF3Ctmp`, 'path 2130706433:7890\uFF3Ctmp'],
    [`see \u201Cuser:${password}@my-proxy:7890\u201D`, 'see \u201Cmy-proxy:7890\u201D'],
    [`see \u2018user:${password}@10.1:8080\u2019`, 'see \u201810.1:8080\u2019'],
    [`user:${password}@127.0.0.1:7890\\tmp`, '127.0.0.1:7890\\tmp'],
    [`via user:${password} proxy@my-proxy:7890\` failed`, 'via my-proxy:7890` failed'],
    [`http://example.com/?x=user:${password}@router:8080|next`, 'http://example.com/?x=router:8080|next'],
    [`socks5://alice:hunter2@my-proxy:7890\\tmp`, 'socks5://my-proxy:7890\\tmp'],
    [`two user:${password}@my-proxy:7890\` and user:other-secret@10.1:8080|next`, 'two my-proxy:7890` and 10.1:8080|next']
  ];
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  assert.equal(redactPublic(`Build v1:2@beta\`next`), `Build v1:2@beta\`next`);
  assert.equal(redactPublic(`user:${password}@internal\`x`), `user:${password}@internal\`x`);
  assert.equal(redactPublic(`user:${password}@my-proxy:7\`x`), `user:${password}@my-proxy:7\`x`);
  assert.equal(redactPublic('member@example.test|next'), 'member@example.test|next');
  assert.equal(redactPublic(`user:${password}@my-proxy:789012|next`), `user:${password}@my-proxy:789012|next`);
  assert.equal(redactPublic('note 100%40off sale'), 'note 100%40off sale');
  assert.equal(redactPublic(`user:${password}@my-proxy:7890`), 'my-proxy:7890');
  const proxy = `http://user:${password}@127.0.0.1:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note \`user:${password}@my-proxy:7890\``, email: 'a@example.test', last_error: `path user:${password}@10.1:8080\\tmp failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note `my-proxy:7890`');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'path 10.1:8080\\tmp failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords before a query joiner', () => {
  const password = 's3cret-token';
  const marks = ['&', '=', '\uFF06', '\uFE60', '\uFF1D', '\uFE66', '\u207C', '\u208C'];
  const nest = (value, layers) => {
    let out = value;
    for (let layer = 0; layer < layers; layer += 1) out = out.replace(/%/g, '%25');
    return out;
  };
  const cases = [];
  for (const mark of marks) {
    const encoded = encodeURIComponent(mark);
    cases.push([`user:${password}@my-proxy:7890${mark}next`, `my-proxy:7890${mark}next`]);
    cases.push([`a${mark}1${mark}user:${password}@my-proxy:7890${mark}b`, `a${mark}1${mark}my-proxy:7890${mark}b`]);
    cases.push([`user:${password}@10.1:8080${mark}next`, `10.1:8080${mark}next`]);
    cases.push([`user:${password}@example.com${mark}next`, `example.com${mark}next`]);
    cases.push([`user:${password}@router:8080${encoded}next`, `router:8080${encoded}next`]);
    cases.push([`user:${password}@router:8080${encoded.toLowerCase()}next`, `router:8080${encoded.toLowerCase()}next`]);
    cases.push([`user:${password}@2130706433:7890${nest(encoded, 3)}next`, `2130706433:7890${nest(encoded, 3)}next`]);
  }
  cases.push(
    [`a=1&user:${password}@my-proxy:7890&b=2`, 'a=1&my-proxy:7890&b=2'],
    [`proxy=user:${password}@router:8080&fallback=1`, 'proxy=router:8080&fallback=1'],
    [`http://example.com/?x=user:${password}@10.0.0.8:1080&y=1`, 'http://example.com/?x=10.0.0.8:1080&y=1'],
    [`user:${password}@127.0.0.1:7890&y=1`, '127.0.0.1:7890&y=1'],
    [`user:${password}@my-proxy:7890%26next`, 'my-proxy:7890%26next'],
    [`user:${password}@my-proxy:7890%3Dnext`, 'my-proxy:7890%3Dnext'],
    [`user:${password}@my-proxy:7890%3dnext`, 'my-proxy:7890%3dnext'],
    [`user:${password}@my-proxy:7890%2526next`, 'my-proxy:7890%2526next'],
    [`user:${password}@10.1:8080%25253Dnext`, '10.1:8080%25253Dnext'],
    [`user:${password}@my-proxy:7890%25252526next`, 'my-proxy:7890%25252526next'],
    [`via user:${password} proxy@my-proxy:7890&next`, 'via my-proxy:7890&next'],
    [`socks5://alice:hunter2@my-proxy:7890&x=1`, 'socks5://my-proxy:7890&x=1'],
    [`user:${password}/token@my-proxy:7890&next`, 'my-proxy:7890&next'],
    [`//user:${password}@my-proxy:7890%3Dnext`, '//my-proxy:7890%3Dnext'],
    [`user\uFF1A${password}@my-proxy:7890&next`, 'my-proxy:7890&next'],
    [`two user:${password}@my-proxy:7890& and user:other-secret@10.1:8080=next`, 'two my-proxy:7890& and 10.1:8080=next']
  );
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  assert.equal(redactPublic(`Build v1:2@beta&next`), `Build v1:2@beta&next`);
  assert.equal(redactPublic(`user:${password}@internal&x`), `user:${password}@internal&x`);
  assert.equal(redactPublic(`user:${password}@my-proxy:7&x`), `user:${password}@my-proxy:7&x`);
  assert.equal(redactPublic(`user:${password}@my-proxy:789012&next`), `user:${password}@my-proxy:789012&next`);
  assert.equal(redactPublic(`user:${password}@my-proxy:%37%26x`), `user:${password}@my-proxy:%37%26x`);
  assert.equal(redactPublic('member@example.test&next'), 'member@example.test&next');
  assert.equal(redactPublic('member@example.test\uFF1Dnext'), 'member@example.test\uFF1Dnext');
  assert.equal(redactPublic('note 100%26off sale'), 'note 100%26off sale');
  assert.equal(redactPublic('note 100%3Doff sale'), 'note 100%3Doff sale');
  assert.equal(redactPublic('score 1:2@10.5&x'), 'score 1:2@10.5&x');
  assert.equal(redactPublic('http://user@127.0.0.1:7890&x'), 'http://user@127.0.0.1:7890&x');
  assert.equal(redactPublic(`user:${password}@my-proxy:7890`), 'my-proxy:7890');
  const proxy = `http://user:${password}@127.0.0.1:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `a=1&user:${password}@my-proxy:7890&b=2`, email: 'a@example.test', last_error: `dial user:${password}@10.1:8080%26next failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'a=1&my-proxy:7890&b=2');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial 10.1:8080%26next failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords before an opening bracket', () => {
  const password = 's3cret-token';
  const marks = ['(', '<', '[', '{', ')', '>', ']', '}', '\u207D', '\u207E', '\u208D', '\u208E', '\uFE35', '\uFE36', '\uFE37', '\uFE38', '\uFE47', '\uFE48', '\uFE59', '\uFE5A', '\uFE5B', '\uFE5C', '\uFE64', '\uFE65', '\uFF08', '\uFF09', '\uFF1C', '\uFF1E', '\uFF3B', '\uFF3D', '\uFF5B', '\uFF5D'];
  const nest = (value, layers) => {
    let out = value;
    for (let layer = 0; layer < layers; layer += 1) out = out.replace(/%/g, '%25');
    return out;
  };
  const cases = [];
  for (const mark of marks) {
    const encoded = encodeURIComponent(mark);
    cases.push([`user:${password}@my-proxy:7890${mark}next`, `my-proxy:7890${mark}next`]);
    cases.push([`note ${mark}user:${password}@10.1:8080${mark}`, `note ${mark}10.1:8080${mark}`]);
    cases.push([`user:${password}@example.com${mark}x`, `example.com${mark}x`]);
    cases.push([`user:${password}@router:8080${encoded}next`, `router:8080${encoded}next`]);
    cases.push([`user:${password}@router:8080${encoded.toLowerCase()}next`, `router:8080${encoded.toLowerCase()}next`]);
    cases.push([`user:${password}@2130706433:7890${nest(encoded, 3)}next`, `2130706433:7890${nest(encoded, 3)}next`]);
  }
  cases.push(
    [`user:${password}@my-proxy:7890<br>`, 'my-proxy:7890<br>'],
    [`user:${password}@10.1:8080[ref]`, '10.1:8080[ref]'],
    [`user:${password}@my-proxy:7890{,2}`, 'my-proxy:7890{,2}'],
    [`(user:${password}@127.0.0.1:7890)`, '(127.0.0.1:7890)'],
    [`\uFF5Buser:${password}@my-proxy:7890\uFF5D`, '\uFF5Bmy-proxy:7890\uFF5D'],
    [`http://example.com/?x=user:${password}@router:8080(next`, 'http://example.com/?x=router:8080(next'],
    [`via user:${password} proxy@my-proxy:7890<br> failed`, 'via my-proxy:7890<br> failed'],
    [`socks5://alice:hunter2@my-proxy:7890[ref]`, 'socks5://my-proxy:7890[ref]'],
    [`user:${password}/token@my-proxy:7890{next`, 'my-proxy:7890{next'],
    [`//user:${password}@10.1:8080%3Cnext`, '//10.1:8080%3Cnext'],
    [`user:${password}@my-proxy:7890%28next`, 'my-proxy:7890%28next'],
    [`user:${password}@my-proxy:7890%5Bnext`, 'my-proxy:7890%5Bnext'],
    [`user:${password}@my-proxy:7890%7Bnext`, 'my-proxy:7890%7Bnext'],
    [`user:${password}@127.0.0.1:7890%2528next`, '127.0.0.1:7890%2528next'],
    [`user\uFF1A${password}@my-proxy:7890<br>`, 'my-proxy:7890<br>'],
    [`two user:${password}@my-proxy:7890( and user:other-secret@10.1:8080[next`, 'two my-proxy:7890( and 10.1:8080[next']
  );
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  assert.equal(redactPublic(`Build v1:2@beta(next`), `Build v1:2@beta(next`);
  assert.equal(redactPublic(`user:${password}@internal(x`), `user:${password}@internal(x`);
  assert.equal(redactPublic(`user:${password}@my-proxy:7(x`), `user:${password}@my-proxy:7(x`);
  assert.equal(redactPublic(`user:${password}@my-proxy:789012(next`), `user:${password}@my-proxy:789012(next`);
  assert.equal(redactPublic(`user:${password}@my-proxy:%37%28x`), `user:${password}@my-proxy:%37%28x`);
  assert.equal(redactPublic('member@example.test(next'), 'member@example.test(next');
  assert.equal(redactPublic('note 100%28off sale'), 'note 100%28off sale');
  assert.equal(redactPublic('score 1:2@10.5(x'), 'score 1:2@10.5(x');
  assert.equal(redactPublic('http://user@127.0.0.1:7890(x'), 'http://user@127.0.0.1:7890(x');
  assert.equal(redactPublic(`user:${password}@my-proxy:7890`), 'my-proxy:7890');
  const proxy = `http://user:${password}@127.0.0.1:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: true, usage_probe: false },
    accounts: [{ id: 'acc-1', name: `see <user:${password}@my-proxy:7890>`, email: 'a@example.test', last_error: `dial user:${password}@10.1:8080<br> failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'see <my-proxy:7890>');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial 10.1:8080<br> failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});
