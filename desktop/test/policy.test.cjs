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

test('renderer text drops proxy passwords before a tilde, glob, or shell mark', () => {
  const password = 's3cret-token';
  const marks = ['~', '*', '+', '$', '^', '\uFF5E', '\uFE61', '\uFF0A', '\u207A', '\u208A', '\uFB29', '\uFE62', '\uFF0B', '\uFE69', '\uFF04', '\uFF3E'];
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
    [`user:${password}@my-proxy:7890~/tmp`, 'my-proxy:7890~/tmp'],
    [`path user:${password}@10.1:8080*.log`, 'path 10.1:8080*.log'],
    [`dial user:${password}@router:8080$HOME`, 'dial router:8080$HOME'],
    [`socks5://alice:hunter2@my-proxy:7890~tmp`, 'socks5://my-proxy:7890~tmp'],
    [`via user:${password} proxy@my-proxy:7890* failed`, 'via my-proxy:7890* failed'],
    [`user:${password}/token@my-proxy:7890+next`, 'my-proxy:7890+next'],
    [`//user:${password}@10.1:8080%7Enext`, '//10.1:8080%7Enext'],
    [`http://example.com/?x=user:${password}@router:8080^next`, 'http://example.com/?x=router:8080^next'],
    [`user\uFF1A${password}@my-proxy:7890~tmp`, 'my-proxy:7890~tmp'],
    [`two user:${password}@my-proxy:7890~ and user:other-secret@10.1:8080*next`, 'two my-proxy:7890~ and 10.1:8080*next']
  );
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  assert.equal(redactPublic(`Build v1:2@beta~next`), `Build v1:2@beta~next`);
  assert.equal(redactPublic(`user:${password}@internal~x`), `user:${password}@internal~x`);
  assert.equal(redactPublic(`user:${password}@my-proxy:7~x`), `user:${password}@my-proxy:7~x`);
  assert.equal(redactPublic(`user:${password}@my-proxy:789012~next`), `user:${password}@my-proxy:789012~next`);
  assert.equal(redactPublic(`user:${password}@my-proxy:%37%7Ex`), `user:${password}@my-proxy:%37%7Ex`);
  assert.equal(redactPublic('member@example.test~next'), 'member@example.test~next');
  assert.equal(redactPublic('note 100%7Eoff sale'), 'note 100%7Eoff sale');
  assert.equal(redactPublic('note $100 sale'), 'note $100 sale');
  assert.equal(redactPublic('score 1:2@10.5*x'), 'score 1:2@10.5*x');
  assert.equal(redactPublic('http://user@127.0.0.1:7890~x'), 'http://user@127.0.0.1:7890~x');
  assert.equal(redactPublic(`user:${password}@my-proxy:7890`), 'my-proxy:7890');
  const proxy = `http://user:${password}@127.0.0.1:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `path user:${password}@my-proxy:7890~/tmp`, email: 'a@example.test', last_error: `dial user:${password}@10.1:8080*.log failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'path my-proxy:7890~/tmp');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial 10.1:8080*.log failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords before a semicolon or comma', () => {
  const password = 's3cret-token';
  const marks = [';', ',', '\u037E', '\uFE14', '\uFE54', '\uFF1B', '\uFE10', '\uFE50', '\uFF0C'];
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
    [`user:${password}@my-proxy:7890;next`, 'my-proxy:7890;next'],
    [`list user:${password}@example.com, next`, 'list example.com, next'],
    [`dial user:${password}@router:8080%3Bnext`, 'dial router:8080%3Bnext'],
    [`socks5://alice:hunter2@my-proxy:7890%2Cnext`, 'socks5://my-proxy:7890%2Cnext'],
    [`via user:${password} proxy@my-proxy:7890%3B failed`, 'via my-proxy:7890%3B failed'],
    [`user:${password}/token@my-proxy:7890,next`, 'my-proxy:7890,next'],
    [`//user:${password}@10.1:8080%3bnext`, '//10.1:8080%3bnext'],
    [`http://example.com/?x=user:${password}@router:8080%2cnext`, 'http://example.com/?x=router:8080%2cnext'],
    [`user\uFF1A${password}@my-proxy:7890%3Bnext`, 'my-proxy:7890%3Bnext'],
    [`two user:${password}@my-proxy:7890; and user:other-secret@10.1:8080,next`, 'two my-proxy:7890; and 10.1:8080,next']
  );
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  assert.equal(redactPublic('Build v1:2@beta;next'), 'Build v1:2@beta;next');
  assert.equal(redactPublic(`user:${password}@internal;x`), `user:${password}@internal;x`);
  assert.equal(redactPublic(`user:${password}@my-proxy:7,x`), `user:${password}@my-proxy:7,x`);
  assert.equal(redactPublic(`user:${password}@my-proxy:789012;next`), `user:${password}@my-proxy:789012;next`);
  assert.equal(redactPublic(`user:${password}@my-proxy:%37%3Bx`), `user:${password}@my-proxy:%37%3Bx`);
  assert.equal(redactPublic('member@example.test,next'), 'member@example.test,next');
  assert.equal(redactPublic('note 100%3Boff sale'), 'note 100%3Boff sale');
  assert.equal(redactPublic('note 100%2Coff sale'), 'note 100%2Coff sale');
  assert.equal(redactPublic('score 1:2@10.5,x'), 'score 1:2@10.5,x');
  assert.equal(redactPublic('http://user@127.0.0.1:7890;x'), 'http://user@127.0.0.1:7890;x');
  assert.equal(redactPublic(`user:${password}@my-proxy:7890`), 'my-proxy:7890');
  const proxy = `http://user:${password}@127.0.0.1:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `list user:${password}@example.com, next`, email: 'a@example.test', last_error: `dial user:${password}@router:8080%3Bnext failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'list example.com, next');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial router:8080%3Bnext failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords before an exclamation mark', () => {
  const password = 's3cret-token';
  const marks = ['!', '\uFE15', '\uFE57', '\uFF01'];
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
    [`dial user:${password}@router:8080%21next`, 'dial router:8080%21next'],
    [`socks5://alice:hunter2@my-proxy:7890!tmp`, 'socks5://my-proxy:7890!tmp'],
    [`via user:${password} proxy@my-proxy:7890%21 failed`, 'via my-proxy:7890%21 failed'],
    [`user:${password}/token@my-proxy:7890!next`, 'my-proxy:7890!next'],
    [`//user:${password}@10.1:8080%21next`, '//10.1:8080%21next'],
    [`http://example.com/?x=user:${password}@router:8080%21next`, 'http://example.com/?x=router:8080%21next'],
    [`user\uFF1A${password}@my-proxy:7890!next`, 'my-proxy:7890!next'],
    [`two user:${password}@my-proxy:7890! and user:other-secret@10.1:8080%21next`, 'two my-proxy:7890! and 10.1:8080%21next']
  );
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  assert.equal(redactPublic('Build v1:2@beta!next'), 'Build v1:2@beta!next');
  assert.equal(redactPublic(`user:${password}@internal!x`), `user:${password}@internal!x`);
  assert.equal(redactPublic(`user:${password}@my-proxy:7!x`), `user:${password}@my-proxy:7!x`);
  assert.equal(redactPublic(`user:${password}@my-proxy:789012!next`), `user:${password}@my-proxy:789012!next`);
  assert.equal(redactPublic(`user:${password}@my-proxy:%37%21x`), `user:${password}@my-proxy:%37%21x`);
  assert.equal(redactPublic('member@example.test!next'), 'member@example.test!next');
  assert.equal(redactPublic('note 100%21off sale'), 'note 100%21off sale');
  assert.equal(redactPublic('score 1:2@10.5!x'), 'score 1:2@10.5!x');
  assert.equal(redactPublic('http://user@127.0.0.1:7890!x'), 'http://user@127.0.0.1:7890!x');
  assert.equal(redactPublic(`user:${password}@my-proxy:7890`), 'my-proxy:7890');
  const proxy = `http://user:${password}@127.0.0.1:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note user:${password}@my-proxy:7890!next`, email: 'a@example.test', last_error: `dial user:${password}@router:8080%21next failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my-proxy:7890!next');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial router:8080%21next failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords before an encoded path, query, or fragment', () => {
  const password = 's3cret-token';
  const marks = ['/', '?', '#', '\uFF0F', '\uFE16', '\uFE56', '\uFF1F', '\uFE5F', '\uFF03'];
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
    [`dial user:${password}@router:8080%2Fnext`, 'dial router:8080%2Fnext'],
    [`socks5://alice:hunter2@my-proxy:7890%3Ftmp`, 'socks5://my-proxy:7890%3Ftmp'],
    [`via user:${password} proxy@my-proxy:7890%23 failed`, 'via my-proxy:7890%23 failed'],
    [`user:${password}/token@my-proxy:7890%2Fnext`, 'my-proxy:7890%2Fnext'],
    [`//user:${password}@10.1:8080%3fnext`, '//10.1:8080%3fnext'],
    [`http://example.com/?x=user:${password}@router:8080%23next`, 'http://example.com/?x=router:8080%23next'],
    [`user\uFF1A${password}@my-proxy:7890\uFF0Fnext`, 'my-proxy:7890\uFF0Fnext'],
    [`two user:${password}@my-proxy:7890%2F and user:other-secret@10.1:8080%3Fnext`, 'two my-proxy:7890%2F and 10.1:8080%3Fnext']
  );
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  assert.equal(redactPublic('Build v1:2@beta%2Fnext'), 'Build v1:2@beta%2Fnext');
  assert.equal(redactPublic(`user:${password}@internal%2Fx`), `user:${password}@internal%2Fx`);
  assert.equal(redactPublic(`user:${password}@my-proxy:7%3Fx`), `user:${password}@my-proxy:7%3Fx`);
  assert.equal(redactPublic(`user:${password}@my-proxy:789012%23next`), `user:${password}@my-proxy:789012%23next`);
  assert.equal(redactPublic(`user:${password}@my-proxy:%37%2Fx`), `user:${password}@my-proxy:%37%2Fx`);
  assert.equal(redactPublic('member@example.test%2Fnext'), 'member@example.test%2Fnext');
  assert.equal(redactPublic('note 100%2Foff sale'), 'note 100%2Foff sale');
  assert.equal(redactPublic('note 100%3Foff sale'), 'note 100%3Foff sale');
  assert.equal(redactPublic('note 100%23off sale'), 'note 100%23off sale');
  assert.equal(redactPublic('score 1:2@10.5%2Fx'), 'score 1:2@10.5%2Fx');
  assert.equal(redactPublic('http://user@127.0.0.1:7890%2Fx'), 'http://user@127.0.0.1:7890%2Fx');
  assert.equal(redactPublic(`user:${password}@my-proxy:7890`), 'my-proxy:7890');
  const proxy = `http://user:${password}@127.0.0.1:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `path user:${password}@my-proxy:7890%2Ftmp`, email: 'a@example.test', last_error: `dial user:${password}@router:8080%3Fnext failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'path my-proxy:7890%2Ftmp');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial router:8080%3Fnext failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords before encoded whitespace', () => {
  const password = 's3cret-token';
  const marks = ['\u0009', '\u000A', '\u000B', '\u000C', '\u000D', '\u0020', '\u00A0', '\u1680', '\u2000', '\u2001', '\u2002', '\u2003', '\u2004', '\u2005', '\u2006', '\u2007', '\u2008', '\u2009', '\u200A', '\u2028', '\u2029', '\u202F', '\u205F', '\u3000', '\uFEFF'];
  const nest = (value, layers) => {
    let out = value;
    for (let layer = 0; layer < layers; layer += 1) out = out.replace(/%/g, '%25');
    return out;
  };
  const cases = [];
  for (const mark of marks) {
    const encoded = encodeURIComponent(mark);
    // U+FEFF is an invisible mark. A percent-encoded copy folds when a password is removed.
    const encodedShown = mark === '\uFEFF' ? mark : encoded;
    const encodedShownLower = mark === '\uFEFF' ? mark : encoded.toLowerCase();
    const encodedShownNested = mark === '\uFEFF' ? mark : nest(encoded, 3);
    cases.push([`user:${password}@my-proxy:7890${mark}next`, `my-proxy:7890${mark}next`]);
    cases.push([`note ${mark}user:${password}@10.1:8080${mark}`, `note ${mark}10.1:8080${mark}`]);
    cases.push([`user:${password}@example.com${mark}x`, `example.com${mark}x`]);
    cases.push([`user:${password}@router:8080${encoded}next`, `router:8080${encodedShown}next`]);
    cases.push([`user:${password}@router:8080${encoded.toLowerCase()}next`, `router:8080${encodedShownLower}next`]);
    cases.push([`user:${password}@2130706433:7890${nest(encoded, 3)}next`, `2130706433:7890${encodedShownNested}next`]);
  }
  cases.push(
    [`dial user:${password}@router:8080%20next`, 'dial router:8080%20next'],
    [`socks5://alice:hunter2@my-proxy:7890%09tmp`, 'socks5://my-proxy:7890%09tmp'],
    [`via user:${password} proxy@my-proxy:7890%0A failed`, 'via my-proxy:7890%0A failed'],
    [`user:${password}/token@my-proxy:7890%0Dnext`, 'my-proxy:7890%0Dnext'],
    [`//user:${password}@10.1:8080%20next`, '//10.1:8080%20next'],
    [`http://example.com/?x=user:${password}@router:8080%0anext`, 'http://example.com/?x=router:8080%0anext'],
    [`user\uFF1A${password}@my-proxy:7890%20next`, 'my-proxy:7890%20next'],
    [`two user:${password}@my-proxy:7890%20 and user:other-secret@10.1:8080%09next`, 'two my-proxy:7890%20 and 10.1:8080%09next']
  );
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  assert.equal(redactPublic('Build v1:2@beta%20next'), 'Build v1:2@beta%20next');
  assert.equal(redactPublic(`user:${password}@internal%20x`), `user:${password}@internal%20x`);
  assert.equal(redactPublic(`user:${password}@my-proxy:7%09x`), `user:${password}@my-proxy:7%09x`);
  assert.equal(redactPublic(`user:${password}@my-proxy:789012%0Anext`), `user:${password}@my-proxy:789012%0Anext`);
  assert.equal(redactPublic(`user:${password}@my-proxy:%37%20x`), `user:${password}@my-proxy:%37%20x`);
  assert.equal(redactPublic('member@example.test%20next'), 'member@example.test%20next');
  assert.equal(redactPublic('note 100%20off sale'), 'note 100%20off sale');
  assert.equal(redactPublic('note 100%0Aoff sale'), 'note 100%0Aoff sale');
  assert.equal(redactPublic('score 1:2@10.5%0Dx'), 'score 1:2@10.5%0Dx');
  assert.equal(redactPublic('http://user@127.0.0.1:7890%20x'), 'http://user@127.0.0.1:7890%20x');
  assert.equal(redactPublic(`user:${password}@my-proxy:7890`), 'my-proxy:7890');
  const proxy = `http://user:${password}@127.0.0.1:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note user:${password}@my-proxy:7890%20next`, email: 'a@example.test', last_error: `dial user:${password}@router:8080%09next failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my-proxy:7890%20next');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial router:8080%09next failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords before an encoded quote', () => {
  const password = 's3cret-token';
  const marks = ['"', "'", '\u2018', '\u2019', '\u201C', '\u201D', '\uFF02', '\uFF07'];
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
    [`dial user:${password}@router:8080%22next`, 'dial router:8080%22next'],
    [`socks5://alice:hunter2@my-proxy:7890%27tmp`, 'socks5://my-proxy:7890%27tmp'],
    [`via user:${password} proxy@my-proxy:7890%E2%80%9C failed`, 'via my-proxy:7890%E2%80%9C failed'],
    [`user:${password}/token@my-proxy:7890%22next`, 'my-proxy:7890%22next'],
    [`//user:${password}@10.1:8080%27next`, '//10.1:8080%27next'],
    [`http://example.com/?x=user:${password}@router:8080%22next`, 'http://example.com/?x=router:8080%22next'],
    [`user\uFF1A${password}@my-proxy:7890\uFF02next`, 'my-proxy:7890\uFF02next'],
    [`two user:${password}@my-proxy:7890%22 and user:other-secret@10.1:8080%27next`, 'two my-proxy:7890%22 and 10.1:8080%27next']
  );
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  assert.equal(redactPublic('Build v1:2@beta%22next'), 'Build v1:2@beta%22next');
  assert.equal(redactPublic(`user:${password}@internal%22x`), `user:${password}@internal%22x`);
  assert.equal(redactPublic(`user:${password}@my-proxy:7%27x`), `user:${password}@my-proxy:7%27x`);
  assert.equal(redactPublic(`user:${password}@my-proxy:789012%22next`), `user:${password}@my-proxy:789012%22next`);
  assert.equal(redactPublic(`user:${password}@my-proxy:%37%22x`), `user:${password}@my-proxy:%37%22x`);
  assert.equal(redactPublic('member@example.test%22next'), 'member@example.test%22next');
  assert.equal(redactPublic('note 100%22off sale'), 'note 100%22off sale');
  assert.equal(redactPublic('note 100%27off sale'), 'note 100%27off sale');
  assert.equal(redactPublic('score 1:2@10.5%22x'), 'score 1:2@10.5%22x');
  assert.equal(redactPublic('http://user@127.0.0.1:7890%22x'), 'http://user@127.0.0.1:7890%22x');
  assert.equal(redactPublic(`user:${password}@my-proxy:7890`), 'my-proxy:7890');
  const proxy = `http://user:${password}@127.0.0.1:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note user:${password}@my-proxy:7890%22next`, email: 'a@example.test', last_error: `dial user:${password}@router:8080%27next failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my-proxy:7890%22next');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial router:8080%27next failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords before an encoded backtick, pipe, or backslash', () => {
  const password = 's3cret-token';
  const marks = ['`', '|', '\\', '\uFF40', '\uFF5C', '\uFF3C', '\u1FEF', '\uFE68'];
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
    [`dial user:${password}@router:8080%60next`, 'dial router:8080%60next'],
    [`socks5://alice:hunter2@my-proxy:7890%7Ctmp`, 'socks5://my-proxy:7890%7Ctmp'],
    [`via user:${password} proxy@my-proxy:7890%5C failed`, 'via my-proxy:7890%5C failed'],
    [`user:${password}/token@my-proxy:7890%60next`, 'my-proxy:7890%60next'],
    [`//user:${password}@10.1:8080%7cnext`, '//10.1:8080%7cnext'],
    [`http://example.com/?x=user:${password}@router:8080%5cnext`, 'http://example.com/?x=router:8080%5cnext'],
    [`user\uFF1A${password}@my-proxy:7890\uFE68next`, 'my-proxy:7890\uFE68next'],
    [`two user:${password}@my-proxy:7890%60 and user:other-secret@10.1:8080%7Cnext`, 'two my-proxy:7890%60 and 10.1:8080%7Cnext']
  );
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  assert.equal(redactPublic('Build v1:2@beta%60next'), 'Build v1:2@beta%60next');
  assert.equal(redactPublic(`user:${password}@internal%7Cx`), `user:${password}@internal%7Cx`);
  assert.equal(redactPublic(`user:${password}@my-proxy:7%5Cx`), `user:${password}@my-proxy:7%5Cx`);
  assert.equal(redactPublic(`user:${password}@my-proxy:789012%60next`), `user:${password}@my-proxy:789012%60next`);
  assert.equal(redactPublic(`user:${password}@my-proxy:%37%7Cx`), `user:${password}@my-proxy:%37%7Cx`);
  assert.equal(redactPublic('member@example.test%5Cnext'), 'member@example.test%5Cnext');
  assert.equal(redactPublic('note 100%60off sale'), 'note 100%60off sale');
  assert.equal(redactPublic('note 100%7Coff sale'), 'note 100%7Coff sale');
  assert.equal(redactPublic('note 100%5Coff sale'), 'note 100%5Coff sale');
  assert.equal(redactPublic('score 1:2@10.5%60x'), 'score 1:2@10.5%60x');
  assert.equal(redactPublic('http://user@127.0.0.1:7890%60x'), 'http://user@127.0.0.1:7890%60x');
  assert.equal(redactPublic(`user:${password}@my-proxy:7890`), 'my-proxy:7890');
  const proxy = `http://user:${password}@127.0.0.1:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note user:${password}@my-proxy:7890%60next`, email: 'a@example.test', last_error: `dial user:${password}@router:8080%5Cnext failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my-proxy:7890%60next');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial router:8080%5Cnext failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords before an encoded control', () => {
  const password = 's3cret-token';
  const marks = [];
  for (let cp = 0; cp <= 0x1F; cp += 1) {
    if (cp >= 0x09 && cp <= 0x0D) continue;
    marks.push(String.fromCodePoint(cp));
  }
  marks.push('\u007F');
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
    [`dial user:${password}@router:8080%00next`, 'dial router:8080%00next'],
    [`socks5://alice:hunter2@my-proxy:7890%7Ftmp`, 'socks5://my-proxy:7890%7Ftmp'],
    [`via user:${password} proxy@my-proxy:7890%08 failed`, 'via my-proxy:7890%08 failed'],
    [`user:${password}/token@my-proxy:7890%00next`, 'my-proxy:7890%00next'],
    [`//user:${password}@10.1:8080%1bnext`, '//10.1:8080%1bnext'],
    [`http://example.com/?x=user:${password}@router:8080%0Enext`, 'http://example.com/?x=router:8080%0Enext'],
    [`user\uFF1A${password}@my-proxy:7890\u0000next`, 'my-proxy:7890\u0000next'],
    [`two user:${password}@my-proxy:7890%00 and user:other-secret@10.1:8080%7Fnext`, 'two my-proxy:7890%00 and 10.1:8080%7Fnext']
  );
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  assert.equal(redactPublic('Build v1:2@beta%00next'), 'Build v1:2@beta%00next');
  assert.equal(redactPublic(`user:${password}@internal%00x`), `user:${password}@internal%00x`);
  assert.equal(redactPublic(`user:${password}@my-proxy:7%00x`), `user:${password}@my-proxy:7%00x`);
  assert.equal(redactPublic(`user:${password}@my-proxy:789012%7Fnext`), `user:${password}@my-proxy:789012%7Fnext`);
  assert.equal(redactPublic(`user:${password}@my-proxy:%37%00x`), `user:${password}@my-proxy:%37%00x`);
  assert.equal(redactPublic('member@example.test%00next'), 'member@example.test%00next');
  assert.equal(redactPublic('note 100%00off sale'), 'note 100%00off sale');
  assert.equal(redactPublic('note 100%7Foff sale'), 'note 100%7Foff sale');
  assert.equal(redactPublic('note 100%1Boff sale'), 'note 100%1Boff sale');
  assert.equal(redactPublic('score 1:2@10.5%00x'), 'score 1:2@10.5%00x');
  assert.equal(redactPublic('http://user@127.0.0.1:7890%00x'), 'http://user@127.0.0.1:7890%00x');
  assert.equal(redactPublic(`user:${password}@my-proxy:7890`), 'my-proxy:7890');
  const proxy = `http://user:${password}@127.0.0.1:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note user:${password}@my-proxy:7890%00next`, email: 'a@example.test', last_error: `dial user:${password}@router:8080%7Fnext failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my-proxy:7890%00next');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial router:8080%7Fnext failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords before an encoded period', () => {
  const password = 's3cret-token';
  const marks = ['.', '\uFF0E', '\uFE52', '\u2024', '\u3002', '\uFE12', '\uFF61'];
  const nest = (value, layers) => {
    let out = value;
    for (let layer = 0; layer < layers; layer += 1) out = out.replace(/%/g, '%25');
    return out;
  };
  const cases = [];
  for (const mark of marks) {
    const encoded = mark === '.' ? '%2E' : encodeURIComponent(mark);
    cases.push([`user:${password}@my-proxy:7890${mark}next`, `my-proxy:7890${mark}next`]);
    if (mark !== '.') cases.push([`note ${mark}user:${password}@10.1:8080${mark}`, `note ${mark}10.1:8080${mark}`]);
    cases.push([`user:${password}@example.com${mark}x`, `example.com${mark}x`]);
    cases.push([`user:${password}@router:8080${encoded}next`, `router:8080${encoded}next`]);
    cases.push([`user:${password}@router:8080${encoded.toLowerCase()}next`, `router:8080${encoded.toLowerCase()}next`]);
    cases.push([`user:${password}@2130706433:7890${nest(encoded, 3)}next`, `2130706433:7890${nest(encoded, 3)}next`]);
  }
  cases.push(
    [`dial user:${password}@router:8080%2Enext`, 'dial router:8080%2Enext'],
    [`socks5://alice:hunter2@my-proxy:7890%E3%80%82tmp`, 'socks5://my-proxy:7890%E3%80%82tmp'],
    [`via user:${password} proxy@my-proxy:7890%2e failed`, 'via my-proxy:7890%2e failed'],
    [`user:${password}/token@my-proxy:7890%2Enext`, 'my-proxy:7890%2Enext'],
    [`//user:${password}@10.1:8080%2enext`, '//10.1:8080%2enext'],
    [`http://example.com/?x=user:${password}@router:8080%2Enext`, 'http://example.com/?x=router:8080%2Enext'],
    [`user\uFF1A${password}@my-proxy:7890\uFF0Enext`, 'my-proxy:7890\uFF0Enext'],
    [`user:${password}@127%2E0%2E0%2E1:7890`, '127%2E0%2E0%2E1:7890'],
    [`user.name:${password}@my-proxy:7890`, 'my-proxy:7890'],
    [`two user:${password}@my-proxy:7890%2E and user:other-secret@10.1:8080\u3002next`, 'two my-proxy:7890%2E and 10.1:8080\u3002next']
  );
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  assert.equal(redactPublic(`user:${password}@internal%2Ex`), `user:${password}@internal%2Ex`);
  assert.equal(redactPublic(`user:${password}@my-proxy:7%2Ex`), `user:${password}@my-proxy:7%2Ex`);
  assert.equal(redactPublic(`user:${password}@my-proxy:789012%2Enext`), `user:${password}@my-proxy:789012%2Enext`);
  assert.equal(redactPublic(`user:${password}@my-proxy:%37%2Ex`), `user:${password}@my-proxy:%37%2Ex`);
  assert.equal(redactPublic('member@example.test%2Enext'), 'member@example.test%2Enext');
  assert.equal(redactPublic('note 100%2Eoff sale'), 'note 100%2Eoff sale');
  assert.equal(redactPublic('note 100%E3%80%82off sale'), 'note 100%E3%80%82off sale');
  assert.equal(redactPublic('score 1:2@10.5%2Ex'), 'score 1:2@10.5%2Ex');
  assert.equal(redactPublic('http://user@127.0.0.1:7890%2Ex'), 'http://user@127.0.0.1:7890%2Ex');
  assert.equal(redactPublic(`user:${password}@my-proxy:7890`), 'my-proxy:7890');
  const proxy = `http://user:${password}@127.0.0.1:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note user:${password}@my-proxy:7890%2Enext`, email: 'a@example.test', last_error: `dial user:${password}@router:8080\u3002next failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my-proxy:7890%2Enext');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial router:8080\u3002next failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords before an encoded colon after the port', () => {
  const password = 's3cret-token';
  const marks = ['\uFE13', '\uFE55', '\uFF1A', '\u2236', '\u02D0', '\uA789', '\u02F8', '\u0703', '\u0704', '\u0589'];
  const nest = (value, layers) => {
    let out = value;
    for (let layer = 0; layer < layers; layer += 1) out = out.replace(/%/g, '%25');
    return out;
  };
  const cases = [];
  cases.push([`user:${password}@my-proxy:7890:next`, 'my-proxy:7890:next']);
  cases.push([`user:${password}@router:8080%3Anext`, 'router:8080%3Anext']);
  cases.push([`user:${password}@router:8080%3anext`, 'router:8080%3anext']);
  cases.push([`user:${password}@2130706433:7890${nest('%3A', 3)}next`, `2130706433:7890${nest('%3A', 3)}next`]);
  for (const mark of marks) {
    const encoded = encodeURIComponent(mark);
    cases.push([`user:${password}@my-proxy:7890${mark}next`, `my-proxy:7890${mark}next`]);
    cases.push([`user:${password}@example.com${mark}x`, `example.com${mark}x`]);
    cases.push([`user:${password}@router:8080${encoded}next`, `router:8080${encoded}next`]);
    cases.push([`user:${password}@router:8080${encoded.toLowerCase()}next`, `router:8080${encoded.toLowerCase()}next`]);
    cases.push([`user:${password}@2130706433:7890${nest(encoded, 3)}next`, `2130706433:7890${nest(encoded, 3)}next`]);
  }
  cases.push(
    [`dial user:${password}@router:8080%3Anext`, 'dial router:8080%3Anext'],
    [`socks5://alice:hunter2@my-proxy:7890%3Atmp`, 'socks5://my-proxy:7890%3Atmp'],
    [`via user:${password} proxy@my-proxy:7890\uFF1A failed`, 'via my-proxy:7890\uFF1A failed'],
    [`user:${password}/token@my-proxy:7890%3Anext`, 'my-proxy:7890%3Anext'],
    [`//user:${password}@10.1:8080%3anext`, '//10.1:8080%3anext'],
    [`http://example.com/?x=user:${password}@router:8080%3Anext`, 'http://example.com/?x=router:8080%3Anext'],
    [`user:${password}@my-proxy%3A7890`, 'my-proxy%3A7890'],
    [`user.name:${password}@my-proxy:7890`, 'my-proxy:7890'],
    [`two user:${password}@my-proxy:7890%3A and user:other-secret@10.1:8080\uFF1Anext`, 'two my-proxy:7890%3A and 10.1:8080\uFF1Anext']
  );
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  assert.equal(redactPublic('Build v1:2@beta%3Anext'), 'Build v1:2@beta%3Anext');
  assert.equal(redactPublic(`user:${password}@internal%3Ax`), `user:${password}@internal%3Ax`);
  assert.equal(redactPublic(`user:${password}@my-proxy:7%3Ax`), `user:${password}@my-proxy:7%3Ax`);
  assert.equal(redactPublic(`user:${password}@my-proxy:789012%3Anext`), `user:${password}@my-proxy:789012%3Anext`);
  assert.equal(redactPublic(`user:${password}@my-proxy:%37%3Ax`), `user:${password}@my-proxy:%37%3Ax`);
  assert.equal(redactPublic('member@example.test%3Anext'), 'member@example.test%3Anext');
  assert.equal(redactPublic('note 100%3Aoff sale'), 'note 100%3Aoff sale');
  assert.equal(redactPublic('score 1:2@10.5%3Ax'), 'score 1:2@10.5%3Ax');
  assert.equal(redactPublic('http://user@127.0.0.1:7890%3Ax'), 'http://user@127.0.0.1:7890%3Ax');
  assert.equal(redactPublic(`user:${password}@my-proxy:7890`), 'my-proxy:7890');
  const proxy = `http://user:${password}@127.0.0.1:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note user:${password}@my-proxy:7890%3Anext`, email: 'a@example.test', last_error: `dial user:${password}@router:8080\uFF1Anext failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my-proxy:7890%3Anext');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial router:8080\uFF1Anext failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords before a middle dot', () => {
  const password = 's3cret-token';
  const marks = ['\u00B7', '\u0387', '\u1427', '\u2027', '\u2219', '\u22C5', '\u2E31', '\u30FB', '\uFF65'];
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
    [`dial user:${password}@router:8080%C2%B7next`, 'dial router:8080%C2%B7next'],
    [`socks5://alice:hunter2@my-proxy:7890%E3%83%BBtmp`, 'socks5://my-proxy:7890%E3%83%BBtmp'],
    [`via user:${password} proxy@my-proxy:7890\u00B7 failed`, 'via my-proxy:7890\u00B7 failed'],
    [`user:${password}/token@my-proxy:7890%C2%B7next`, 'my-proxy:7890%C2%B7next'],
    [`//user:${password}@10.1:8080%c2%b7next`, '//10.1:8080%c2%b7next'],
    [`http://example.com/?x=user:${password}@router:8080%C2%B7next`, 'http://example.com/?x=router:8080%C2%B7next'],
    [`us\u00B7er:${password}@my-proxy:7890`, 'us\u00B7my-proxy:7890'],
    [`user:sec\u00B7ret@my-proxy:7890`, 'my-proxy:7890'],
    [`two user:${password}@my-proxy:7890%C2%B7 and user:other-secret@10.1:8080\u30FBnext`, 'two my-proxy:7890%C2%B7 and 10.1:8080\u30FBnext']
  );
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  assert.equal(redactPublic('Build v1:2@beta\u00B7x'), 'Build v1:2@beta\u00B7x');
  assert.equal(redactPublic(`user:${password}@internal\u00B7x`), `user:${password}@internal\u00B7x`);
  assert.equal(redactPublic(`user:${password}@my-proxy:7\u00B7x`), `user:${password}@my-proxy:7\u00B7x`);
  assert.equal(redactPublic(`user:${password}@my-proxy:789012\u00B7next`), `user:${password}@my-proxy:789012\u00B7next`);
  assert.equal(redactPublic(`user:${password}@my-proxy:%37\u00B7x`), `user:${password}@my-proxy:%37\u00B7x`);
  assert.equal(redactPublic('member@example.test\u00B7next'), 'member@example.test\u00B7next');
  assert.equal(redactPublic('note 100%C2%B7off sale'), 'note 100%C2%B7off sale');
  assert.equal(redactPublic('note 100%E3%83%BBoff sale'), 'note 100%E3%83%BBoff sale');
  assert.equal(redactPublic('score 1:2@10.5\u00B7x'), 'score 1:2@10.5\u00B7x');
  assert.equal(redactPublic('http://user@127.0.0.1:7890\u00B7x'), 'http://user@127.0.0.1:7890\u00B7x');
  assert.equal(redactPublic(`user:${password}@my-proxy:7890`), 'my-proxy:7890');
  const proxy = `http://user:${password}@127.0.0.1:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note user:${password}@my-proxy:7890%C2%B7next`, email: 'a@example.test', last_error: `dial user:${password}@router:8080\u30FBnext failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my-proxy:7890%C2%B7next');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial router:8080\u30FBnext failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords when a middle dot splits the host', () => {
  const password = 's3cret-token';
  const marks = ['\u00B7', '\u0387', '\u1427', '\u2027', '\u2219', '\u22C5', '\u2E31', '\u30FB', '\uFF65'];
  const nest = (value, layers) => {
    let out = value;
    for (let layer = 0; layer < layers; layer += 1) out = out.replace(/%/g, '%25');
    return out;
  };
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
  cases.push(
    [`user:${password}@127%C2%B70%C2%B70%C2%B71:7890`, '127%C2%B70%C2%B70%C2%B71:7890'],
    [`user:${password}@127%c2%b70%c2%b70%c2%b71:7890`, '127%c2%b70%c2%b70%c2%b71:7890'],
    [`user:${password}@10\u00B71:8080`, '10\u00B71:8080'],
    [`user:${password}@127.0\u00B70.1:7890`, '127.0\u00B70.1:7890'],
    [`via user:${password} proxy@127\u00B70\u00B70\u00B71:7890 failed`, 'via 127\u00B70\u00B70\u00B71:7890 failed'],
    [`http://example.com/?x=user:${password}@10\u30FB0\u30FB0\u30FB8:1080`, 'http://example.com/?x=10\u30FB0\u30FB0\u30FB8:1080'],
    [`user:${password}/token@example\u00B7com`, 'example\u00B7com'],
    [`socks5://alice:hunter2@10\u00B70\u00B70\u00B78:1080`, 'socks5://10\u00B70\u00B70\u00B78:1080'],
    [`two user:${password}@127\u00B70\u00B70\u00B71:7890) and user:other-secret@my\u30FBproxy:7890.`, 'two 127\u00B70\u00B70\u00B71:7890) and my\u30FBproxy:7890.']
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
  assert.equal(redactPublic(`user:${password}@internal`), `user:${password}@internal`);
  assert.equal(redactPublic(`user:${password}@internal\u00B7`), `user:${password}@internal\u00B7`);
  assert.equal(redactPublic(`user:${password}@10\u00B71`), `user:${password}@10\u00B71`);
  assert.equal(redactPublic('score 1:2@10\u00B75'), 'score 1:2@10\u00B75');
  assert.equal(redactPublic('ratio:1@v1\u00B72'), 'ratio:1@v1\u00B72');
  assert.equal(redactPublic('member@example\u00B7test'), 'member@example\u00B7test');
  assert.equal(redactPublic('note 100%C2%B70 sale'), 'note 100%C2%B70 sale');
  assert.equal(redactPublic('http://user@127\u00B70\u00B70\u00B71:7890'), 'http://user@127\u00B70\u00B70\u00B71:7890');
  const proxy = `http://user:${password}@127.0.0.1:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note user:${password}@my\u00B7proxy:7890`, email: 'a@example.test', last_error: `dial user:${password}@127\u00B70\u00B70\u00B71:7890 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my\u00B7proxy:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial 127\u00B70\u00B70\u00B71:7890 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by a bullet or another stop', () => {
  const password = 's3cret-token';
  const marks = ['\u2022', '\u2023', '\u2043', '\u204C', '\u204D', '\u25E6', '\u29BF', '\u0964', '\u0965', '\u06D4', '\u0701', '\u0702', '\u2025', '\uFE30', '\u3002', '\uFE12', '\uFF61'];
  const nest = (value, layers) => {
    let out = value;
    for (let layer = 0; layer < layers; layer += 1) out = out.replace(/%/g, '%25');
    return out;
  };
  const cases = [];
  for (const mark of marks) {
    const encoded = encodeURIComponent(mark);
    cases.push([`user:${password}@my-proxy:7890${mark}next`, `my-proxy:7890${mark}next`]);
    cases.push([`user:${password}@127${mark}0${mark}0${mark}1:7890`, `127${mark}0${mark}0${mark}1:7890`]);
    cases.push([`user:${password}@example${mark}com`, `example${mark}com`]);
    cases.push([`user:${password}@router:8080${encoded}next`, `router:8080${encoded}next`]);
    cases.push([`user:${password}@10${encoded.toLowerCase()}0${encoded.toLowerCase()}0${encoded.toLowerCase()}8:1080`, `10${encoded.toLowerCase()}0${encoded.toLowerCase()}0${encoded.toLowerCase()}8:1080`]);
    cases.push([`user:${password}@2130706433:7890${nest(encoded, 3)}next`, `2130706433:7890${nest(encoded, 3)}next`]);
  }
  cases.push(
    [`dial user:${password}@router:8080%E2%80%A2next`, 'dial router:8080%E2%80%A2next'],
    [`socks5://alice:hunter2@my-proxy:7890\u2025tmp`, 'socks5://my-proxy:7890\u2025tmp'],
    [`via user:${password} proxy@127\u30020\u30020\u30021:7890 failed`, 'via 127\u30020\u30020\u30021:7890 failed'],
    [`user:${password}/token@my-proxy:7890\u0964next`, 'my-proxy:7890\u0964next'],
    [`//user:${password}@10.1:8080\uFE30next`, '//10.1:8080\uFE30next'],
    [`http://example.com/?x=user:${password}@10\u06D40\u06D40\u06D48:1080`, 'http://example.com/?x=10\u06D40\u06D40\u06D48:1080'],
    [`us\u2022er:${password}@my-proxy:7890`, 'us\u2022my-proxy:7890'],
    [`user:sec\u2022ret@my-proxy:7890`, 'my-proxy:7890'],
    [`two user:${password}@my-proxy:7890\u2022 and user:other-secret@10.1:8080\u0965next`, 'two my-proxy:7890\u2022 and 10.1:8080\u0965next']
  );
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  assert.equal(redactPublic('Build v1:2@beta\u2022x'), 'Build v1:2@beta\u2022x');
  assert.equal(redactPublic(`user:${password}@internal\u2022x`), `user:${password}@internal\u2022x`);
  assert.equal(redactPublic(`user:${password}@internal\u3002`), `user:${password}@internal\u3002`);
  assert.equal(redactPublic(`user:${password}@10\u20221`), `user:${password}@10\u20221`);
  assert.equal(redactPublic(`user:${password}@10\u30021`), `user:${password}@10\u30021`);
  assert.equal(redactPublic('score 1:2@10\u20225'), 'score 1:2@10\u20225');
  assert.equal(redactPublic('ratio:1@v1\u06D42'), 'ratio:1@v1\u06D42');
  assert.equal(redactPublic(`user:${password}@my-proxy:7\u2022x`), `user:${password}@my-proxy:7\u2022x`);
  assert.equal(redactPublic(`user:${password}@my-proxy:789012\u2022next`), `user:${password}@my-proxy:789012\u2022next`);
  assert.equal(redactPublic(`user:${password}@my-proxy:%37\u0964x`), `user:${password}@my-proxy:%37\u0964x`);
  assert.equal(redactPublic('member@example\u2022test'), 'member@example\u2022test');
  assert.equal(redactPublic('member@example.test\u3002next'), 'member@example.test\u3002next');
  assert.equal(redactPublic('note 100%E2%80%A2off sale'), 'note 100%E2%80%A2off sale');
  assert.equal(redactPublic('note 100%E3%80%82off sale'), 'note 100%E3%80%82off sale');
  assert.equal(redactPublic('http://user@127.0.0.1:7890\u2022x'), 'http://user@127.0.0.1:7890\u2022x');
  assert.equal(redactPublic(`user:${password}@my-proxy:7890`), 'my-proxy:7890');
  const proxy = `http://user:${password}@127.0.0.1:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note user:${password}@127\u20220\u20220\u20221:7890`, email: 'a@example.test', last_error: `dial user:${password}@router:8080\u0964next failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note 127\u20220\u20220\u20221:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial router:8080\u0964next failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords when fullwidth digits are encoded', () => {
  const password = 's3cret-token';
  const fwText = value => value.replace(/[0-9]/g, digit => String.fromCodePoint(0xFF10 + Number(digit)));
  const encDigits = text => text.split('').map(digit => encodeURIComponent(String.fromCodePoint(0xFF10 + Number(digit)))).join('');
  const nest = text => text.replace(/%/g, '%25');
  const port = encDigits('7890');
  const portLower = port.toLowerCase();
  const nestedPort = nest(port);
  const quadPort = nest(nest(nestedPort));
  const host = [encDigits('127'), encDigits('0'), encDigits('0'), encDigits('1')].join('.');
  const hostDots = [encDigits('127'), encDigits('0'), encDigits('0'), encDigits('1')].join('%2E');
  const shortHost = [encDigits('10'), encDigits('1')].join('%2e');
  const decimal = encDigits('2130706433');
  const mixed = `12${encDigits('7')}.0.0.1`;
  const cases = [
    [`user:${password}@my-proxy:${port}`, `my-proxy:${port}`],
    [`user:${password}@my-proxy:${portLower}`, `my-proxy:${portLower}`],
    [`(user:${password}@my-proxy:${nestedPort})`, `(my-proxy:${nestedPort})`],
    [`user:${password}@my-proxy:${quadPort}`, `my-proxy:${quadPort}`],
    [`user:${password}@${host}:7890`, `${host}:7890`],
    [`user:${password}@${hostDots}:${port}`, `${hostDots}:${port}`],
    [`user:${password}@${shortHost}:${encDigits('8080')}`, `${shortHost}:${encDigits('8080')}`],
    [`user:${password}@${decimal}:${port}`, `${decimal}:${port}`],
    [`user:${password}@${mixed}:7890`, `${mixed}:7890`],
    [`user:${password}@my-proxy%3A${port}`, `my-proxy%3A${port}`],
    [`user:${password}@10.1%3a${portLower}`, `10.1%3a${portLower}`],
    [`via user:${password} proxy@my-proxy:${port} failed`, `via my-proxy:${port} failed`],
    [`http://example.com/?x=user:${password}@my-proxy:${port}`, `http://example.com/?x=my-proxy:${port}`],
    [`http://user:${password}@${host}:${port}/x`, `http://${host}:${port}/x`],
    [`socks5://alice:hunter2@${shortHost}:${encDigits('8080')}`, `socks5://${shortHost}:${encDigits('8080')}`],
    [`user:${password}/token@my-proxy:${port}`, `my-proxy:${port}`],
    [`user\uFF1A${password}@${host}:7890`, `${host}:7890`],
    [`//user:${password}@${hostDots}:${port}`, `//${hostDots}:${port}`],
    [`two user:${password}@my-proxy:${port}) and user:other-secret@10.1:${fwText('8080')}.`, `two my-proxy:${port}) and 10.1:${fwText('8080')}.`],
    [`invalid proxy url "http://user:s3cret/token@my-proxy:${port}": invalid port ":s3cret" after host`, `invalid proxy url "http://my-proxy:${port}": invalid port ":[凭据已隐藏]" after host`]
  ];
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  assert.equal(redactPublic(`user:${password}@my-proxy:${encDigits('7')}`), `user:${password}@my-proxy:${encDigits('7')}`);
  assert.equal(redactPublic(`user:${password}@${encDigits('10')}:${encDigits('8')}`), `user:${password}@${encDigits('10')}:${encDigits('8')}`);
  assert.equal(redactPublic(`user:${password}@my-proxy:${encDigits('789012')}`), `user:${password}@my-proxy:${encDigits('789012')}`);
  assert.equal(redactPublic(`user:${password}@${encDigits('127')}`), `user:${password}@${encDigits('127')}`);
  assert.equal(redactPublic(`user:${password}@${encDigits('21307064331')}:7890`), `user:${password}@${encDigits('21307064331')}:7890`);
  assert.equal(redactPublic('Build v1:2@beta'), 'Build v1:2@beta');
  assert.equal(redactPublic(`user:${password}@internal`), `user:${password}@internal`);
  assert.equal(redactPublic('score 1:2@10.5'), 'score 1:2@10.5');
  assert.equal(redactPublic('member@example.test'), 'member@example.test');
  assert.equal(redactPublic(`note 100${encDigits('7')} off`), `note 100${encDigits('7')} off`);
  assert.equal(redactPublic(`http://user@my-proxy:${port}`), `http://user@my-proxy:${port}`);
  assert.equal(redactPublic(`user:${password}@127.0.0.1:7890`), '127.0.0.1:7890');
  const proxy = `http://user:${password}@127.0.0.1:${port}`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: true, usage_probe: false },
    accounts: [{ id: 'acc-1', name: `note user:${password}@${host}:7890`, email: 'a@example.test', last_error: `dial user:${password}@my-proxy:${port} failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, `note ${host}:7890`);
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, `dial my-proxy:${port} failed`);
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords when superscript or subscript digits hide the host', () => {
  const password = 's3cret-token';
  const superDigit = { 0: '\u2070', 1: '\u00B9', 2: '\u00B2', 3: '\u00B3', 4: '\u2074', 5: '\u2075', 6: '\u2076', 7: '\u2077', 8: '\u2078', 9: '\u2079' };
  const subDigit = digit => String.fromCodePoint(0x2080 + Number(digit));
  const mapDigits = (text, digit) => text.split('').map(item => (typeof digit === 'function' ? digit(item) : digit[item])).join('');
  const encDigits = (text, digit) => mapDigits(text, digit).split('').map(char => encodeURIComponent(char)).join('');
  const nest = text => text.replace(/%/g, '%25');
  const superPort = mapDigits('7890', superDigit);
  const subPort = mapDigits('8080', subDigit);
  const encSubPort = encDigits('8080', subDigit);
  const encSuperHost = [encDigits('127', superDigit), encDigits('0', superDigit), encDigits('0', superDigit), encDigits('1', superDigit)].join('%2E');
  const literalHost = [mapDigits('127', superDigit), mapDigits('0', superDigit), mapDigits('0', superDigit), mapDigits('1', superDigit)].join('.');
  const cases = [
    [`user:${password}@my-proxy:${superPort}`, `my-proxy:${superPort}`],
    [`(user:${password}@router:${subPort})`, `(router:${subPort})`],
    [`user:${password}@10.1:${encSubPort}`, `10.1:${encSubPort}`],
    [`user:${password}@10.1:${nest(encSubPort)}`, `10.1:${nest(encSubPort)}`],
    [`user:${password}@my-proxy:${encSubPort.toLowerCase()}`, `my-proxy:${encSubPort.toLowerCase()}`],
    [`user:${password}@${literalHost}:7890`, `${literalHost}:7890`],
    [`user:${password}@${encSuperHost}:${superPort}`, `${encSuperHost}:${superPort}`],
    [`user:${password}@my-proxy%3A${superPort}`, `my-proxy%3A${superPort}`],
    [`via user:${password} proxy@router:${subPort} failed`, `via router:${subPort} failed`],
    [`http://example.com/?x=user:${password}@my-proxy:${superPort}`, `http://example.com/?x=my-proxy:${superPort}`],
    [`http://user:${password}@${literalHost}:${subPort}/x`, `http://${literalHost}:${subPort}/x`],
    [`socks5://alice:hunter2@10.1:${encSubPort}`, `socks5://10.1:${encSubPort}`],
    [`user:${password}/token@my-proxy:${superPort}`, `my-proxy:${superPort}`],
    [`user\uFF1A${password}@router:${subPort}`, `router:${subPort}`],
    [`//user:${password}@${encSuperHost}:7890`, `//${encSuperHost}:7890`],
    [`two user:${password}@my-proxy:${superPort}) and user:other-secret@10.1:${subPort}.`, `two my-proxy:${superPort}) and 10.1:${subPort}.`],
    [`invalid proxy url "http://user:s3cret/token@my-proxy:${superPort}": invalid port ":s3cret" after host`, `invalid proxy url "http://my-proxy:${superPort}": invalid port ":[凭据已隐藏]" after host`]
  ];
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  assert.equal(redactPublic(`user:${password}@my-proxy:${superDigit[7]}`), `user:${password}@my-proxy:${superDigit[7]}`);
  assert.equal(redactPublic(`user:${password}@10.1:${subDigit(8)}`), `user:${password}@10.1:${subDigit(8)}`);
  assert.equal(redactPublic(`user:${password}@my-proxy:${mapDigits('789012', superDigit)}`), `user:${password}@my-proxy:${mapDigits('789012', superDigit)}`);
  assert.equal(redactPublic(`user:${password}@${mapDigits('127', superDigit)}`), `user:${password}@${mapDigits('127', superDigit)}`);
  assert.equal(redactPublic('Build v1:2@beta'), 'Build v1:2@beta');
  assert.equal(redactPublic(`user:${password}@internal`), `user:${password}@internal`);
  assert.equal(redactPublic('score 1:2@10.5'), 'score 1:2@10.5');
  assert.equal(redactPublic('member@example.test'), 'member@example.test');
  assert.equal(redactPublic(`note 100${encodeURIComponent(superDigit[2])} off`), `note 100${encodeURIComponent(superDigit[2])} off`);
  assert.equal(redactPublic(`http://user@my-proxy:${superPort}`), `http://user@my-proxy:${superPort}`);
  assert.equal(redactPublic(`user:${password}@127.0.0.1:7890`), '127.0.0.1:7890');
  const proxy = `http://user:${password}@127.0.0.1:${superPort}`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note user:${password}@${literalHost}:7890`, email: 'a@example.test', last_error: `dial user:${password}@router:${subPort} failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, `note ${literalHost}:7890`);
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, `dial router:${subPort} failed`);
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by Mongolian full stops', () => {
  const password = 's3cret-token';
  const marks = ['\u1803', '\u1809'];
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
    cases.push([`user:${password}@my-proxy${mark}7890`, `my-proxy${mark}7890`]);
    cases.push([`user:${password}@my-proxy${encoded}7890`, `my-proxy${encoded}7890`]);
    cases.push([`user:${password}@my-proxy${nest(encoded, 3)}7890`, `my-proxy${nest(encoded, 3)}7890`]);
    cases.push([`user:${password}@127${mark}0${mark}0${mark}1:7890`, `127${mark}0${mark}0${mark}1:7890`]);
    cases.push([`user:${password}@10${encoded.toLowerCase()}0${encoded.toLowerCase()}0${encoded.toLowerCase()}8:1080`, `10${encoded.toLowerCase()}0${encoded.toLowerCase()}0${encoded.toLowerCase()}8:1080`]);
    cases.push([`user:${password}@example${mark}com`, `example${mark}com`]);
    cases.push([`user:${password}@my-proxy:7890${mark}next`, `my-proxy:7890${mark}next`]);
  }
  cases.push(
    [`dial user%E1%A0%83${password}@router:8080%E1%A0%89next`, 'dial router:8080%E1%A0%89next'],
    [`socks5://alice\u1809hunter2@my-proxy:7890`, 'socks5://my-proxy:7890'],
    [`via user\u1803${password} proxy@127\u18030\u18030\u18031:7890 failed`, 'via 127\u18030\u18030\u18031:7890 failed'],
    [`user:${password}/token@my-proxy\u18097890`, 'my-proxy\u18097890'],
    [`//user\u1809${password}@10.1:8080`, '//10.1:8080'],
    [`http://example.com/?x=user\u1803${password}@10\u18090\u18090\u18098:1080`, 'http://example.com/?x=10\u18090\u18090\u18098:1080'],
    [`http://user\u1803${password}\uFF20127.0.0.1:7890`, 'http://127.0.0.1:7890'],
    [`http://user\u1809${password}%zz@127.0.0.1:7890`, 'http://127.0.0.1:7890'],
    [`two user\u1803${password}@my-proxy:7890) and user\u1809other-secret@10.1:8080.`, 'two my-proxy:7890) and 10.1:8080.'],
    [`invalid proxy url "http://user\u1803s3cret/token@my-proxy:7890": invalid port "\u1803s3cret" after host`, 'invalid proxy url "http://my-proxy:7890": invalid port ":[凭据已隐藏]" after host']
  );
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  assert.equal(redactPublic('http://user\u1803@127.0.0.1:7890'), 'http://user\u1803@127.0.0.1:7890');
  assert.equal(redactPublic('http://user\u1809@127.0.0.1:7890'), 'http://user\u1809@127.0.0.1:7890');
  assert.equal(redactPublic('http://user%E1%A0%83@127.0.0.1:7890'), 'http://user%E1%A0%83@127.0.0.1:7890');
  assert.equal(redactPublic('Build v1\u18032@beta'), 'Build v1\u18032@beta');
  assert.equal(redactPublic(`user\u1803${password}@internal`), `user\u1803${password}@internal`);
  assert.equal(redactPublic(`user:${password}@10\u18031`), `user:${password}@10\u18031`);
  assert.equal(redactPublic('score 1:2@10\u18035'), 'score 1:2@10\u18035');
  assert.equal(redactPublic('member@example\u1803test'), 'member@example\u1803test');
  assert.equal(redactPublic('member@example.test\u1809next'), 'member@example.test\u1809next');
  assert.equal(redactPublic('note 100%E1%A0%83off sale'), 'note 100%E1%A0%83off sale');
  assert.equal(redactPublic('http://user@127.0.0.1\u18037890'), 'http://user@127.0.0.1\u18037890');
  assert.equal(redactPublic(`user:${password}@my-proxy\u18037`), `user:${password}@my-proxy\u18037`);
  assert.equal(redactPublic(`user:${password}@my-proxy\u1809789012`), `user:${password}@my-proxy\u1809789012`);
  assert.equal(redactPublic(`user:${password}@127.0.0.1:7890`), '127.0.0.1:7890');
  const proxy = `http://user\u1803${password}@127.0.0.1:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note user\u1809${password}@127\u18030\u18030\u18031:7890`, email: 'a@example.test', last_error: `dial user:${password}@my-proxy\u18097890 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note 127\u18030\u18030\u18031:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial my-proxy\u18097890 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by a double-colon confusable', () => {
  const password = 's3cret-token';
  const marks = ['\u2237', '\u2E2C'];
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
    cases.push([`user:${password}@my-proxy${mark}7890`, `my-proxy${mark}7890`]);
    cases.push([`user:${password}@my-proxy${encoded}7890`, `my-proxy${encoded}7890`]);
    cases.push([`user:${password}@my-proxy${nest(encoded, 3)}7890`, `my-proxy${nest(encoded, 3)}7890`]);
    cases.push([`user:${password}@my-proxy:7890${mark}next`, `my-proxy:7890${mark}next`]);
  }
  cases.push(
    [`dial user%E2%88%B7${password}@router:8080%E2%B8%ACnext`, 'dial router:8080%E2%B8%ACnext'],
    [`socks5://alice\u2E2Chunter2@my-proxy:7890`, 'socks5://my-proxy:7890'],
    [`via user\u2237${password} proxy@10.1.1.1:8080 failed`, 'via 10.1.1.1:8080 failed'],
    [`user:${password}/token@my-proxy\u2E2C7890`, 'my-proxy\u2E2C7890'],
    [`//user\u2E2C${password}@10.1:8080`, '//10.1:8080'],
    [`http://example.com/?x=user\u2237${password}@10.0.0.8:1080`, 'http://example.com/?x=10.0.0.8:1080'],
    [`http://user\u2237${password}\uFF20127.0.0.1:7890`, 'http://127.0.0.1:7890'],
    [`http://user\u2E2C${password}%zz@127.0.0.1:7890`, 'http://127.0.0.1:7890'],
    [`two user\u2237${password}@my-proxy:7890) and user\u2E2Cother-secret@10.1:8080.`, 'two my-proxy:7890) and 10.1:8080.'],
    [`invalid proxy url "http://user\u2237s3cret/token@my-proxy:7890": invalid port "\u2237s3cret" after host`, 'invalid proxy url "http://my-proxy:7890": invalid port ":[凭据已隐藏]" after host']
  );
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  assert.equal(redactPublic('http://user\u2237@127.0.0.1:7890'), 'http://user\u2237@127.0.0.1:7890');
  assert.equal(redactPublic('http://user\u2E2C@127.0.0.1:7890'), 'http://user\u2E2C@127.0.0.1:7890');
  assert.equal(redactPublic('http://user%E2%88%B7@127.0.0.1:7890'), 'http://user%E2%88%B7@127.0.0.1:7890');
  assert.equal(redactPublic('Build v1\u22372@beta'), 'Build v1\u22372@beta');
  assert.equal(redactPublic(`user\u2237${password}@internal`), `user\u2237${password}@internal`);
  assert.equal(redactPublic(`user:${password}@10\u22371`), `user:${password}@10\u22371`);
  assert.equal(redactPublic('score 1:2@10\u2E2C5'), 'score 1:2@10\u2E2C5');
  assert.equal(redactPublic('member@example.test'), 'member@example.test');
  assert.equal(redactPublic('note 100%E2%88%B7off sale'), 'note 100%E2%88%B7off sale');
  assert.equal(redactPublic('http://user@127.0.0.1\u22377890'), 'http://user@127.0.0.1\u22377890');
  assert.equal(redactPublic(`user:${password}@my-proxy\u22377`), `user:${password}@my-proxy\u22377`);
  assert.equal(redactPublic(`user:${password}@my-proxy\u2E2C789012`), `user:${password}@my-proxy\u2E2C789012`);
  assert.equal(redactPublic(`user:${password}@127.0.0.1:7890`), '127.0.0.1:7890');
  const proxy = `http://user\u2237${password}@127.0.0.1:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: true, usage_probe: false },
    accounts: [{ id: 'acc-1', name: `note user\u2E2C${password}@my-proxy:7890`, email: 'a@example.test', last_error: `dial user:${password}@router\u22377890 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my-proxy:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial router\u22377890 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by a sign colon', () => {
  const password = 's3cret-token';
  const marks = ['\u1393', '\u{1D108}', '\u{11DD9}'];
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
    cases.push([`user:${password}@my-proxy${mark}7890`, `my-proxy${mark}7890`]);
    cases.push([`user:${password}@my-proxy${encoded}7890`, `my-proxy${encoded}7890`]);
    cases.push([`user:${password}@my-proxy${nest(encoded, 2)}7890`, `my-proxy${nest(encoded, 2)}7890`]);
    cases.push([`user:${password}@my-proxy:7890${mark}next`, `my-proxy:7890${mark}next`]);
  }
  cases.push(
    [`socks5://alice\u1393hunter2@my-proxy:7890`, 'socks5://my-proxy:7890'],
    [`via user\u{1D108}${password} proxy@10.1.1.1:8080 failed`, 'via 10.1.1.1:8080 failed'],
    [`user:${password}/token@my-proxy\u{11DD9}7890`, 'my-proxy\u{11DD9}7890'],
    [`http://example.com/?x=user\u1393${password}@10.0.0.8:1080`, 'http://example.com/?x=10.0.0.8:1080'],
    [`http://user\u{1D108}${password}\uFF20127.0.0.1:7890`, 'http://127.0.0.1:7890'],
    [`http://user\u{11DD9}${password}%zz@127.0.0.1:7890`, 'http://127.0.0.1:7890'],
    [`two user\u1393${password}@my-proxy:7890) and user\u{11DD9}other-secret@10.1:8080.`, 'two my-proxy:7890) and 10.1:8080.'],
    [`invalid proxy url "http://user\u1393s3cret/token@my-proxy:7890": invalid port "\u1393s3cret" after host`, 'invalid proxy url "http://my-proxy:7890": invalid port ":[凭据已隐藏]" after host']
  );
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  assert.equal(redactPublic('http://user\u1393@127.0.0.1:7890'), 'http://user\u1393@127.0.0.1:7890');
  assert.equal(redactPublic('http://user\u{1D108}@127.0.0.1:7890'), 'http://user\u{1D108}@127.0.0.1:7890');
  assert.equal(redactPublic('http://user\u{11DD9}@127.0.0.1:7890'), 'http://user\u{11DD9}@127.0.0.1:7890');
  assert.equal(redactPublic('Build v1\u13932@beta'), 'Build v1\u13932@beta');
  assert.equal(redactPublic(`user\u1393${password}@internal`), `user\u1393${password}@internal`);
  assert.equal(redactPublic(`user:${password}@10\u13931`), `user:${password}@10\u13931`);
  assert.equal(redactPublic('score 1:2@10\u{1D108}5'), 'score 1:2@10\u{1D108}5');
  assert.equal(redactPublic('member@example.test'), 'member@example.test');
  assert.equal(redactPublic('http://user@127.0.0.1\u13937890'), 'http://user@127.0.0.1\u13937890');
  assert.equal(redactPublic(`user:${password}@my-proxy\u13937`), `user:${password}@my-proxy\u13937`);
  assert.equal(redactPublic(`user:${password}@my-proxy\u{11DD9}789012`), `user:${password}@my-proxy\u{11DD9}789012`);
  assert.equal(redactPublic(`user:${password}@127.0.0.1:7890`), '127.0.0.1:7890');
  const proxy = `http://user\u1393${password}@127.0.0.1:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note user\u{1D108}${password}@my-proxy:7890`, email: 'a@example.test', last_error: `dial user:${password}@router\u{11DD9}7890 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my-proxy:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial router\u{11DD9}7890 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by the remaining Syriac colons', () => {
  const password = 's3cret-token';
  const marks = ['\u0705', '\u0706', '\u0707', '\u0708', '\u0709'];
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
    cases.push([`user:${password}@my-proxy${mark}7890`, `my-proxy${mark}7890`]);
    cases.push([`user:${password}@my-proxy${encoded}7890`, `my-proxy${encoded}7890`]);
    cases.push([`user:${password}@my-proxy${nest(encoded, 3)}7890`, `my-proxy${nest(encoded, 3)}7890`]);
    cases.push([`user:${password}@my-proxy:7890${mark}next`, `my-proxy:7890${mark}next`]);
    cases.push([`note ${mark}user:${password}@10.1:8080`, `note ${mark}10.1:8080`]);
    cases.push([`(${mark}user:${password}@127.0.0.1:7890)`, `(${mark}127.0.0.1:7890)`]);
  }
  cases.push(
    [`dial user%DC%85${password}@router:8080%DC%89next`, 'dial router:8080%DC%89next'],
    [`socks5://alice\u0706hunter2@my-proxy:7890`, 'socks5://my-proxy:7890'],
    [`via user\u0707${password} proxy@10.1.1.1:8080 failed`, 'via 10.1.1.1:8080 failed'],
    [`user:${password}/token@my-proxy\u07087890`, 'my-proxy\u07087890'],
    [`//user\u0709${password}@10.1:8080`, '//10.1:8080'],
    [`http://example.com/?x=user\u0705${password}@10.0.0.8:1080`, 'http://example.com/?x=10.0.0.8:1080'],
    [`http://user\u0706${password}\uFF20127.0.0.1:7890`, 'http://127.0.0.1:7890'],
    [`http://user\u0707${password}%zz@127.0.0.1:7890`, 'http://127.0.0.1:7890'],
    [`two user\u0708${password}@my-proxy:7890) and user\u0709other-secret@10.1:8080.`, 'two my-proxy:7890) and 10.1:8080.'],
    [`invalid proxy url "http://user\u0705s3cret/token@my-proxy:7890": invalid port "\u0705s3cret" after host`, 'invalid proxy url "http://my-proxy:7890": invalid port ":[凭据已隐藏]" after host'],
    [`note :user:${password}@10.1:8080`, `note :10.1:8080`],
    [`(:user:${password}@127.0.0.1:7890)`, `(:127.0.0.1:7890)`],
    [`:user:${password}@my-proxy:7890`, `:my-proxy:7890`],
    [`note \uFF1Auser:${password}@10.1:8080`, `note \uFF1A10.1:8080`],
    [`see (\u2236user:${password}@10.0.0.8:1080)`, `see (\u223610.0.0.8:1080)`]
  );
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  assert.equal(redactPublic('http://user\u0705@127.0.0.1:7890'), 'http://user\u0705@127.0.0.1:7890');
  assert.equal(redactPublic('http://user\u0709@127.0.0.1:7890'), 'http://user\u0709@127.0.0.1:7890');
  assert.equal(redactPublic('http://user%DC%85@127.0.0.1:7890'), 'http://user%DC%85@127.0.0.1:7890');
  assert.equal(redactPublic('Build v1\u07052@beta'), 'Build v1\u07052@beta');
  assert.equal(redactPublic('Build v1:2@beta'), 'Build v1:2@beta');
  assert.equal(redactPublic(`user\u0705${password}@internal`), `user\u0705${password}@internal`);
  assert.equal(redactPublic(`user:${password}@10\u07051`), `user:${password}@10\u07051`);
  assert.equal(redactPublic('score 1:2@10\u07065'), 'score 1:2@10\u07065');
  assert.equal(redactPublic('member@example.test'), 'member@example.test');
  assert.equal(redactPublic('note 100%DC%85off sale'), 'note 100%DC%85off sale');
  assert.equal(redactPublic('http://user@127.0.0.1\u07057890'), 'http://user@127.0.0.1\u07057890');
  assert.equal(redactPublic(`user:${password}@my-proxy\u07057`), `user:${password}@my-proxy\u07057`);
  assert.equal(redactPublic(`user:${password}@my-proxy\u0706789012`), `user:${password}@my-proxy\u0706789012`);
  assert.equal(redactPublic(`user:${password}@127\u07050\u07050\u07051:7890`), `user:${password}@127\u07050\u07050\u07051:7890`);
  assert.equal(redactPublic(`user:${password}@127.0.0.1:7890`), '127.0.0.1:7890');
  assert.equal(redactPublic('http://user@127.0.0.1:7890'), 'http://user@127.0.0.1:7890');
  const proxy = `http://user\u0705${password}@127.0.0.1:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note user\u0706${password}@my-proxy:7890`, email: 'a@example.test', last_error: `dial user:${password}@router\u07077890 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my-proxy:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial router\u07077890 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by an Ethiopic colon', () => {
  const password = 's3cret-token';
  const marks = ['\u1365', '\u1366'];
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
    cases.push([`user:${password}@my-proxy${mark}7890`, `my-proxy${mark}7890`]);
    cases.push([`user:${password}@my-proxy${encoded}7890`, `my-proxy${encoded}7890`]);
    cases.push([`user:${password}@my-proxy${nest(encoded, 3)}7890`, `my-proxy${nest(encoded, 3)}7890`]);
    cases.push([`user:${password}@my-proxy:7890${mark}next`, `my-proxy:7890${mark}next`]);
    cases.push([`note ${mark}user:${password}@10.1:8080`, `note ${mark}10.1:8080`]);
    cases.push([`(${mark}user:${password}@127.0.0.1:7890)`, `(${mark}127.0.0.1:7890)`]);
  }
  cases.push(
    [`dial user%E1%8D%A5${password}@router:8080%E1%8D%A6next`, 'dial router:8080%E1%8D%A6next'],
    [`socks5://alice\u1366hunter2@my-proxy:7890`, 'socks5://my-proxy:7890'],
    [`via user\u1365${password} proxy@10.1.1.1:8080 failed`, 'via 10.1.1.1:8080 failed'],
    [`user:${password}/token@my-proxy\u13667890`, 'my-proxy\u13667890'],
    [`//user\u1365${password}@10.1:8080`, '//10.1:8080'],
    [`http://example.com/?x=user\u1365${password}@10.0.0.8:1080`, 'http://example.com/?x=10.0.0.8:1080'],
    [`http://user\u1366${password}\uFF20127.0.0.1:7890`, 'http://127.0.0.1:7890'],
    [`http://user\u1365${password}%zz@127.0.0.1:7890`, 'http://127.0.0.1:7890'],
    [`two user\u1365${password}@my-proxy:7890) and user\u1366other-secret@10.1:8080.`, 'two my-proxy:7890) and 10.1:8080.'],
    [`invalid proxy url "http://user\u1365s3cret/token@my-proxy:7890": invalid port "\u1365s3cret" after host`, 'invalid proxy url "http://my-proxy:7890": invalid port ":[凭据已隐藏]" after host'],
    [`note \u1365user:${password}@10.1:8080`, `note \u136510.1:8080`],
    [`(\u1366user:${password}@127.0.0.1:7890)`, `(\u1366127.0.0.1:7890)`]
  );
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  assert.equal(redactPublic('http://user\u1365@127.0.0.1:7890'), 'http://user\u1365@127.0.0.1:7890');
  assert.equal(redactPublic('http://user\u1366@127.0.0.1:7890'), 'http://user\u1366@127.0.0.1:7890');
  assert.equal(redactPublic('http://user%E1%8D%A5@127.0.0.1:7890'), 'http://user%E1%8D%A5@127.0.0.1:7890');
  assert.equal(redactPublic('Build v1\u13652@beta'), 'Build v1\u13652@beta');
  assert.equal(redactPublic('Build v1:2@beta'), 'Build v1:2@beta');
  assert.equal(redactPublic(`user\u1365${password}@internal`), `user\u1365${password}@internal`);
  assert.equal(redactPublic(`user:${password}@10\u13651`), `user:${password}@10\u13651`);
  assert.equal(redactPublic('score 1:2@10\u13665'), 'score 1:2@10\u13665');
  assert.equal(redactPublic('member@example.test'), 'member@example.test');
  assert.equal(redactPublic('note 100%E1%8D%A5off sale'), 'note 100%E1%8D%A5off sale');
  assert.equal(redactPublic('see \u1365 later'), 'see \u1365 later');
  assert.equal(redactPublic('http://user@127.0.0.1\u13657890'), 'http://user@127.0.0.1\u13657890');
  assert.equal(redactPublic(`user:${password}@my-proxy\u13657`), `user:${password}@my-proxy\u13657`);
  assert.equal(redactPublic(`user:${password}@my-proxy\u1366789012`), `user:${password}@my-proxy\u1366789012`);
  assert.equal(redactPublic(`user:${password}@127\u13650\u13650\u13651:7890`), `user:${password}@127\u13650\u13650\u13651:7890`);
  assert.equal(redactPublic(`user:${password}@127.0.0.1:7890`), '127.0.0.1:7890');
  assert.equal(redactPublic('http://user@127.0.0.1:7890'), 'http://user@127.0.0.1:7890');
  const proxy = `http://user\u1365${password}@127.0.0.1:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note user\u1366${password}@my-proxy:7890`, email: 'a@example.test', last_error: `dial user:${password}@router\u13657890 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my-proxy:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial router\u13657890 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by a Mongolian colon', () => {
  const password = 's3cret-token';
  const mark = '\u1804';
  const nest = (value, layers) => {
    let out = value;
    for (let layer = 0; layer < layers; layer += 1) out = out.replace(/%/g, '%25');
    return out;
  };
  const encoded = encodeURIComponent(mark);
  const cases = [
    [`http://user${mark}${password}@127.0.0.1:7890`, 'http://127.0.0.1:7890'],
    [`user${mark}${password}@my-proxy:7890`, 'my-proxy:7890'],
    [`(user${mark}${password}@10.0.0.8:1080)`, '(10.0.0.8:1080)'],
    [`http://user${encoded}${password}@127.0.0.1:7890`, 'http://127.0.0.1:7890'],
    [`user${nest(encoded, 1).toLowerCase()}${password}@127.1:7890`, '127.1:7890'],
    [`//user${nest(encoded, 3)}${password}@[::1]:8792`, '//[::1]:8792'],
    [`user:${password}@my-proxy${mark}7890`, `my-proxy${mark}7890`],
    [`user:${password}@my-proxy${encoded}7890`, `my-proxy${encoded}7890`],
    [`user:${password}@my-proxy${nest(encoded, 3)}7890`, `my-proxy${nest(encoded, 3)}7890`],
    [`user:${password}@my-proxy:7890${mark}next`, `my-proxy:7890${mark}next`],
    [`note ${mark}user:${password}@10.1:8080`, `note ${mark}10.1:8080`],
    [`(${mark}user:${password}@127.0.0.1:7890)`, `(${mark}127.0.0.1:7890)`],
    [`dial user%E1%A0%84${password}@router:8080${mark}next`, `dial router:8080${mark}next`],
    [`socks5://alice${mark}hunter2@my-proxy:7890`, 'socks5://my-proxy:7890'],
    [`via user${mark}${password} proxy@10.1.1.1:8080 failed`, 'via 10.1.1.1:8080 failed'],
    [`user:${password}/token@my-proxy${mark}7890`, `my-proxy${mark}7890`],
    [`//user${mark}${password}@10.1:8080`, '//10.1:8080'],
    [`http://example.com/?x=user${mark}${password}@10.0.0.8:1080`, 'http://example.com/?x=10.0.0.8:1080'],
    [`http://user${mark}${password}\uFF20127.0.0.1:7890`, 'http://127.0.0.1:7890'],
    [`http://user${mark}${password}%zz@127.0.0.1:7890`, 'http://127.0.0.1:7890'],
    [`two user${mark}${password}@my-proxy:7890) and user${mark}other-secret@10.1:8080.`, 'two my-proxy:7890) and 10.1:8080.'],
    [`invalid proxy url "http://user${mark}s3cret/token@my-proxy:7890": invalid port "${mark}s3cret" after host`, 'invalid proxy url "http://my-proxy:7890": invalid port ":[凭据已隐藏]" after host']
  ];
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  assert.equal(redactPublic(`http://user${mark}@127.0.0.1:7890`), `http://user${mark}@127.0.0.1:7890`);
  assert.equal(redactPublic('http://user%E1%A0%84@127.0.0.1:7890'), 'http://user%E1%A0%84@127.0.0.1:7890');
  assert.equal(redactPublic(`Build v1${mark}2@beta`), `Build v1${mark}2@beta`);
  assert.equal(redactPublic('Build v1:2@beta'), 'Build v1:2@beta');
  assert.equal(redactPublic(`user${mark}${password}@internal`), `user${mark}${password}@internal`);
  assert.equal(redactPublic(`user:${password}@10${mark}1`), `user:${password}@10${mark}1`);
  assert.equal(redactPublic(`score 1:2@10${mark}5`), `score 1:2@10${mark}5`);
  assert.equal(redactPublic('member@example.test'), 'member@example.test');
  assert.equal(redactPublic('note 100%E1%A0%84off sale'), 'note 100%E1%A0%84off sale');
  assert.equal(redactPublic(`see ${mark} later`), `see ${mark} later`);
  assert.equal(redactPublic(`http://user@127.0.0.1${mark}7890`), `http://user@127.0.0.1${mark}7890`);
  assert.equal(redactPublic(`user:${password}@my-proxy${mark}7`), `user:${password}@my-proxy${mark}7`);
  assert.equal(redactPublic(`user:${password}@my-proxy${mark}789012`), `user:${password}@my-proxy${mark}789012`);
  assert.equal(redactPublic(`user:${password}@127${mark}0${mark}0${mark}1:7890`), `user:${password}@127${mark}0${mark}0${mark}1:7890`);
  assert.equal(redactPublic(`user:${password}@127.0.0.1:7890`), '127.0.0.1:7890');
  assert.equal(redactPublic('http://user@127.0.0.1:7890'), 'http://user@127.0.0.1:7890');
  const proxy = `http://user${mark}${password}@127.0.0.1:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: true, usage_probe: false },
    accounts: [{ id: 'acc-1', name: `note user${mark}${password}@my-proxy:7890`, email: 'a@example.test', last_error: `dial user:${password}@router${mark}7890 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my-proxy:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, `dial router${mark}7890 failed`);
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by a half triangular colon', () => {
  const password = 's3cret-token';
  const mark = '\u02D1';
  const nest = (value, layers) => {
    let out = value;
    for (let layer = 0; layer < layers; layer += 1) out = out.replace(/%/g, '%25');
    return out;
  };
  const encoded = encodeURIComponent(mark);
  const cases = [
    [`http://user${mark}${password}@127.0.0.1:7890`, 'http://127.0.0.1:7890'],
    [`user${mark}${password}@my-proxy:7890`, 'my-proxy:7890'],
    [`(user${mark}${password}@10.0.0.8:1080)`, '(10.0.0.8:1080)'],
    [`http://user${encoded}${password}@127.0.0.1:7890`, 'http://127.0.0.1:7890'],
    [`user${nest(encoded, 1).toLowerCase()}${password}@127.1:7890`, '127.1:7890'],
    [`//user${nest(encoded, 3)}${password}@[::1]:8792`, '//[::1]:8792'],
    [`user:${password}@my-proxy${mark}7890`, `my-proxy${mark}7890`],
    [`user:${password}@my-proxy${encoded}7890`, `my-proxy${encoded}7890`],
    [`user:${password}@my-proxy${nest(encoded, 3)}7890`, `my-proxy${nest(encoded, 3)}7890`],
    [`user:${password}@my-proxy:7890${mark}next`, `my-proxy:7890${mark}next`],
    [`note ${mark}user:${password}@10.1:8080`, `note ${mark}10.1:8080`],
    [`(${mark}user:${password}@127.0.0.1:7890)`, `(${mark}127.0.0.1:7890)`],
    [`dial user%CB%91${password}@router:8080${mark}next`, `dial router:8080${mark}next`],
    [`socks5://alice${mark}hunter2@my-proxy:7890`, 'socks5://my-proxy:7890'],
    [`via user${mark}${password} proxy@10.1.1.1:8080 failed`, 'via 10.1.1.1:8080 failed'],
    [`user:${password}/token@my-proxy${mark}7890`, `my-proxy${mark}7890`],
    [`//user${mark}${password}@10.1:8080`, '//10.1:8080'],
    [`http://example.com/?x=user${mark}${password}@10.0.0.8:1080`, 'http://example.com/?x=10.0.0.8:1080'],
    [`http://user${mark}${password}\uFF20127.0.0.1:7890`, 'http://127.0.0.1:7890'],
    [`http://user${mark}${password}%zz@127.0.0.1:7890`, 'http://127.0.0.1:7890'],
    [`two user${mark}${password}@my-proxy:7890) and user\u02D0other-secret@10.1:8080.`, 'two my-proxy:7890) and 10.1:8080.'],
    [`invalid proxy url "http://user${mark}s3cret/token@my-proxy:7890": invalid port "${mark}s3cret" after host`, 'invalid proxy url "http://my-proxy:7890": invalid port ":[凭据已隐藏]" after host']
  ];
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  assert.equal(redactPublic(`http://user${mark}@127.0.0.1:7890`), `http://user${mark}@127.0.0.1:7890`);
  assert.equal(redactPublic('http://user%CB%91@127.0.0.1:7890'), 'http://user%CB%91@127.0.0.1:7890');
  assert.equal(redactPublic(`Build v1${mark}2@beta`), `Build v1${mark}2@beta`);
  assert.equal(redactPublic('Build v1:2@beta'), 'Build v1:2@beta');
  assert.equal(redactPublic(`user${mark}${password}@internal`), `user${mark}${password}@internal`);
  assert.equal(redactPublic(`user:${password}@10${mark}1`), `user:${password}@10${mark}1`);
  assert.equal(redactPublic(`score 1:2@10${mark}5`), `score 1:2@10${mark}5`);
  assert.equal(redactPublic('member@example.test'), 'member@example.test');
  assert.equal(redactPublic('note 100%CB%91off sale'), 'note 100%CB%91off sale');
  assert.equal(redactPublic(`see ${mark} later`), `see ${mark} later`);
  assert.equal(redactPublic(`http://user@127.0.0.1${mark}7890`), `http://user@127.0.0.1${mark}7890`);
  assert.equal(redactPublic(`user:${password}@my-proxy${mark}7`), `user:${password}@my-proxy${mark}7`);
  assert.equal(redactPublic(`user:${password}@my-proxy${mark}789012`), `user:${password}@my-proxy${mark}789012`);
  assert.equal(redactPublic(`user:${password}@127${mark}0${mark}0${mark}1:7890`), `user:${password}@127${mark}0${mark}0${mark}1:7890`);
  assert.equal(redactPublic(`user:${password}@127.0.0.1:7890`), '127.0.0.1:7890');
  assert.equal(redactPublic('http://user@127.0.0.1:7890'), 'http://user@127.0.0.1:7890');
  assert.equal(redactPublic(`user\u02D0${password}@127.0.0.1:7890`), '127.0.0.1:7890');
  const proxy = `http://user${mark}${password}@127.0.0.1:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note user${mark}${password}@my-proxy:7890`, email: 'a@example.test', last_error: `dial user:${password}@router${mark}7890 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my-proxy:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, `dial router${mark}7890 failed`);
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by the remaining colon confusables', () => {
  const password = 's3cret-token';
  const marks = ['\u05C3', '\u0831', '\u0903', '\u0A83', '\u1361', '\u16EC', '\u205A', '\uA4FD', '\uFE30'];
  const signs = ['\u{1015B}', '\u{10AF5}', '\u{11002}', '\u{11082}', '\u{11182}', '\u{1123A}', '\u{115BE}', '\u{116AC}', '\u{11838}'];
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
    cases.push([`user:${password}@my-proxy${mark}7890`, `my-proxy${mark}7890`]);
    cases.push([`user:${password}@my-proxy${encoded}7890`, `my-proxy${encoded}7890`]);
    cases.push([`user:${password}@my-proxy${nest(encoded, 3)}7890`, `my-proxy${nest(encoded, 3)}7890`]);
    cases.push([`user:${password}@my-proxy:7890${mark}next`, `my-proxy:7890${mark}next`]);
    cases.push([`note ${mark}user:${password}@10.1:8080`, `note ${mark}10.1:8080`]);
    cases.push([`(${mark}user:${password}@127.0.0.1:7890)`, `(${mark}127.0.0.1:7890)`]);
  }
  for (const mark of signs) {
    const encoded = encodeURIComponent(mark);
    cases.push([`http://user${mark}${password}@127.0.0.1:7890`, 'http://127.0.0.1:7890']);
    cases.push([`user${mark}${password}@my-proxy:7890`, 'my-proxy:7890']);
    cases.push([`(user${mark}${password}@10.0.0.8:1080)`, '(10.0.0.8:1080)']);
    cases.push([`http://user${encoded}${password}@127.0.0.1:7890`, 'http://127.0.0.1:7890']);
    cases.push([`user${nest(encoded, 1).toLowerCase()}${password}@127.1:7890`, '127.1:7890']);
    cases.push([`//user${nest(encoded, 3)}${password}@[::1]:8792`, '//[::1]:8792']);
    cases.push([`user:${password}@my-proxy${mark}7890`, `my-proxy${mark}7890`]);
    cases.push([`user:${password}@my-proxy${encoded}7890`, `my-proxy${encoded}7890`]);
    cases.push([`user:${password}@my-proxy${nest(encoded, 3)}7890`, `my-proxy${nest(encoded, 3)}7890`]);
    cases.push([`user:${password}@my-proxy:7890${mark}next`, `my-proxy:7890${mark}next`]);
    cases.push([`note ${mark}user:${password}@10.1:8080`, 'note 10.1:8080']);
    cases.push([`(${mark}user:${password}@127.0.0.1:7890)`, '(127.0.0.1:7890)']);
  }
  cases.push(
    [`socks5://alice\u05C3hunter2@my-proxy:7890`, 'socks5://my-proxy:7890'],
    [`via user\u16EC${password} proxy@10.1.1.1:8080 failed`, 'via 10.1.1.1:8080 failed'],
    [`user:${password}/token@my-proxy\u205A7890`, 'my-proxy\u205A7890'],
    [`//user\uA4FD${password}@10.1:8080`, '//10.1:8080'],
    [`http://example.com/?x=user\u1361${password}@10.0.0.8:1080`, 'http://example.com/?x=10.0.0.8:1080'],
    [`http://user\u0831${password}\uFF20127.0.0.1:7890`, 'http://127.0.0.1:7890'],
    [`http://user\u0903${password}%zz@127.0.0.1:7890`, 'http://127.0.0.1:7890'],
    [`two user\u0A83${password}@my-proxy:7890) and user\u{1123A}other-secret@10.1:8080.`, 'two my-proxy:7890) and 10.1:8080.'],
    [`invalid proxy url "http://user\u05C3s3cret/token@my-proxy:7890": invalid port "\u05C3s3cret" after host`, 'invalid proxy url "http://my-proxy:7890": invalid port ":[凭据已隐藏]" after host'],
    [`invalid proxy url "http://user\u{10AF5}s3cret/token@my-proxy:7890": invalid port "\u{10AF5}s3cret" after host`, 'invalid proxy url "http://my-proxy:7890": invalid port ":[凭据已隐藏]" after host'],
    [`user:${password}@127\uFE300\uFE300\uFE301:7890`, '127\uFE300\uFE300\uFE301:7890'],
    [`note :user:${password}@10.1:8080`, 'note :10.1:8080']
  );
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  for (const mark of marks.concat(signs)) {
    assert.equal(redactPublic(`http://user${mark}@127.0.0.1:7890`), `http://user${mark}@127.0.0.1:7890`);
    assert.equal(redactPublic(`http://user${encodeURIComponent(mark)}@127.0.0.1:7890`), `http://user${encodeURIComponent(mark)}@127.0.0.1:7890`);
    assert.equal(redactPublic(`Build v1${mark}2@beta`), `Build v1${mark}2@beta`);
    assert.equal(redactPublic(`user${mark}${password}@internal`), `user${mark}${password}@internal`);
    assert.equal(redactPublic(`user:${password}@10${mark}1`), `user:${password}@10${mark}1`);
    assert.equal(redactPublic(`score 1:2@10${mark}5`), `score 1:2@10${mark}5`);
    assert.equal(redactPublic(`see ${mark} later`), `see ${mark} later`);
    assert.equal(redactPublic(`http://user@127.0.0.1${mark}7890`), `http://user@127.0.0.1${mark}7890`);
    assert.equal(redactPublic(`user:${password}@my-proxy${mark}7`), `user:${password}@my-proxy${mark}7`);
    assert.equal(redactPublic(`user:${password}@my-proxy${mark}789012`), `user:${password}@my-proxy${mark}789012`);
  }
  for (const mark of marks) {
    if (mark === '\uFE30') continue;
    assert.equal(redactPublic(`user:${password}@127${mark}0${mark}0${mark}1:7890`), `user:${password}@127${mark}0${mark}0${mark}1:7890`);
  }
  assert.equal(redactPublic('Build v1:2@beta'), 'Build v1:2@beta');
  assert.equal(redactPublic('member@example.test'), 'member@example.test');
  assert.equal(redactPublic('note 100%D7%83off sale'), 'note 100%D7%83off sale');
  assert.equal(redactPublic(`user:${password}@127.0.0.1:7890`), '127.0.0.1:7890');
  assert.equal(redactPublic('http://user@127.0.0.1:7890'), 'http://user@127.0.0.1:7890');
  const proxy = `http://user\u05C3${password}@127.0.0.1:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note user\u16EC${password}@my-proxy:7890`, email: 'a@example.test', last_error: `dial user:${password}@router\u{1123A}7890 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my-proxy:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial router\u{1123A}7890 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by a colon compound', () => {
  const password = 's3cret-token';
  const marks = ['\u2254', '\u2255', '\u29F4', '\u2A74'];
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
    cases.push([`user:${password}@my-proxy${mark}7890`, `my-proxy${mark}7890`]);
    cases.push([`user:${password}@my-proxy${encoded}7890`, `my-proxy${encoded}7890`]);
    cases.push([`user:${password}@my-proxy${nest(encoded, 3)}7890`, `my-proxy${nest(encoded, 3)}7890`]);
    cases.push([`user:${password}@my-proxy:7890${mark}next`, `my-proxy:7890${mark}next`]);
    cases.push([`note ${mark}user:${password}@10.1:8080`, `note ${mark}10.1:8080`]);
    cases.push([`(${mark}user:${password}@127.0.0.1:7890)`, `(${mark}127.0.0.1:7890)`]);
  }
  cases.push(
    [`socks5://alice\u2254hunter2@my-proxy:7890`, 'socks5://my-proxy:7890'],
    [`via user\u29F4${password} proxy@10.1.1.1:8080 failed`, 'via 10.1.1.1:8080 failed'],
    [`user:${password}/token@my-proxy\u2A747890`, 'my-proxy\u2A747890'],
    [`//user\u2255${password}@10.1:8080`, '//10.1:8080'],
    [`http://example.com/?x=user\u2254${password}@10.0.0.8:1080`, 'http://example.com/?x=10.0.0.8:1080'],
    [`http://user\u2255${password}\uFF20127.0.0.1:7890`, 'http://127.0.0.1:7890'],
    [`http://user\u2A74${password}%zz@127.0.0.1:7890`, 'http://127.0.0.1:7890'],
    [`two user\u2254${password}@my-proxy:7890) and user\u29F4other-secret@10.1:8080.`, 'two my-proxy:7890) and 10.1:8080.'],
    [`invalid proxy url "http://user\u2254s3cret/token@my-proxy:7890": invalid port "\u2254s3cret" after host`, 'invalid proxy url "http://my-proxy:7890": invalid port ":[凭据已隐藏]" after host'],
    [`user:${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`note :=user:${password}@10.1:8080`, 'note :=10.1:8080']
  );
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  for (const mark of marks) {
    assert.equal(redactPublic(`http://user${mark}@127.0.0.1:7890`), `http://user${mark}@127.0.0.1:7890`);
    assert.equal(redactPublic(`http://user${encodeURIComponent(mark)}@127.0.0.1:7890`), `http://user${encodeURIComponent(mark)}@127.0.0.1:7890`);
    assert.equal(redactPublic(`Build v1${mark}2@beta`), `Build v1${mark}2@beta`);
    assert.equal(redactPublic(`user${mark}${password}@internal`), `user${mark}${password}@internal`);
    assert.equal(redactPublic(`user:${password}@10${mark}1`), `user:${password}@10${mark}1`);
    assert.equal(redactPublic(`score 1:2@10${mark}5`), `score 1:2@10${mark}5`);
    assert.equal(redactPublic(`see ${mark} later`), `see ${mark} later`);
    assert.equal(redactPublic(`http://user@127.0.0.1${mark}7890`), `http://user@127.0.0.1${mark}7890`);
    assert.equal(redactPublic(`user:${password}@my-proxy${mark}7`), `user:${password}@my-proxy${mark}7`);
    assert.equal(redactPublic(`user:${password}@my-proxy${mark}789012`), `user:${password}@my-proxy${mark}789012`);
    assert.equal(redactPublic(`user:${password}@127${mark}0${mark}0${mark}1:7890`), `user:${password}@127${mark}0${mark}0${mark}1:7890`);
  }
  assert.equal(redactPublic('Build v1:2@beta'), 'Build v1:2@beta');
  assert.equal(redactPublic('member@example.test'), 'member@example.test');
  assert.equal(redactPublic('note 100%E2%89%94off sale'), 'note 100%E2%89%94off sale');
  assert.equal(redactPublic('http://user@127.0.0.1:7890'), 'http://user@127.0.0.1:7890');
  assert.equal(redactPublic(`user\u2237${password}@127.0.0.1:7890`), '127.0.0.1:7890');
  const proxy = `http://user\u2254${password}@127.0.0.1:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: true, usage_probe: false },
    accounts: [{ id: 'acc-1', name: `note user\u2255${password}@my-proxy:7890`, email: 'a@example.test', last_error: `dial user:${password}@router\u2A747890 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my-proxy:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial router\u2A747890 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by an HTML character reference', () => {
  const password = 's3cret-token';
  const sign = String.fromCodePoint(0x1D108);
  const cases = [
    [`user&#58;${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user&#x3A;${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user&#X3a;${password}@my-proxy:7890`, 'my-proxy:7890'],
    [`user&#00058;${password}@10.0.0.8:1080`, '10.0.0.8:1080'],
    [`user&#58${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user&#x3a${password}@my-proxy:7890`, 'my-proxy:7890'],
    [`user&colon;${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user&amp;colon;${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user&amp;amp;amp;colon;${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user&#38;#58;${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user&#x26;colon;${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`http://user&#58;${password}&#64;127.0.0.1:7890`, 'http://127.0.0.1:7890'],
    [`http://user&colon;${password}&commat;127.0.0.1:7890/x`, 'http://127.0.0.1:7890/x'],
    [`(user&#58;${password}@10.0.0.8:1080)`, '(10.0.0.8:1080)'],
    [`//user&#58;${password}@[::1]:8792`, '//[::1]:8792'],
    [`socks5://alice&#58;hunter2@my-proxy:7890`, 'socks5://my-proxy:7890'],
    [`via user&#58;${password} proxy@10.1.1.1:8080 failed`, 'via 10.1.1.1:8080 failed'],
    [`user&#58;${password}/token@my-proxy:7890`, 'my-proxy:7890'],
    [`http://example.com/?x=user&colon;${password}@10.0.0.8:1080`, 'http://example.com/?x=10.0.0.8:1080'],
    [`two user&#58;${password}@my-proxy:7890) and user:other-secret&#64;10.1:8080.`, 'two my-proxy:7890) and 10.1:8080.'],
    [`invalid proxy url "http://user&#58;s3cret/token@my-proxy:7890": invalid port "&#58;s3cret" after host`, 'invalid proxy url "http://my-proxy:7890": invalid port ":[凭据已隐藏]" after host'],
    [`user:${password}@my-proxy:&#55;&#56;&#57;&#48;`, 'my-proxy:7890'],
    [`user:${password}@my-proxy:&#x37;&#x38;&#x39;&#x30;`, 'my-proxy:7890'],
    [`user:${password}@my-proxy&#58;&#55;&#56;&#57;&#48;`, 'my-proxy:7890'],
    [`user:${password}@&#49;&#50;&#55;&#46;&#48;&#46;&#48;&#46;&#49;:7890`, '127.0.0.1:7890'],
    [`user:${password}@my-proxy:&#xff17;&#xff18;&#xff19;&#xff10;`, 'my-proxy:\uFF17\uFF18\uFF19\uFF10'],
    [`user:${password}@my-proxy:&#178;&#179;&#185;&#8304;`, 'my-proxy:\u00B2\u00B3\u00B9\u2070'],
    [`user&#8758;${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user&#x2236;${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user&ratio;${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user&Colon;${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user&colone;${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user:${password}&#xfe6b;127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user:${password}@127&#8226;0&#8226;0&#8226;1:7890`, '127\u20220\u20220\u20221:7890'],
    [`user:${password}@127&middot;0&middot;0&middot;1:7890`, '127\u00B70\u00B70\u00B71:7890'],
    [`http://user&#${sign.codePointAt(0)};${password}@127.0.0.1:7890`, 'http://127.0.0.1:7890'],
    [`note &#58;user:${password}@10.1:8080`, 'note :10.1:8080'],
    [`(&#58;user:${password}@127.0.0.1:7890)`, '(:127.0.0.1:7890)'],
    [`http://user&#58;${password}%zz@127.0.0.1:7890`, 'http://127.0.0.1:7890'],
    [`a=1&user&#58;${password}@my-proxy:7890&b=2`, 'a=1&my-proxy:7890&b=2']
  ];
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  const unchanged = [
    'Build v1&#58;2@beta',
    `user&#58;${password}@internal`,
    `user&#58;${password}@10.1`,
    'score 1&#58;2@10.5',
    'member&commat;example.test',
    'http://user&#64;127.0.0.1:7890',
    'http://user&#58;@127.0.0.1:7890',
    `user:${password}@my-proxy:&#55;`,
    `user:${password}@my-proxy:&#55;&#56;&#57;&#48;&#49;&#50;`,
    'see &#58; later',
    'user&colons3cret@127.0.0.1:7890',
    'note 100&#58;off sale',
    'version &#49;&#50;',
    'http://user@127.0.0.1:7890'
  ];
  for (const input of unchanged) assert.equal(redactPublic(input), input);
  const proxy = `http://user&#58;${password}@127.0.0.1:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note user&colon;${password}@my-proxy:7890`, email: 'a@example.test', last_error: `dial user:${password}&#64;127.0.0.1:7890 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my-proxy:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial 127.0.0.1:7890 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by an HTML entity alias', () => {
  const password = 's3cret-token';
  const cases = [
    [`user&Assign;${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user&coloneq;${password}@my-proxy:7890`, 'my-proxy:7890'],
    [`user&Proportion;${password}@10.0.0.8:1080`, '10.0.0.8:1080'],
    [`user&RuleDelayed;${password}@127.1:7890`, '127.1:7890'],
    [`user&ecolon;${password}@[::1]:8792`, '[::1]:8792'],
    [`(user&Assign;${password}@10.0.0.8:1080)`, '(10.0.0.8:1080)'],
    [`//user&coloneq;${password}@127.0.0.1:7890`, '//127.0.0.1:7890'],
    [`socks5://alice&Proportion;hunter2@my-proxy:7890`, 'socks5://my-proxy:7890'],
    [`via user&RuleDelayed;${password} proxy@10.1.1.1:8080 failed`, 'via 10.1.1.1:8080 failed'],
    [`user&ecolon;${password}/token@my-proxy:7890`, 'my-proxy:7890'],
    [`http://example.com/?x=user&Assign;${password}@10.0.0.8:1080`, 'http://example.com/?x=10.0.0.8:1080'],
    [`user:${password}@my-proxy&Assign;7890`, 'my-proxy\u22547890'],
    [`user:${password}@my-proxy&coloneq;7890`, 'my-proxy\u22547890'],
    [`user:${password}@my-proxy&Proportion;7890`, 'my-proxy\u22377890'],
    [`user:${password}@my-proxy&RuleDelayed;7890`, 'my-proxy\u29F47890'],
    [`user:${password}@my-proxy&ecolon;7890`, 'my-proxy\u22557890'],
    [`note &Assign;user:${password}@10.1:8080`, 'note \u225410.1:8080'],
    [`(&ecolon;user:${password}@127.0.0.1:7890)`, '(\u2255127.0.0.1:7890)'],
    [`user&amp;Assign;${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user&AMP;colon;${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user&ampcolon;${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user&ampAssign;${password}@my-proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@127&bull;0&bull;0&bull;1:7890`, '127\u20220\u20220\u20221:7890'],
    [`user:${password}@127&bullet;0&bullet;0&bullet;1:7890`, '127\u20220\u20220\u20221:7890'],
    [`user:${password}@127&hybull;0&hybull;0&hybull;1:7890`, '127\u20430\u20430\u20431:7890'],
    [`user:${password}@127&nldr;0&nldr;0&nldr;1:7890`, '127\u20250\u20250\u20251:7890'],
    [`user:${password}@127&ofcir;0&ofcir;0&ofcir;1:7890`, '127\u29BF0\u29BF0\u29BF1:7890'],
    [`user:${password}@127&sdot;0&sdot;0&sdot;1:7890`, '127\u22C50\u22C50\u22C51:7890'],
    [`user:${password}@127&CenterDot;0&CenterDot;0&CenterDot;1:7890`, '127\u00B70\u00B70\u00B71:7890'],
    [`user:${password}@127&centerdot;0&centerdot;0&centerdot;1:7890`, '127\u00B70\u00B70\u00B71:7890'],
    [`user:${password}@127&middot0&middot0&middot1:7890`, '127\u00B70\u00B70\u00B71:7890'],
    [`user:${password}@&sup1;&sup2;&sup3;.0.0.1:7890`, '\u00B9\u00B2\u00B3.0.0.1:7890'],
    [`user:${password}@my-proxy:&sup2;&sup3;&sup1;&sup2;`, 'my-proxy:\u00B2\u00B3\u00B9\u00B2'],
    [`user:${password}@my-proxy:&sup2&sup3&sup1&sup2`, 'my-proxy:\u00B2\u00B3\u00B9\u00B2'],
    [`user&percnt;3A${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user&#37;3A${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user&#x25;3A${password}@my-proxy:7890`, 'my-proxy:7890'],
    [`user&#X25;3a${password}@10.0.0.8:1080`, '10.0.0.8:1080'],
    [`user&#00037;3A${password}@127.1:7890`, '127.1:7890'],
    [`user&#37;253A${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user&amp;percnt;3A${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user&AMP;percnt;3A${password}@my-proxy:7890`, 'my-proxy:7890'],
    [`user&#38;#37;3A${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user&#x26;percnt;3A${password}@10.0.0.8:1080`, '10.0.0.8:1080'],
    [`http://user&#37;3A${password}&#37;40127.0.0.1:7890/x`, 'http://127.0.0.1:7890/x'],
    [`user:${password}&#37;40127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user:${password}&percnt;40my-proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@127&#37;2E0&#37;2E0&#37;2E1:7890`, '127%2E0%2E0%2E1:7890'],
    [`user:${password}@my-proxy:&#37;37&#37;38&#37;39&#37;30`, 'my-proxy:%37%38%39%30'],
    [`two user&Assign;${password}@my-proxy:7890) and user&percnt;3Aother-secret@10.1:8080.`, 'two my-proxy:7890) and 10.1:8080.'],
    [`invalid proxy url "http://user&Assign;s3cret/token@my-proxy:7890": invalid port "&Assign;s3cret" after host`, 'invalid proxy url "http://my-proxy:7890": invalid port ":[凭据已隐藏]" after host'],
    [`a=1&user&Assign;${password}@127&sdot;0&sdot;0&sdot;1:7890&b=2`, 'a=1&127\u22C50\u22C50\u22C51:7890&b=2']
  ];
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  const unchanged = [
    'Build v1&Assign;2@beta',
    `user&Assign;${password}@internal`,
    `user&#37;3A${password}@internal`,
    `user&percnt;3A${password}@internal`,
    'score 1&percnt;3A2@10.5',
    'score 1&#37;3A2@10.5',
    'member&percnt;40example.test',
    'http://user&#37;40127.0.0.1:7890',
    'http://user&percnt;40example.test',
    'note 100&percnt; off',
    'see &bull; later',
    'version &sup2;',
    `user:${password}@my-proxy:&sup2`,
    `user:${password}@10&sup1;`,
    'user&Assigns3cret@127.0.0.1:7890',
    'user&colons3cret@127.0.0.1:7890',
    'user&bulletextra@127.0.0.1:7890',
    'http://user@127.0.0.1:7890'
  ];
  for (const input of unchanged) assert.equal(redactPublic(input), input);
  const proxy = `http://user&Assign;${password}@127.0.0.1:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: true, usage_probe: false },
    accounts: [{ id: 'acc-1', name: `note user&Assign;${password}@127&sdot;0&sdot;0&sdot;1:7890`, email: 'a@example.test', last_error: `dial user&percnt;3A${password}@my-proxy:&sup2;&sup3;&sup1;&sup2; failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note 127\u22C50\u22C50\u22C51:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial my-proxy:\u00B2\u00B3\u00B9\u00B2 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by an encoded HTML reference', () => {
  const password = 's3cret-token';
  const nest = (value, layers) => {
    let out = value;
    for (let layer = 0; layer < layers; layer += 1) out = out.replace(/%/g, '%25');
    return out;
  };
  const colon = '%26%2358%3B';
  const cases = [
    [`user${colon}${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user%26%23x3A%3B${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user%26%23X3a%3b${password}@my-proxy:7890`, 'my-proxy:7890'],
    [`user%26%2300058%3B${password}@10.0.0.8:1080`, '10.0.0.8:1080'],
    [`user%26%2358${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user%26colon%3B${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user%26Assign%3B${password}@my-proxy:7890`, 'my-proxy:7890'],
    [`user%26amp%3Bcolon%3B${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user%26ampcolon%3B${password}@10.0.0.8:1080`, '10.0.0.8:1080'],
    [`user${nest(colon, 1)}${password}@127.1:7890`, '127.1:7890'],
    [`user${nest(colon, 3).toLowerCase()}${password}@[::1]:8792`, '[::1]:8792'],
    [`http://user${colon}${password}%26%2364%3B127.0.0.1:7890/x`, 'http://127.0.0.1:7890/x'],
    [`http://user%26colon%3B${password}%26commat%3B127.0.0.1:7890`, 'http://127.0.0.1:7890'],
    [`(user%26Assign%3B${password}@10.0.0.8:1080)`, '(10.0.0.8:1080)'],
    [`socks5://alice%26colon%3Bhunter2@my-proxy:7890`, 'socks5://my-proxy:7890'],
    [`via user%26%2358%3B${password} proxy@10.1.1.1:8080 failed`, 'via 10.1.1.1:8080 failed'],
    [`user${colon}${password}/token@my-proxy:7890`, 'my-proxy:7890'],
    [`http://example.com/?x=user%26colon%3B${password}@10.0.0.8:1080`, 'http://example.com/?x=10.0.0.8:1080'],
    [`user:${password}@my-proxy%26%2358%3B7890`, 'my-proxy:7890'],
    [`user:${password}@127%26%2346%3B0%26%2346%3B0%26%2346%3B1:7890`, '127.0.0.1:7890'],
    [`user:${password}@127%26bull%3B0%26sdot%3B0%26period%3B1:7890`, '127\u20220\u22C50.1:7890'],
    [`user%26percnt%3B3A${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user%26%2337%3B3A${password}@my-proxy:7890`, 'my-proxy:7890'],
    [`user:${password}%26%2364%3B127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user:${password}%26%23x40%3Bmy-proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my-proxy:%26sup2%3B%26sup3%3B%26sup1%3B%26sup2%3B`, 'my-proxy:\u00B2\u00B3\u00B9\u00B2'],
    [`note %26Assign%3Buser:${password}@10.1:8080`, 'note \u225410.1:8080'],
    [`two user${colon}${password}@my-proxy:7890) and user%26colon%3Bother-secret@10.1:8080.`, 'two my-proxy:7890) and 10.1:8080.'],
    [`invalid proxy url "http://user%26%2358%3Bs3cret/token@my-proxy:7890": invalid port "%26%2358%3Bs3cret" after host`, 'invalid proxy url "http://my-proxy:7890": invalid port ":[凭据已隐藏]" after host'],
    [`a=1&user%26colon%3B${password}@my-proxy:7890&b=2`, 'a=1&my-proxy:7890&b=2']
  ];
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  const unchanged = [
    'Build v1%26%2358%3B2@beta',
    `user%26colon%3B${password}@internal`,
    `user%26%2337%3B3A${password}@internal`,
    'score 1%26%2337%3B3A2@10.5',
    'note 100%26%2337%3B off',
    'member%26commat%3Bexample.test',
    'http://user%26%2340%3B127.0.0.1:7890',
    'user%26colons3cret@127.0.0.1:7890',
    'see %26bull%3B later',
    'note %26amp off',
    'http://user@127.0.0.1:7890'
  ];
  for (const input of unchanged) assert.equal(redactPublic(input), input);
  const proxy = `http://user%26%2358%3B${password}@127.0.0.1:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note user%26Assign%3B${password}@my-proxy:7890`, email: 'a@example.test', last_error: `dial user:${password}%26%2364%3B127.0.0.1:7890 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my-proxy:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial 127.0.0.1:7890 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by an encoded HTML reference body', () => {
  const password = 's3cret-token';
  const body = value => value.split('').map(char => `%${char.charCodeAt(0).toString(16).toUpperCase()}`).join('');
  const nest = (value, layers) => {
    let out = value;
    for (let layer = 0; layer < layers; layer += 1) out = out.replace(/%/g, '%25');
    return out;
  };
  const colon = body('&#58;');
  const sign = String.fromCodePoint(0x1D108);
  const cases = [
    [`user${colon}${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user${body('&#x3A;')}${password}@my-proxy:7890`, 'my-proxy:7890'],
    [`user${body('&#X3a;')}${password}@10.0.0.8:1080`, '10.0.0.8:1080'],
    [`user${body('&#00058;')}${password}@127.1:7890`, '127.1:7890'],
    [`user${body('&#58')}${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user${body('&colon;')}${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user${body('&Assign;')}${password}@my-proxy:7890`, 'my-proxy:7890'],
    [`user%26%23x%33%41%3B${password}@my-proxy:7890`, 'my-proxy:7890'],
    [`user%26%235%38%3B${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user&co%6Con;${password}@10.0.0.8:1080`, '10.0.0.8:1080'],
    [`user${nest(colon, 1)}${password}@127.1:7890`, '127.1:7890'],
    [`user${nest(colon, 3).toLowerCase()}${password}@[::1]:8792`, '[::1]:8792'],
    [`user%2526%23%2535%38%253B${password}@10.0.0.8:1080`, '10.0.0.8:1080'],
    [`http://user${colon}${password}${body('&#64;')}127.0.0.1:7890/x`, 'http://127.0.0.1:7890/x'],
    [`http://user${body('&colon;')}${password}${body('&commat;')}127.0.0.1:7890`, 'http://127.0.0.1:7890'],
    [`(user${body('&Assign;')}${password}@10.0.0.8:1080)`, '(10.0.0.8:1080)'],
    [`socks5://alice${body('&colon;')}hunter2@my-proxy:7890`, 'socks5://my-proxy:7890'],
    [`via user${colon}${password} proxy@10.1.1.1:8080 failed`, 'via 10.1.1.1:8080 failed'],
    [`user${colon}${password}/token@my-proxy:7890`, 'my-proxy:7890'],
    [`http://example.com/?x=user${body('&colon;')}${password}@10.0.0.8:1080`, 'http://example.com/?x=10.0.0.8:1080'],
    [`user:${password}@127${body('&#46;')}0${body('&#46;')}0${body('&#46;')}1:7890`, '127.0.0.1:7890'],
    [`user:${password}@my-proxy:${body('&#55;')}${body('&#56;')}${body('&#57;')}${body('&#48;')}`, 'my-proxy:7890'],
    [`user:${password}@my-proxy:${body('&#xFF17;&#xFF18;&#xFF19;&#xFF10;')}`, 'my-proxy:\uFF17\uFF18\uFF19\uFF10'],
    [`user${body('&percnt;')}3A${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user${body('&amp;colon;')}${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user${body('&amp;amp;amp;colon;')}${password}@my-proxy:7890`, 'my-proxy:7890'],
    [`http://user${body(`&#${sign.codePointAt(0)};`)}${password}@127.0.0.1:7890`, 'http://127.0.0.1:7890'],
    [`note ${colon}user:${password}@10.1:8080`, 'note :10.1:8080'],
    [`two user${colon}${password}@my-proxy:7890) and user${body('&colon;')}other-secret@10.1:8080.`, 'two my-proxy:7890) and 10.1:8080.'],
    [`invalid proxy url "http://user${colon}s3cret/token@my-proxy:7890": invalid port "${colon}s3cret" after host`, 'invalid proxy url "http://my-proxy:7890": invalid port ":[凭据已隐藏]" after host'],
    [`a=1&user${body('&Assign;')}${password}@127${body('&sdot;')}0${body('&sdot;')}0${body('&sdot;')}1:7890&b=2`, 'a=1&127\u22C50\u22C50\u22C51:7890&b=2'],
    [`user:${password}@my-proxy:7890%26next`, 'my-proxy:7890%26next']
  ];
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  const unchanged = [
    `Build v1${colon}2@beta`,
    `user${colon}${password}@internal`,
    `user${body('&percnt;')}3A${password}@internal`,
    'score 1%26%23%35%38%3B2@10.5',
    `member${body('&commat;')}example.test`,
    `http://user${body('&#64;')}127.0.0.1:7890`,
    'user&co%6Cons3cret@127.0.0.1:7890',
    'see %26%23%36%35%3B later',
    'note %26amp off',
    'http://user@127.0.0.1:7890'
  ];
  for (const input of unchanged) assert.equal(redactPublic(input), input);
  const proxy = `http://user${colon}${password}@127.0.0.1:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: true, usage_probe: false },
    accounts: [{ id: 'acc-1', name: `note user${body('&Assign;')}${password}@my-proxy:7890`, email: 'a@example.test', last_error: `dial user:${password}${body('&#64;')}127.0.0.1:7890 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my-proxy:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial 127.0.0.1:7890 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by an invisible mark', () => {
  const password = 's3cret-token';
  const vs = String.fromCodePoint(0xE0100);
  const cases = [
    [`user:${password}@my\u200Bproxy:7890`, 'my\u200Bproxy:7890'],
    [`user:${password}@my\u200Cproxy:7890`, 'my\u200Cproxy:7890'],
    [`user:${password}@my\u2060proxy:7890`, 'my\u2060proxy:7890'],
    [`user:${password}@my\u00ADproxy:7890`, 'my\u00ADproxy:7890'],
    [`user:${password}@my\u202Eproxy:7890`, 'my\u202Eproxy:7890'],
    [`user:${password}@my\uFEFFproxy:7890`, 'my\uFEFFproxy:7890'],
    [`user:${password}@my${vs}proxy:7890`, 'my\u200Bproxy:7890'],
    [`user:${password}@127.0\u200B.0.1:7890`, '127.0\u200B.0.1:7890'],
    [`user:${password}@127\u200B.0.0.1:7890`, '127\u200B.0.0.1:7890'],
    [`user:${password}@\u200B127.0.0.1:7890`, '\u200B127.0.0.1:7890'],
    [`user:${password}@127.0.0.1\uFEFF:7890`, '127.0.0.1\uFEFF:7890'],
    [`user:${password}@my-proxy:78\u200B90`, 'my-proxy:78\u200B90'],
    [`user:${password}@my-proxy:7890\u200Bnext`, 'my-proxy:7890\u200Bnext'],
    [`user:${password}@my-proxy:7890\uFEFFnext`, 'my-proxy:7890\uFEFFnext'],
    [`http://user:${password}@ex\u200Bample.com:8080/x`, 'http://ex\u200Bample.com:8080/x'],
    [`(user:${password}@10.0.0.8\u200B:1080)`, '(10.0.0.8\u200B:1080)'],
    [`socks5://alice\u200B:hunter2@my-proxy:7890`, 'socks5://my-proxy:7890'],
    [`via user:${password}\u200B proxy@10.1.1.1:8080 failed`, 'via 10.1.1.1:8080 failed'],
    [`user&#5\u200B8;${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user&#5\uFEFF8;${password}@my-proxy:7890`, 'my-proxy:7890'],
    [`note\u200B user:${password}@my\u200Bproxy:7890`, 'note\u200B my\u200Bproxy:7890'],
    [`two user:${password}@my\u200Bproxy:7890) and user:other-secret@10.1:8080.`, 'two my\u200Bproxy:7890) and 10.1:8080.']
  ];
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  const unchanged = [
    `user:${password}@internal\u200B`,
    `user:${password}@10.1\u200B`,
    `Build v1:2@be\u200Bta`,
    'note\u200B later',
    'http://user@127.0.0.1:7890'
  ];
  for (const input of unchanged) assert.equal(redactPublic(input), input);
  const proxy = `http://user:${password}@127.0.0.1\u200B:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note user:${password}@my\u200Bproxy:7890`, email: 'a@example.test', last_error: `dial user:${password}@\uFEFF127.0.0.1:7890 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my\u200Bproxy:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial \uFEFF127.0.0.1:7890 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by an encoded invisible mark', () => {
  const password = 's3cret-token';
  const mark = '%E2%80%8B';
  const nest = (value, layers) => {
    let out = value;
    for (let layer = 0; layer < layers; layer += 1) out = out.replace(/%/g, '%25');
    return out;
  };
  const vs = '%F3%A0%84%80';
  const cases = [
    [`user:${password}@my${mark}proxy:7890`, 'my\u200Bproxy:7890'],
    [`user:${password}@my${mark.toLowerCase()}proxy:7890`, 'my\u200Bproxy:7890'],
    [`user:${password}@my${nest(mark, 1)}proxy:7890`, 'my\u200Bproxy:7890'],
    [`user:${password}@my${nest(mark, 3)}proxy:7890`, 'my\u200Bproxy:7890'],
    [`user:${password}@my%E2%2580%8Bproxy:7890`, 'my\u200Bproxy:7890'],
    [`user:${password}@my%C2%ADproxy:7890`, 'my\u00ADproxy:7890'],
    [`user:${password}@my%EF%BB%BFproxy:7890`, 'my\uFEFFproxy:7890'],
    [`user:${password}@my${vs}proxy:7890`, 'my\u200Bproxy:7890'],
    [`user:${password}@127${mark}.0.0.1:7890`, '127\u200B.0.0.1:7890'],
    [`user:${password}@127.0.0.1${mark}:7890`, '127.0.0.1\u200B:7890'],
    [`user:${password}@my-proxy:78${mark}90`, 'my-proxy:78\u200B90'],
    [`user:${password}@my-proxy:7890${mark}next`, 'my-proxy:7890\u200Bnext'],
    [`user:${password}@my-proxy%3A${mark}7890`, 'my-proxy%3A\u200B7890'],
    [`user:${password}@my-proxy:${mark}7890`, 'my-proxy:\u200B7890'],
    [`user:${password}@10.1:${mark}8080`, '10.1:\u200B8080'],
    [`user:${password}@my-proxy:${mark}7${mark}890`, 'my-proxy:\u200B7\u200B890'],
    [`user:${password}@local${mark}host:7890`, 'local\u200Bhost:7890'],
    [`user:${password}@[${mark}::1]:8792`, '[\u200B::1]:8792'],
    [`http://user:${password}@ex${mark}ample.com:8080/x`, 'http://ex\u200Bample.com:8080/x'],
    [`(user:${password}@10.0.0.8${mark}:1080)`, '(10.0.0.8\u200B:1080)'],
    [`socks5://alice%C2%AD:hunter2@my-proxy:7890`, 'socks5://my-proxy:7890'],
    [`via user:${password}${mark} proxy@10.1.1.1:8080 failed`, 'via 10.1.1.1:8080 failed'],
    [`user&#5${mark}8;${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user%26%235${mark}8%3B${password}@my-proxy:7890`, 'my-proxy:7890'],
    [`a=1&user:${password}@my${mark}proxy:7890&b=2`, 'a=1&my\u200Bproxy:7890&b=2'],
    [`see %C2%AD later user:${password}@127.0.0.1:7890`, 'see \u00AD later 127.0.0.1:7890'],
    [`two user:${password}@my${mark}proxy:7890) and user:other-secret@10.1:8080.`, 'two my\u200Bproxy:7890) and 10.1:8080.'],
    [`invalid proxy url "http://user:s3cret/token@my${mark}proxy:7890": invalid port ":s3cret" after host`, 'invalid proxy url "http://my\u200Bproxy:7890": invalid port ":[凭据已隐藏]" after host'],
    [`user:${password}@my-proxy:7890%E2%80%A2next`, 'my-proxy:7890%E2%80%A2next']
  ];
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  const unchanged = [
    `Build v1:2@be${mark}ta`,
    `user:${password}@internal${mark}`,
    `user:${password}@10.1${mark}`,
    `user:${password}@my${mark}proxy`,
    `score 1:2@10${mark}.5`,
    `note ${mark} later`,
    'http://user@127.0.0.1:7890'
  ];
  for (const input of unchanged) assert.equal(redactPublic(input), input);
  const proxy = `http://user:${password}@127.0.0.1${mark}:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note user:${password}@my${mark}proxy:7890`, email: 'a@example.test', last_error: `dial user:${password}@${mark}127.0.0.1:7890 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my\u200Bproxy:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial \u200B127.0.0.1:7890 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by an HTML reference to an invisible mark', () => {
  const password = 's3cret-token';
  const body = value => value.split('').map(char => `%${char.charCodeAt(0).toString(16).toUpperCase()}`).join('');
  const vs = '&#xE0100;';
  const cases = [
    [`user:${password}@my&#8203;proxy:7890`, 'my\u200Bproxy:7890'],
    [`user:${password}@my&#x200B;proxy:7890`, 'my\u200Bproxy:7890'],
    [`user:${password}@my&#x200b;proxy:7890`, 'my\u200Bproxy:7890'],
    [`user:${password}@my&#X200B;proxy:7890`, 'my\u200Bproxy:7890'],
    [`user:${password}@my&#008203;proxy:7890`, 'my\u200Bproxy:7890'],
    [`user:${password}@my&#8203proxy:7890`, 'my\u200Bproxy:7890'],
    [`user:${password}@my&#xFEFF;proxy:7890`, 'my\uFEFFproxy:7890'],
    [`user:${password}@my${vs}proxy:7890`, 'my\u200Bproxy:7890'],
    [`user:${password}@127&#8203;.0.0.1:7890`, '127\u200B.0.0.1:7890'],
    [`user:${password}@my-proxy:&#8203;7890`, 'my-proxy:\u200B7890'],
    [`user:${password}@10.1:&#x200B;8080`, '10.1:\u200B8080'],
    [`user:${password}@my-proxy:7890&#8203;next`, 'my-proxy:7890\u200Bnext'],
    [`user:${password}@local&#8203;host:7890`, 'local\u200Bhost:7890'],
    [`user:${password}@[&#8203;::1]:8792`, '[\u200B::1]:8792'],
    [`http://user:${password}@ex&#8203;ample.com:8080/x`, 'http://ex\u200Bample.com:8080/x'],
    [`(user:${password}@10.0.0.8&#x200B;:1080)`, '(10.0.0.8\u200B:1080)'],
    [`socks5://alice&#8203;:hunter2@my-proxy:7890`, 'socks5://my-proxy:7890'],
    [`via user:${password}&#8203; proxy@10.1.1.1:8080 failed`, 'via 10.1.1.1:8080 failed'],
    [`user%26%238203%3B:${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user${body('&#x200B;')}:${password}@my-proxy:7890`, 'my-proxy:7890'],
    [`user&#5&#8203;8;${password}@10.0.0.8:1080`, '10.0.0.8:1080'],
    [`a=1&user:${password}@my&#8203;proxy:7890&b=2`, 'a=1&my\u200Bproxy:7890&b=2'],
    [`see &#8203; later user:${password}@127.0.0.1:7890`, 'see \u200B later 127.0.0.1:7890'],
    [`two user:${password}@my&#8203;proxy:7890) and user:other-secret@10.1:8080.`, 'two my\u200Bproxy:7890) and 10.1:8080.'],
    [`invalid proxy url "http://user:s3cret/token@my&#8203;proxy:7890": invalid port ":s3cret" after host`, 'invalid proxy url "http://my\u200Bproxy:7890": invalid port ":[凭据已隐藏]" after host']
  ];
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  const unchanged = [
    `Build v1&#8203;:2@beta`,
    `user:${password}@internal&#8203;`,
    `user:${password}@10.1&#8203;`,
    `user:${password}@my&#8203;proxy`,
    `score 1&#8203;:2@10.5`,
    `note &#8203; later`,
    `user:${password}@my&#x200Baproxy:7890`,
    `user:${password}@my&#82030proxy:7890`,
    'http://user@127.0.0.1:7890'
  ];
  for (const input of unchanged) assert.equal(redactPublic(input), input);
  const proxy = `http://user:${password}@127.0.0.1&#8203;:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: true, usage_probe: false },
    accounts: [{ id: 'acc-1', name: `note user:${password}@my&#x200B;proxy:7890`, email: 'a@example.test', last_error: `dial user:${password}@&#8203;127.0.0.1:7890 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my\u200Bproxy:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial \u200B127.0.0.1:7890 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by an invisible mark name', () => {
  const password = 's3cret-token';
  const names = [
    ['ZeroWidthSpace', '\u200B'],
    ['zwnj', '\u200C'],
    ['zwj', '\u200D'],
    ['lrm', '\u200E'],
    ['rlm', '\u200F'],
    ['shy', '\u00AD']
  ];
  const body = value => value.split('').map(char => `%${char.charCodeAt(0).toString(16).toUpperCase()}`).join('');
  const cases = [];
  for (const [name, mark] of names) {
    cases.push([`user:${password}@my&${name};proxy:7890`, `my${mark}proxy:7890`]);
    cases.push([`user:${password}@my-proxy:&${name};7890`, `my-proxy:${mark}7890`]);
    cases.push([`user:${password}@my-proxy:7890&${name};next`, `my-proxy:7890${mark}next`]);
  }
  cases.push(
    [`user:${password}@127&ZeroWidthSpace;.0.0.1:7890`, '127\u200B.0.0.1:7890'],
    [`http://user:${password}@ex&zwnj;ample.com:8080/x`, 'http://ex\u200Cample.com:8080/x'],
    [`(user:${password}@10.0.0.8&zwj;:1080)`, '(10.0.0.8\u200D:1080)'],
    [`socks5://alice&shy;:hunter2@my-proxy:7890`, 'socks5://my-proxy:7890'],
    [`via user:${password}&lrm; proxy@10.1.1.1:8080 failed`, 'via 10.1.1.1:8080 failed'],
    [`user%26ZeroWidthSpace%3B:${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user${body('&shy;')}:${password}@my-proxy:7890`, 'my-proxy:7890'],
    [`a=1&user:${password}@my&rlm;proxy:7890&b=2`, 'a=1&my\u200Fproxy:7890&b=2'],
    [`see &shy; later user:${password}@127.0.0.1:7890`, 'see \u00AD later 127.0.0.1:7890'],
    [`two user:${password}@my&ZeroWidthSpace;proxy:7890) and user:other-secret@10.1:8080.`, 'two my\u200Bproxy:7890) and 10.1:8080.'],
    [`invalid proxy url "http://user:s3cret/token@my&shy;proxy:7890": invalid port ":s3cret" after host`, 'invalid proxy url "http://my\u00ADproxy:7890": invalid port ":[凭据已隐藏]" after host']
  );
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  const unchanged = [
    `Build v1&shy;:2@beta`,
    `user:${password}@internal&ZeroWidthSpace;`,
    `user:${password}@10.1&zwnj;`,
    `user:${password}@my&zwj;proxy`,
    `note &lrm; later`,
    `user:${password}@my&ZeroWidthSpaceproxy:7890`,
    `user:${password}@my&shyproxy:7890`,
    'http://user@127.0.0.1:7890'
  ];
  for (const input of unchanged) assert.equal(redactPublic(input), input);
  const proxy = `http://user:${password}@127.0.0.1&ZeroWidthSpace;:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note user:${password}@my&shy;proxy:7890`, email: 'a@example.test', last_error: `dial user:${password}@&zwnj;127.0.0.1:7890 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my\u00ADproxy:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial \u200C127.0.0.1:7890 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by the remaining invisible mark names', () => {
  const password = 's3cret-token';
  const names = [
    ['NoBreak', '\u2060'],
    ['ApplyFunction', '\u2061'],
    ['af', '\u2061'],
    ['InvisibleTimes', '\u2062'],
    ['it', '\u2062'],
    ['InvisibleComma', '\u2063'],
    ['ic', '\u2063'],
    ['NegativeMediumSpace', '\u200B'],
    ['NegativeThickSpace', '\u200B'],
    ['NegativeThinSpace', '\u200B'],
    ['NegativeVeryThinSpace', '\u200B']
  ];
  const body = value => value.split('').map(char => `%${char.charCodeAt(0).toString(16).toUpperCase()}`).join('');
  const cases = [];
  for (const [name, mark] of names) {
    cases.push([`user:${password}@my&${name};proxy:7890`, `my${mark}proxy:7890`]);
    cases.push([`user:${password}@my-proxy:&${name};7890`, `my-proxy:${mark}7890`]);
    cases.push([`user:${password}@my-proxy:7890&${name};next`, `my-proxy:7890${mark}next`]);
  }
  cases.push(
    [`user:${password}@127&NoBreak;.0.0.1:7890`, '127\u2060.0.0.1:7890'],
    [`http://user:${password}@ex&it;ample.com:8080/x`, 'http://ex\u2062ample.com:8080/x'],
    [`(user:${password}@10.0.0.8&ic;:1080)`, '(10.0.0.8\u2063:1080)'],
    [`socks5://alice&af;:hunter2@my-proxy:7890`, 'socks5://my-proxy:7890'],
    [`via user:${password}&ApplyFunction; proxy@10.1.1.1:8080 failed`, 'via 10.1.1.1:8080 failed'],
    [`user%26NoBreak%3B:${password}@127.0.0.1:7890`, '127.0.0.1:7890'],
    [`user${body('&InvisibleComma;')}:${password}@my-proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&amp;NegativeThinSpace;proxy:7890`, 'my\u200Bproxy:7890'],
    [`a=1&user:${password}@my&NegativeMediumSpace;proxy:7890&b=2`, 'a=1&my\u200Bproxy:7890&b=2'],
    [`see &it; later user:${password}@127.0.0.1:7890`, 'see \u2062 later 127.0.0.1:7890'],
    [`two user:${password}@my&NoBreak;proxy:7890) and user:other-secret@10.1:8080.`, 'two my\u2060proxy:7890) and 10.1:8080.'],
    [`invalid proxy url "http://user:s3cret/token@my&af;proxy:7890": invalid port ":s3cret" after host`, 'invalid proxy url "http://my\u2061proxy:7890": invalid port ":[凭据已隐藏]" after host'],
    [`user:${password}@my&shy-proxy:7890`, 'my\u00AD-proxy:7890'],
    [`user:${password}@127&shy.0.0.1:7890`, '127\u00AD.0.0.1:7890'],
    [`user:${password}@my-proxy:7890&shy-next`, 'my-proxy:7890\u00AD-next'],
    [`user:${password}@my-proxy:7890&shy/next`, 'my-proxy:7890\u00AD/next'],
    [`http://user:${password}@ex&shy-ample.com:8080/x`, 'http://ex\u00AD-ample.com:8080/x'],
    [`(user:${password}@my&shy-proxy:7890)`, '(my\u00AD-proxy:7890)'],
    [`user%26shy-:${password}@10.1:8080`, '10.1:8080'],
    [`user:${password}@my%26shy-proxy:7890`, 'my\u00AD-proxy:7890'],
    [`user:${password}@my${body('&shy')}-proxy:7890`, 'my\u00AD-proxy:7890'],
    [`user:${password}@my&#38;shy-proxy:7890`, 'my\u00AD-proxy:7890'],
    [`user:${password}@my&amp;shy-proxy:7890`, 'my\u00AD-proxy:7890'],
    [`two user:${password}@my&shy-proxy:7890) and user:other-secret@10.1:8080.`, 'two my\u00AD-proxy:7890) and 10.1:8080.']
  );
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('hunter2'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  const unchanged = [
    `Build v1&NoBreak;:2@beta`,
    `user:${password}@internal&it;`,
    `user:${password}@10.1&ic;`,
    `user:${password}@my&af;proxy`,
    `note &ApplyFunction; later`,
    `user:${password}@my&NoBreakproxy:7890`,
    `user:${password}@my&itproxy:7890`,
    `user:${password}@my&shyproxy:7890`,
    `user:${password}@my-proxy:&shy7890`,
    `user:${password}@my&shy=proxy:7890`,
    `user:${password}@my&IT;proxy:7890`,
    'http://user@127.0.0.1:7890'
  ];
  for (const input of unchanged) assert.equal(redactPublic(input), input);
  const proxy = `http://user:${password}@127.0.0.1&NoBreak;:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: true, usage_probe: false },
    accounts: [{ id: 'acc-1', name: `note user:${password}@my&shy-proxy:7890`, email: 'a@example.test', last_error: `dial user:${password}@&NegativeVeryThinSpace;127.0.0.1:7890 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my\u00AD-proxy:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial \u200B127.0.0.1:7890 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords when a host hyphen or underscore is encoded', () => {
  const password = 's3cret-token';
  const nest = (token, extra) => {
    let out = token;
    for (let layer = 0; layer < extra; layer += 1) out = out.replace(/%/g, '%25');
    return out;
  };
  const cases = [
    [`user:${password}@my%2Dproxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my%2dproxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest('%2D', 1)}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest('%2D', 3)}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my%2D%2Dproxy:7890`, 'my--proxy:7890'],
    [`user:${password}@ex%2Dample.com`, 'ex-ample.com'],
    [`user:${password}@ex%2Dample.com:8080`, 'ex-ample.com:8080'],
    [`user:${password}@ex${nest('%2D', 1)}ample.com:8080/x`, 'ex-ample.com:8080/x'],
    [`http://user:${password}@ex%2Dample.com:8080/x`, 'http://ex-ample.com:8080/x'],
    [`http://us%2Der:${password}@ex-ample.com:8080/x`, 'http://ex-ample.com:8080/x'],
    [`(user:${password}@my%2Dproxy:7890)`, '(my-proxy:7890)'],
    [`a=1&user:${password}@my%2Dproxy:7890&b=2`, 'a=1&my-proxy:7890&b=2'],
    [`user:${password}@my%5Fproxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my%5fproxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my${nest('%5F', 1)}proxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my${nest('%5F', 3)}proxy:7890`, 'my_proxy:7890'],
    [`socks5://alice:${password}@my%5Fproxy:7890`, 'socks5://my_proxy:7890'],
    [`note %2D later user:${password}@10.1:8080`, 'note - later 10.1:8080'],
    [`two user:${password}@my%2Dproxy:7890) and user:other-secret@10.1:8080.`, 'two my-proxy:7890) and 10.1:8080.'],
    [`invalid proxy url "http://user:s3cret/token@my%2Dproxy:7890": invalid port ":s3cret" after host`, 'invalid proxy url "http://my-proxy:7890": invalid port ":[凭据已隐藏]" after host']
  ];
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  const unchanged = [
    `Build v1%2D2@beta`,
    `file%2Dname.txt`,
    `score 1%2D2@10.5`,
    `version%2D1:2@host`,
    `user:${password}@my%2Dproxy`,
    `user:${password}@my%5Fproxy`,
    `user:${password}@10%2D1:8080`,
    `ex%2Dample.com`,
    'http://user@127.0.0.1:7890'
  ];
  for (const input of unchanged) assert.equal(redactPublic(input), input);
  const proxy = `http://user:${password}@127.0.0.1:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note user:${password}@my%2Dproxy:7890`, email: 'a@example.test', last_error: `dial user:${password}@my%5Fproxy:7890 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my-proxy:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial my_proxy:7890 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by a hyphen-minus lookalike', () => {
  const password = 's3cret-token';
  const full = '\uFF0D';
  const small = '\uFE63';
  const nest = (token, extra) => {
    let out = token;
    for (let layer = 0; layer < extra; layer += 1) out = out.replace(/%/g, '%25');
    return out;
  };
  const fullEnc = encodeURIComponent(full);
  const smallEnc = encodeURIComponent(small);
  const cases = [
    [`user:${password}@my${full}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${small}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@ex${full}ample.com:8080`, 'ex-ample.com:8080'],
    [`user:${password}@ex${small}ample.com`, 'ex-ample.com'],
    [`http://user:${password}@ex${full}ample.com:8080/x`, 'http://ex-ample.com:8080/x'],
    [`(user:${password}@my${full}proxy:7890)`, '(my-proxy:7890)'],
    [`user:${password}@my${fullEnc}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${fullEnc.toLowerCase()}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest(fullEnc, 1)}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest(fullEnc, 3)}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${smallEnc}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest(smallEnc, 3)}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#65293;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#xFF0D;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#xff0d;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#65123;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#xFE63;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@ex&#xFF0D;ample.com:8080`, 'ex-ample.com:8080'],
    [`a=1&user:${password}@my${full}proxy:7890&b=2`, 'a=1&my-proxy:7890&b=2'],
    [`note ${full} later user:${password}@10.1:8080`, 'note - later 10.1:8080'],
    [`note \u2010 later user:${password}@10.1:8080`, 'note - later 10.1:8080'],
    [`two user:${password}@my${full}proxy:7890) and user:other-secret@10.1:8080.`, 'two my-proxy:7890) and 10.1:8080.']
  ];
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  const unchanged = [
    `Build v1${full}2@beta`,
    `file${small}name.txt`,
    `user:${password}@my${full}proxy`,
    'http://user@127.0.0.1:7890'
  ];
  for (const input of unchanged) assert.equal(redactPublic(input), input);
  const proxy = `http://user:${password}@127.0.0.1:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: true, usage_probe: false },
    accounts: [{ id: 'acc-1', name: `note user:${password}@my${full}proxy:7890`, email: 'a@example.test', last_error: `dial user:${password}@ex${small}ample.com:8080 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my-proxy:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial ex-ample.com:8080 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by a hyphen or dash name', () => {
  const password = 's3cret-token';
  const hyphen = '\u2010';
  const nest = (token, extra) => {
    let out = token;
    for (let layer = 0; layer < extra; layer += 1) out = out.replace(/%/g, '%25');
    return out;
  };
  const body = value => value.split('').map(char => `%${char.charCodeAt(0).toString(16).toUpperCase()}`).join('');
  const encoded = encodeURIComponent(hyphen);
  const cases = [
    [`user:${password}@my${hyphen}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@ex${hyphen}ample.com:8080`, 'ex-ample.com:8080'],
    [`user:${password}@ex${hyphen}ample.com`, 'ex-ample.com'],
    [`user:${password}@my${hyphen}${hyphen}proxy:7890`, 'my--proxy:7890'],
    [`http://user:${password}@ex${hyphen}ample.com:8080/x`, 'http://ex-ample.com:8080/x'],
    [`http://us${hyphen}er:${password}@ex-ample.com:8080/x`, 'http://ex-ample.com:8080/x'],
    [`(user:${password}@my${hyphen}proxy:7890)`, '(my-proxy:7890)'],
    [`user:${password}@my${encoded}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${encoded.toLowerCase()}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest(encoded, 1)}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest(encoded, 3)}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&hyphen;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&dash;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@ex&hyphen;ample.com:8080`, 'ex-ample.com:8080'],
    [`user:${password}@ex&dash;ample.com`, 'ex-ample.com'],
    [`user:${password}@my&#8208;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#x2010;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#x2010proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#X2010;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#008208;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&amp;hyphen;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#38;dash;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my%26hyphen%3Bproxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my%26dash%3bproxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest('%26hyphen%3B', 1)}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${body('&hyphen;')}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${body('&dash;')}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest(body('&hyphen;'), 3)}proxy:7890`, 'my-proxy:7890'],
    [`http://user:${password}@ex&hyphen;ample.com:8080/x`, 'http://ex-ample.com:8080/x'],
    [`a=1&user:${password}@my&hyphen;proxy:7890&b=2`, 'a=1&my-proxy:7890&b=2'],
    [`note &dash; later user:${password}@10.1:8080`, 'note - later 10.1:8080'],
    [`note ${hyphen} later user:${password}@10.1:8080`, 'note - later 10.1:8080'],
    [`two user:${password}@my&hyphen;proxy:7890) and user:other-secret@10.1:8080.`, 'two my-proxy:7890) and 10.1:8080.'],
    [`invalid proxy url "http://user:s3cret/token@my&dash;proxy:7890": invalid port ":s3cret" after host`, 'invalid proxy url "http://my-proxy:7890": invalid port ":[凭据已隐藏]" after host']
  ];
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  const unchanged = [
    `Build v1${hyphen}2@beta`,
    `Build v1&hyphen;2@beta`,
    `file${hyphen}name.txt`,
    `score 1&dash;2@10.5`,
    `user:${password}@my${hyphen}proxy`,
    `user:${password}@my&hyphen;proxy`,
    `user:${password}@my&dash;proxy`,
    `user:${password}@my&hyphenproxy:7890`,
    `user:${password}@my&dashproxy:7890`,
    `user:${password}@my&Hyphen;proxy:7890`,
    `user:${password}@my&DASH;proxy:7890`,
    `note &hyphen; later`,
    'http://user@127.0.0.1:7890'
  ];
  for (const input of unchanged) assert.equal(redactPublic(input), input);
  const proxy = `http://user:${password}@my&hyphen;proxy:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: true, usage_probe: false },
    accounts: [{ id: 'acc-1', name: `note user:${password}@my&hyphen;proxy:7890`, email: 'a@example.test', last_error: `dial user:${password}@ex&dash;ample.com:8080 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my-proxy:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial ex-ample.com:8080 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by a non-breaking hyphen', () => {
  const password = 's3cret-token';
  const hyphen = '\u2011';
  const nest = (token, extra) => {
    let out = token;
    for (let layer = 0; layer < extra; layer += 1) out = out.replace(/%/g, '%25');
    return out;
  };
  const body = value => value.split('').map(char => `%${char.charCodeAt(0).toString(16).toUpperCase()}`).join('');
  const encoded = encodeURIComponent(hyphen);
  const cases = [
    [`user:${password}@my${hyphen}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@ex${hyphen}ample.com:8080`, 'ex-ample.com:8080'],
    [`user:${password}@ex${hyphen}ample.com`, 'ex-ample.com'],
    [`user:${password}@my${hyphen}${hyphen}proxy:7890`, 'my--proxy:7890'],
    [`http://user:${password}@ex${hyphen}ample.com:8080/x`, 'http://ex-ample.com:8080/x'],
    [`http://us${hyphen}er:${password}@ex-ample.com:8080/x`, 'http://ex-ample.com:8080/x'],
    [`(user:${password}@my${hyphen}proxy:7890)`, '(my-proxy:7890)'],
    [`user:${password}@my${encoded}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${encoded.toLowerCase()}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest(encoded, 1)}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest(encoded, 3)}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#8209;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#x2011;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#x2011proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#X2011;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#008209;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&amp;#8209;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my%26%238209%3Bproxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${body('&#8209;')}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest(body('&#x2011;'), 3)}proxy:7890`, 'my-proxy:7890'],
    [`a=1&user:${password}@my${hyphen}proxy:7890&b=2`, 'a=1&my-proxy:7890&b=2'],
    [`note ${hyphen} later user:${password}@10.1:8080`, 'note - later 10.1:8080'],
    [`two user:${password}@my${hyphen}proxy:7890) and user:other-secret@10.1:8080.`, 'two my-proxy:7890) and 10.1:8080.'],
    [`invalid proxy url "http://user:s3cret/token@my${hyphen}proxy:7890": invalid port ":s3cret" after host`, 'invalid proxy url "http://my-proxy:7890": invalid port ":[凭据已隐藏]" after host']
  ];
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  const unchanged = [
    `Build v1${hyphen}2@beta`,
    `file${hyphen}name.txt`,
    `user:${password}@my${hyphen}proxy`,
    `note ${hyphen} later`,
    'http://user@127.0.0.1:7890'
  ];
  for (const input of unchanged) assert.equal(redactPublic(input), input);
  const proxy = `http://user:${password}@my${hyphen}proxy:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note user:${password}@my${hyphen}proxy:7890`, email: 'a@example.test', last_error: `dial user:${password}@ex${hyphen}ample.com:8080 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my-proxy:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial ex-ample.com:8080 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by a figure dash', () => {
  const password = 's3cret-token';
  const hyphen = '\u2012';
  const nest = (token, extra) => {
    let out = token;
    for (let layer = 0; layer < extra; layer += 1) out = out.replace(/%/g, '%25');
    return out;
  };
  const body = value => value.split('').map(char => `%${char.charCodeAt(0).toString(16).toUpperCase()}`).join('');
  const encoded = encodeURIComponent(hyphen);
  const cases = [
    [`user:${password}@my${hyphen}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@ex${hyphen}ample.com:8080`, 'ex-ample.com:8080'],
    [`user:${password}@ex${hyphen}ample.com`, 'ex-ample.com'],
    [`user:${password}@my${hyphen}${hyphen}proxy:7890`, 'my--proxy:7890'],
    [`http://user:${password}@ex${hyphen}ample.com:8080/x`, 'http://ex-ample.com:8080/x'],
    [`http://us${hyphen}er:${password}@ex-ample.com:8080/x`, 'http://ex-ample.com:8080/x'],
    [`(user:${password}@my${hyphen}proxy:7890)`, '(my-proxy:7890)'],
    [`user:${password}@my${encoded}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${encoded.toLowerCase()}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest(encoded, 1)}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest(encoded, 3)}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#8210;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#x2012;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#x2012proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#X2012;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#008210;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&amp;#8210;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my%26%238210%3Bproxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${body('&#8210;')}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest(body('&#x2012;'), 3)}proxy:7890`, 'my-proxy:7890'],
    [`a=1&user:${password}@my${hyphen}proxy:7890&b=2`, 'a=1&my-proxy:7890&b=2'],
    [`note ${hyphen} later user:${password}@10.1:8080`, 'note - later 10.1:8080'],
    [`two user:${password}@my${hyphen}proxy:7890) and user:other-secret@10.1:8080.`, 'two my-proxy:7890) and 10.1:8080.'],
    [`invalid proxy url "http://user:s3cret/token@my${hyphen}proxy:7890": invalid port ":s3cret" after host`, 'invalid proxy url "http://my-proxy:7890": invalid port ":[凭据已隐藏]" after host']
  ];
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  const unchanged = [
    `Build v1${hyphen}2@beta`,
    `file${hyphen}name.txt`,
    `user:${password}@my${hyphen}proxy`,
    `user:${password}@10${hyphen}1:8080`,
    `note ${hyphen} later`,
    'http://user@127.0.0.1:7890'
  ];
  for (const input of unchanged) assert.equal(redactPublic(input), input);
  const proxy = `http://user:${password}@my${hyphen}proxy:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note user:${password}@my${hyphen}proxy:7890`, email: 'a@example.test', last_error: `dial user:${password}@ex${hyphen}ample.com:8080 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my-proxy:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial ex-ample.com:8080 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by an en dash', () => {
  const password = 's3cret-token';
  const hyphen = '\u2013';
  const nest = (token, extra) => {
    let out = token;
    for (let layer = 0; layer < extra; layer += 1) out = out.replace(/%/g, '%25');
    return out;
  };
  const body = value => value.split('').map(char => `%${char.charCodeAt(0).toString(16).toUpperCase()}`).join('');
  const encoded = encodeURIComponent(hyphen);
  const cases = [
    [`user:${password}@my${hyphen}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@ex${hyphen}ample.com:8080`, 'ex-ample.com:8080'],
    [`user:${password}@ex${hyphen}ample.com`, 'ex-ample.com'],
    [`user:${password}@my${hyphen}${hyphen}proxy:7890`, 'my--proxy:7890'],
    [`http://user:${password}@ex${hyphen}ample.com:8080/x`, 'http://ex-ample.com:8080/x'],
    [`http://us${hyphen}er:${password}@ex-ample.com:8080/x`, 'http://ex-ample.com:8080/x'],
    [`(user:${password}@my${hyphen}proxy:7890)`, '(my-proxy:7890)'],
    [`user:${password}@my${encoded}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${encoded.toLowerCase()}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest(encoded, 1)}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest(encoded, 3)}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&ndash;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@ex&ndash;ample.com:8080`, 'ex-ample.com:8080'],
    [`user:${password}@ex&ndash;ample.com`, 'ex-ample.com'],
    [`user:${password}@my&#8211;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#x2013;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#x2013proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#X2013;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#008211;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&amp;ndash;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#38;ndash;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my%26ndash%3Bproxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest('%26ndash%3B', 1)}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${body('&ndash;')}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest(body('&#x2013;'), 3)}proxy:7890`, 'my-proxy:7890'],
    [`http://user:${password}@ex&ndash;ample.com:8080/x`, 'http://ex-ample.com:8080/x'],
    [`a=1&user:${password}@my&ndash;proxy:7890&b=2`, 'a=1&my-proxy:7890&b=2'],
    [`note &ndash; later user:${password}@10.1:8080`, 'note - later 10.1:8080'],
    [`note ${hyphen} later user:${password}@10.1:8080`, 'note - later 10.1:8080'],
    [`two user:${password}@my&ndash;proxy:7890) and user:other-secret@10.1:8080.`, 'two my-proxy:7890) and 10.1:8080.'],
    [`invalid proxy url "http://user:s3cret/token@my&ndash;proxy:7890": invalid port ":s3cret" after host`, 'invalid proxy url "http://my-proxy:7890": invalid port ":[凭据已隐藏]" after host']
  ];
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  const unchanged = [
    `Build v1${hyphen}2@beta`,
    `Build v1&ndash;2@beta`,
    `file${hyphen}name.txt`,
    `score 1&ndash;2@10.5`,
    `user:${password}@my${hyphen}proxy`,
    `user:${password}@my&ndash;proxy`,
    `user:${password}@10${hyphen}1:8080`,
    `user:${password}@my&ndashproxy:7890`,
    `user:${password}@my&Ndash;proxy:7890`,
    `user:${password}@my&NDASH;proxy:7890`,
    `note &ndash; later`,
    'http://user@127.0.0.1:7890'
  ];
  for (const input of unchanged) assert.equal(redactPublic(input), input);
  const proxy = `http://user:${password}@my&ndash;proxy:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: true, usage_probe: false },
    accounts: [{ id: 'acc-1', name: `note user:${password}@my&ndash;proxy:7890`, email: 'a@example.test', last_error: `dial user:${password}@ex${hyphen}ample.com:8080 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my-proxy:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial ex-ample.com:8080 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by an em dash', () => {
  const password = 's3cret-token';
  const hyphen = '\u2014';
  const nest = (token, extra) => {
    let out = token;
    for (let layer = 0; layer < extra; layer += 1) out = out.replace(/%/g, '%25');
    return out;
  };
  const body = value => value.split('').map(char => `%${char.charCodeAt(0).toString(16).toUpperCase()}`).join('');
  const encoded = encodeURIComponent(hyphen);
  const cases = [
    [`user:${password}@my${hyphen}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@ex${hyphen}ample.com:8080`, 'ex-ample.com:8080'],
    [`user:${password}@ex${hyphen}ample.com`, 'ex-ample.com'],
    [`user:${password}@my${hyphen}${hyphen}proxy:7890`, 'my--proxy:7890'],
    [`http://user:${password}@ex${hyphen}ample.com:8080/x`, 'http://ex-ample.com:8080/x'],
    [`http://us${hyphen}er:${password}@ex-ample.com:8080/x`, 'http://ex-ample.com:8080/x'],
    [`(user:${password}@my${hyphen}proxy:7890)`, '(my-proxy:7890)'],
    [`user:${password}@my${encoded}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${encoded.toLowerCase()}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest(encoded, 1)}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest(encoded, 3)}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&mdash;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@ex&mdash;ample.com:8080`, 'ex-ample.com:8080'],
    [`user:${password}@ex&mdash;ample.com`, 'ex-ample.com'],
    [`user:${password}@my&#8212;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#x2014;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#x2014proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#X2014;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#008212;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&amp;mdash;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#38;mdash;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my%26mdash%3Bproxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest('%26mdash%3B', 1)}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${body('&mdash;')}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest(body('&#x2014;'), 3)}proxy:7890`, 'my-proxy:7890'],
    [`http://user:${password}@ex&mdash;ample.com:8080/x`, 'http://ex-ample.com:8080/x'],
    [`a=1&user:${password}@my&mdash;proxy:7890&b=2`, 'a=1&my-proxy:7890&b=2'],
    [`note &mdash; later user:${password}@10.1:8080`, 'note - later 10.1:8080'],
    [`note ${hyphen} later user:${password}@10.1:8080`, 'note - later 10.1:8080'],
    [`two user:${password}@my&mdash;proxy:7890) and user:other-secret@10.1:8080.`, 'two my-proxy:7890) and 10.1:8080.'],
    [`invalid proxy url "http://user:s3cret/token@my&mdash;proxy:7890": invalid port ":s3cret" after host`, 'invalid proxy url "http://my-proxy:7890": invalid port ":[凭据已隐藏]" after host']
  ];
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  const unchanged = [
    `Build v1${hyphen}2@beta`,
    `Build v1&mdash;2@beta`,
    `file${hyphen}name.txt`,
    `score 1&mdash;2@10.5`,
    `user:${password}@my${hyphen}proxy`,
    `user:${password}@my&mdash;proxy`,
    `user:${password}@10${hyphen}1:8080`,
    `user:${password}@my&mdashproxy:7890`,
    `user:${password}@my&Mdash;proxy:7890`,
    `user:${password}@my&MDASH;proxy:7890`,
    `note &mdash; later`,
    'http://user@127.0.0.1:7890'
  ];
  for (const input of unchanged) assert.equal(redactPublic(input), input);
  const proxy = `http://user:${password}@my&mdash;proxy:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note user:${password}@my&mdash;proxy:7890`, email: 'a@example.test', last_error: `dial user:${password}@ex${hyphen}ample.com:8080 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my-proxy:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial ex-ample.com:8080 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by a minus sign', () => {
  const password = 's3cret-token';
  const hyphen = '\u2212';
  const nest = (token, extra) => {
    let out = token;
    for (let layer = 0; layer < extra; layer += 1) out = out.replace(/%/g, '%25');
    return out;
  };
  const body = value => value.split('').map(char => `%${char.charCodeAt(0).toString(16).toUpperCase()}`).join('');
  const encoded = encodeURIComponent(hyphen);
  const cases = [
    [`user:${password}@my${hyphen}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@ex${hyphen}ample.com:8080`, 'ex-ample.com:8080'],
    [`user:${password}@ex${hyphen}ample.com`, 'ex-ample.com'],
    [`user:${password}@my${hyphen}${hyphen}proxy:7890`, 'my--proxy:7890'],
    [`http://user:${password}@ex${hyphen}ample.com:8080/x`, 'http://ex-ample.com:8080/x'],
    [`http://us${hyphen}er:${password}@ex-ample.com:8080/x`, 'http://ex-ample.com:8080/x'],
    [`(user:${password}@my${hyphen}proxy:7890)`, '(my-proxy:7890)'],
    [`user:${password}@my${encoded}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${encoded.toLowerCase()}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest(encoded, 1)}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest(encoded, 3)}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&minus;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@ex&minus;ample.com:8080`, 'ex-ample.com:8080'],
    [`user:${password}@ex&minus;ample.com`, 'ex-ample.com'],
    [`user:${password}@my&#8722;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#x2212;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#x2212proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#X2212;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#008722;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&amp;minus;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#38;minus;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my%26minus%3Bproxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest('%26minus%3B', 1)}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${body('&minus;')}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest(body('&#x2212;'), 3)}proxy:7890`, 'my-proxy:7890'],
    [`http://user:${password}@ex&minus;ample.com:8080/x`, 'http://ex-ample.com:8080/x'],
    [`a=1&user:${password}@my&minus;proxy:7890&b=2`, 'a=1&my-proxy:7890&b=2'],
    [`note &minus; later user:${password}@10.1:8080`, 'note - later 10.1:8080'],
    [`note ${hyphen} later user:${password}@10.1:8080`, 'note - later 10.1:8080'],
    [`two user:${password}@my&minus;proxy:7890) and user:other-secret@10.1:8080.`, 'two my-proxy:7890) and 10.1:8080.'],
    [`invalid proxy url "http://user:s3cret/token@my&minus;proxy:7890": invalid port ":s3cret" after host`, 'invalid proxy url "http://my-proxy:7890": invalid port ":[凭据已隐藏]" after host']
  ];
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  const unchanged = [
    `Build v1${hyphen}2@beta`,
    `Build v1&minus;2@beta`,
    `file${hyphen}name.txt`,
    `score 1&minus;2@10.5`,
    `user:${password}@my${hyphen}proxy`,
    `user:${password}@my&minus;proxy`,
    `user:${password}@10${hyphen}1:8080`,
    `user:${password}@my&minusproxy:7890`,
    `user:${password}@my&Minus;proxy:7890`,
    `user:${password}@my&MINUS;proxy:7890`,
    `note &minus; later`,
    'http://user@127.0.0.1:7890'
  ];
  for (const input of unchanged) assert.equal(redactPublic(input), input);
  const proxy = `http://user:${password}@my&minus;proxy:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: true, usage_probe: false },
    accounts: [{ id: 'acc-1', name: `note user:${password}@my&minus;proxy:7890`, email: 'a@example.test', last_error: `dial user:${password}@ex${hyphen}ample.com:8080 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my-proxy:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial ex-ample.com:8080 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by a horizontal bar', () => {
  const password = 's3cret-token';
  const hyphen = '\u2015';
  const nest = (token, extra) => {
    let out = token;
    for (let layer = 0; layer < extra; layer += 1) out = out.replace(/%/g, '%25');
    return out;
  };
  const body = value => value.split('').map(char => `%${char.charCodeAt(0).toString(16).toUpperCase()}`).join('');
  const encoded = encodeURIComponent(hyphen);
  const cases = [
    [`user:${password}@my${hyphen}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@ex${hyphen}ample.com:8080`, 'ex-ample.com:8080'],
    [`user:${password}@ex${hyphen}ample.com`, 'ex-ample.com'],
    [`user:${password}@my${hyphen}${hyphen}proxy:7890`, 'my--proxy:7890'],
    [`http://user:${password}@ex${hyphen}ample.com:8080/x`, 'http://ex-ample.com:8080/x'],
    [`http://us${hyphen}er:${password}@ex-ample.com:8080/x`, 'http://ex-ample.com:8080/x'],
    [`(user:${password}@my${hyphen}proxy:7890)`, '(my-proxy:7890)'],
    [`user:${password}@my${encoded}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${encoded.toLowerCase()}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest(encoded, 1)}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest(encoded, 3)}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&horbar;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@ex&horbar;ample.com:8080`, 'ex-ample.com:8080'],
    [`user:${password}@ex&horbar;ample.com`, 'ex-ample.com'],
    [`user:${password}@my&#8213;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#x2015;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#x2015proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#X2015;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#008213;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&amp;horbar;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#38;horbar;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my%26horbar%3Bproxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest('%26horbar%3B', 1)}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${body('&horbar;')}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest(body('&#x2015;'), 3)}proxy:7890`, 'my-proxy:7890'],
    [`http://user:${password}@ex&horbar;ample.com:8080/x`, 'http://ex-ample.com:8080/x'],
    [`a=1&user:${password}@my&horbar;proxy:7890&b=2`, 'a=1&my-proxy:7890&b=2'],
    [`note &horbar; later user:${password}@10.1:8080`, 'note - later 10.1:8080'],
    [`note ${hyphen} later user:${password}@10.1:8080`, 'note - later 10.1:8080'],
    [`two user:${password}@my&horbar;proxy:7890) and user:other-secret@10.1:8080.`, 'two my-proxy:7890) and 10.1:8080.'],
    [`invalid proxy url "http://user:s3cret/token@my&horbar;proxy:7890": invalid port ":s3cret" after host`, 'invalid proxy url "http://my-proxy:7890": invalid port ":[凭据已隐藏]" after host']
  ];
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  const unchanged = [
    `Build v1${hyphen}2@beta`,
    `Build v1&horbar;2@beta`,
    `file${hyphen}name.txt`,
    `score 1&horbar;2@10.5`,
    `user:${password}@my${hyphen}proxy`,
    `user:${password}@my&horbar;proxy`,
    `user:${password}@10${hyphen}1:8080`,
    `user:${password}@my&horbarproxy:7890`,
    `user:${password}@my&Horbar;proxy:7890`,
    `user:${password}@my&HORBAR;proxy:7890`,
    `note &horbar; later`,
    'http://user@127.0.0.1:7890'
  ];
  for (const input of unchanged) assert.equal(redactPublic(input), input);
  const proxy = `http://user:${password}@my&horbar;proxy:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: true, usage_probe: false },
    accounts: [{ id: 'acc-1', name: `note user:${password}@my&horbar;proxy:7890`, email: 'a@example.test', last_error: `dial user:${password}@ex${hyphen}ample.com:8080 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my-proxy:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial ex-ample.com:8080 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by a small em dash', () => {
  const password = 's3cret-token';
  const hyphen = '\uFE58';
  const nest = (token, extra) => {
    let out = token;
    for (let layer = 0; layer < extra; layer += 1) out = out.replace(/%/g, '%25');
    return out;
  };
  const body = value => value.split('').map(char => `%${char.charCodeAt(0).toString(16).toUpperCase()}`).join('');
  const encoded = encodeURIComponent(hyphen);
  const cases = [
    [`user:${password}@my${hyphen}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@ex${hyphen}ample.com:8080`, 'ex-ample.com:8080'],
    [`user:${password}@ex${hyphen}ample.com`, 'ex-ample.com'],
    [`user:${password}@my${hyphen}${hyphen}proxy:7890`, 'my--proxy:7890'],
    [`http://user:${password}@ex${hyphen}ample.com:8080/x`, 'http://ex-ample.com:8080/x'],
    [`http://us${hyphen}er:${password}@ex-ample.com:8080/x`, 'http://ex-ample.com:8080/x'],
    [`(user:${password}@my${hyphen}proxy:7890)`, '(my-proxy:7890)'],
    [`user:${password}@my${encoded}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${encoded.toLowerCase()}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest(encoded, 1)}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest(encoded, 3)}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#65112;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#xFE58;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#xFE58proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#xfe58;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#XFE58;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#065112;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&amp;#65112;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#38;#xFE58;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my%26%2365112%3Bproxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest('%26%23xFE58%3B', 1)}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${body('&#xFE58;')}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest(body('&#65112;'), 3)}proxy:7890`, 'my-proxy:7890'],
    [`http://user:${password}@ex&#xFE58;ample.com:8080/x`, 'http://ex-ample.com:8080/x'],
    [`a=1&user:${password}@my&#65112;proxy:7890&b=2`, 'a=1&my-proxy:7890&b=2'],
    [`note &#xFE58; later user:${password}@10.1:8080`, 'note - later 10.1:8080'],
    [`note ${hyphen} later user:${password}@10.1:8080`, 'note - later 10.1:8080'],
    [`two user:${password}@my&#xFE58;proxy:7890) and user:other-secret@10.1:8080.`, 'two my-proxy:7890) and 10.1:8080.'],
    [`invalid proxy url "http://user:s3cret/token@my&#65112;proxy:7890": invalid port ":s3cret" after host`, 'invalid proxy url "http://my-proxy:7890": invalid port ":[凭据已隐藏]" after host']
  ];
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  const unchanged = [
    `Build v1${hyphen}2@beta`,
    `Build v1&#65112;2@beta`,
    `file${hyphen}name.txt`,
    `score 1&#xFE58;2@10.5`,
    `user:${password}@my${hyphen}proxy`,
    `user:${password}@my&#65112;proxy`,
    `user:${password}@10${hyphen}1:8080`,
    `note ${hyphen} later`,
    'http://user@127.0.0.1:7890'
  ];
  for (const input of unchanged) assert.equal(redactPublic(input), input);
  const proxy = `http://user:${password}@my&#xFE58;proxy:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note user:${password}@my&#65112;proxy:7890`, email: 'a@example.test', last_error: `dial user:${password}@ex${hyphen}ample.com:8080 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my-proxy:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial ex-ample.com:8080 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by a vertical em dash', () => {
  const password = 's3cret-token';
  const hyphen = '\uFE31';
  const nest = (token, extra) => {
    let out = token;
    for (let layer = 0; layer < extra; layer += 1) out = out.replace(/%/g, '%25');
    return out;
  };
  const body = value => value.split('').map(char => `%${char.charCodeAt(0).toString(16).toUpperCase()}`).join('');
  const encoded = encodeURIComponent(hyphen);
  const cases = [
    [`user:${password}@my${hyphen}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@ex${hyphen}ample.com:8080`, 'ex-ample.com:8080'],
    [`user:${password}@ex${hyphen}ample.com`, 'ex-ample.com'],
    [`user:${password}@my${hyphen}${hyphen}proxy:7890`, 'my--proxy:7890'],
    [`http://user:${password}@ex${hyphen}ample.com:8080/x`, 'http://ex-ample.com:8080/x'],
    [`http://us${hyphen}er:${password}@ex-ample.com:8080/x`, 'http://ex-ample.com:8080/x'],
    [`(user:${password}@my${hyphen}proxy:7890)`, '(my-proxy:7890)'],
    [`user:${password}@my${encoded}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${encoded.toLowerCase()}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest(encoded, 1)}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest(encoded, 3)}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#65073;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#xFE31;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#xFE31proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#xfe31;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#XFE31;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#065073;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&amp;#65073;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#38;#xFE31;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my%26%2365073%3Bproxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest('%26%23xFE31%3B', 1)}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${body('&#xFE31;')}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest(body('&#65073;'), 3)}proxy:7890`, 'my-proxy:7890'],
    [`http://user:${password}@ex&#xFE31;ample.com:8080/x`, 'http://ex-ample.com:8080/x'],
    [`a=1&user:${password}@my&#65073;proxy:7890&b=2`, 'a=1&my-proxy:7890&b=2'],
    [`note &#xFE31; later user:${password}@10.1:8080`, 'note - later 10.1:8080'],
    [`note ${hyphen} later user:${password}@10.1:8080`, 'note - later 10.1:8080'],
    [`two user:${password}@my&#xFE31;proxy:7890) and user:other-secret@10.1:8080.`, 'two my-proxy:7890) and 10.1:8080.'],
    [`invalid proxy url "http://user:s3cret/token@my&#65073;proxy:7890": invalid port ":s3cret" after host`, 'invalid proxy url "http://my-proxy:7890": invalid port ":[凭据已隐藏]" after host']
  ];
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  const unchanged = [
    `Build v1${hyphen}2@beta`,
    `Build v1&#65073;2@beta`,
    `file${hyphen}name.txt`,
    `score 1&#xFE31;2@10.5`,
    `user:${password}@my${hyphen}proxy`,
    `user:${password}@my&#65073;proxy`,
    `user:${password}@10${hyphen}1:8080`,
    `note ${hyphen} later`,
    'http://user@127.0.0.1:7890'
  ];
  for (const input of unchanged) assert.equal(redactPublic(input), input);
  const proxy = `http://user:${password}@my&#xFE31;proxy:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: true, usage_probe: false },
    accounts: [{ id: 'acc-1', name: `note user:${password}@my&#65073;proxy:7890`, email: 'a@example.test', last_error: `dial user:${password}@ex${hyphen}ample.com:8080 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my-proxy:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial ex-ample.com:8080 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by a vertical en dash', () => {
  const password = 's3cret-token';
  const hyphen = '\uFE32';
  const nest = (token, extra) => {
    let out = token;
    for (let layer = 0; layer < extra; layer += 1) out = out.replace(/%/g, '%25');
    return out;
  };
  const body = value => value.split('').map(char => `%${char.charCodeAt(0).toString(16).toUpperCase()}`).join('');
  const encoded = encodeURIComponent(hyphen);
  const cases = [
    [`user:${password}@my${hyphen}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@ex${hyphen}ample.com:8080`, 'ex-ample.com:8080'],
    [`user:${password}@ex${hyphen}ample.com`, 'ex-ample.com'],
    [`user:${password}@my${hyphen}${hyphen}proxy:7890`, 'my--proxy:7890'],
    [`http://user:${password}@ex${hyphen}ample.com:8080/x`, 'http://ex-ample.com:8080/x'],
    [`http://us${hyphen}er:${password}@ex-ample.com:8080/x`, 'http://ex-ample.com:8080/x'],
    [`(user:${password}@my${hyphen}proxy:7890)`, '(my-proxy:7890)'],
    [`user:${password}@my${encoded}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${encoded.toLowerCase()}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest(encoded, 1)}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest(encoded, 3)}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#65074;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#xFE32;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#xFE32proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#xfe32;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#XFE32;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#065074;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&amp;#65074;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my&#38;#xFE32;proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my%26%2365074%3Bproxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest('%26%23xFE32%3B', 1)}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${body('&#xFE32;')}proxy:7890`, 'my-proxy:7890'],
    [`user:${password}@my${nest(body('&#65074;'), 3)}proxy:7890`, 'my-proxy:7890'],
    [`http://user:${password}@ex&#xFE32;ample.com:8080/x`, 'http://ex-ample.com:8080/x'],
    [`a=1&user:${password}@my&#65074;proxy:7890&b=2`, 'a=1&my-proxy:7890&b=2'],
    [`note &#xFE32; later user:${password}@10.1:8080`, 'note - later 10.1:8080'],
    [`note ${hyphen} later user:${password}@10.1:8080`, 'note - later 10.1:8080'],
    [`two user:${password}@my&#xFE32;proxy:7890) and user:other-secret@10.1:8080.`, 'two my-proxy:7890) and 10.1:8080.'],
    [`invalid proxy url "http://user:s3cret/token@my&#65074;proxy:7890": invalid port ":s3cret" after host`, 'invalid proxy url "http://my-proxy:7890": invalid port ":[凭据已隐藏]" after host']
  ];
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  const unchanged = [
    `Build v1${hyphen}2@beta`,
    `Build v1&#65074;2@beta`,
    `file${hyphen}name.txt`,
    `score 1&#xFE32;2@10.5`,
    `user:${password}@my${hyphen}proxy`,
    `user:${password}@my&#65074;proxy`,
    `user:${password}@10${hyphen}1:8080`,
    `note ${hyphen} later`,
    'http://user@127.0.0.1:7890'
  ];
  for (const input of unchanged) assert.equal(redactPublic(input), input);
  const proxy = `http://user:${password}@my&#xFE32;proxy:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note user:${password}@my&#65074;proxy:7890`, email: 'a@example.test', last_error: `dial user:${password}@ex${hyphen}ample.com:8080 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my-proxy:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial ex-ample.com:8080 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by a vertical low line', () => {
  const password = 's3cret-token';
  const mark = '\uFE33';
  const nest = (token, extra) => {
    let out = token;
    for (let layer = 0; layer < extra; layer += 1) out = out.replace(/%/g, '%25');
    return out;
  };
  const body = value => value.split('').map(char => `%${char.charCodeAt(0).toString(16).toUpperCase()}`).join('');
  const encoded = encodeURIComponent(mark);
  const cases = [
    [`user:${password}@my${mark}proxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my${mark}${mark}proxy:7890`, 'my__proxy:7890'],
    [`http://user:${password}@my${mark}proxy:7890/x`, 'http://my_proxy:7890/x'],
    [`http://us${mark}er:${password}@ex-ample.com:8080/x`, 'http://ex-ample.com:8080/x'],
    [`socks5://alice:${password}@my${mark}proxy:7890`, 'socks5://my_proxy:7890'],
    [`(user:${password}@my${mark}proxy:7890)`, '(my_proxy:7890)'],
    [`user:${password}@my${encoded}proxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my${encoded.toLowerCase()}proxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my${nest(encoded, 1)}proxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my${nest(encoded, 3)}proxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my&#65075;proxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my&#xFE33;proxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my&#xFE33proxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my&#xfe33;proxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my&#XFE33;proxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my&#065075;proxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my&amp;#65075;proxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my&#38;#xFE33;proxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my%26%2365075%3Bproxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my${nest('%26%23xFE33%3B', 1)}proxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my${body('&#xFE33;')}proxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my${nest(body('&#65075;'), 3)}proxy:7890`, 'my_proxy:7890'],
    [`a=1&user:${password}@my&#65075;proxy:7890&b=2`, 'a=1&my_proxy:7890&b=2'],
    [`note &#xFE33; later user:${password}@10.1:8080`, 'note _ later 10.1:8080'],
    [`note ${mark} later user:${password}@10.1:8080`, 'note _ later 10.1:8080'],
    [`two user:${password}@my&#xFE33;proxy:7890) and user:other-secret@10.1:8080.`, 'two my_proxy:7890) and 10.1:8080.'],
    [`invalid proxy url "http://user:s3cret/token@my&#65075;proxy:7890": invalid port ":s3cret" after host`, 'invalid proxy url "http://my_proxy:7890": invalid port ":[凭据已隐藏]" after host']
  ];
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  const unchanged = [
    `Build v1${mark}2@beta`,
    `Build v1&#65075;2@beta`,
    `file${mark}name.txt`,
    `score 1&#xFE33;2@10.5`,
    `user:${password}@my${mark}proxy`,
    `user:${password}@my&#65075;proxy`,
    `user:${password}@10${mark}1:8080`,
    `user:${password}@ex${mark}ample.com:8080`,
    `user:${password}@ex${mark}ample.com`,
    `note ${mark} later`,
    'http://user@127.0.0.1:7890'
  ];
  for (const input of unchanged) assert.equal(redactPublic(input), input);
  const proxy = `http://user:${password}@my&#xFE33;proxy:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: true, usage_probe: false },
    accounts: [{ id: 'acc-1', name: `note user:${password}@my&#65075;proxy:7890`, email: 'a@example.test', last_error: `dial user:${password}@my${mark}proxy:7890 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my_proxy:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial my_proxy:7890 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by a vertical wavy low line', () => {
  const password = 's3cret-token';
  const mark = '\uFE34';
  const nest = (token, extra) => {
    let out = token;
    for (let layer = 0; layer < extra; layer += 1) out = out.replace(/%/g, '%25');
    return out;
  };
  const body = value => value.split('').map(char => `%${char.charCodeAt(0).toString(16).toUpperCase()}`).join('');
  const encoded = encodeURIComponent(mark);
  const cases = [
    [`user:${password}@my${mark}proxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my${mark}${mark}proxy:7890`, 'my__proxy:7890'],
    [`http://user:${password}@my${mark}proxy:7890/x`, 'http://my_proxy:7890/x'],
    [`http://us${mark}er:${password}@ex-ample.com:8080/x`, 'http://ex-ample.com:8080/x'],
    [`socks5://alice:${password}@my${mark}proxy:7890`, 'socks5://my_proxy:7890'],
    [`(user:${password}@my${mark}proxy:7890)`, '(my_proxy:7890)'],
    [`user:${password}@my${encoded}proxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my${encoded.toLowerCase()}proxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my${nest(encoded, 1)}proxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my${nest(encoded, 3)}proxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my&#65076;proxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my&#xFE34;proxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my&#xFE34proxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my&#xfe34;proxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my&#XFE34;proxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my&#065076;proxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my&amp;#65076;proxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my&#38;#xFE34;proxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my%26%2365076%3Bproxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my${nest('%26%23xFE34%3B', 1)}proxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my${body('&#xFE34;')}proxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my${nest(body('&#65076;'), 3)}proxy:7890`, 'my_proxy:7890'],
    [`a=1&user:${password}@my&#65076;proxy:7890&b=2`, 'a=1&my_proxy:7890&b=2'],
    [`note &#xFE34; later user:${password}@10.1:8080`, 'note _ later 10.1:8080'],
    [`note ${mark} later user:${password}@10.1:8080`, 'note _ later 10.1:8080'],
    [`two user:${password}@my&#xFE34;proxy:7890) and user:other-secret@10.1:8080.`, 'two my_proxy:7890) and 10.1:8080.'],
    [`invalid proxy url "http://user:s3cret/token@my&#65076;proxy:7890": invalid port ":s3cret" after host`, 'invalid proxy url "http://my_proxy:7890": invalid port ":[凭据已隐藏]" after host']
  ];
  for (const [input, expected] of cases) {
    const got = redactPublic(input);
    assert.equal(got, expected);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  const unchanged = [
    `Build v1${mark}2@beta`,
    `Build v1&#65076;2@beta`,
    `file${mark}name.txt`,
    `score 1&#xFE34;2@10.5`,
    `user:${password}@my${mark}proxy`,
    `user:${password}@my&#65076;proxy`,
    `user:${password}@10${mark}1:8080`,
    `user:${password}@ex${mark}ample.com:8080`,
    `user:${password}@ex${mark}ample.com`,
    `note ${mark} later`,
    'http://user@127.0.0.1:7890'
  ];
  for (const input of unchanged) assert.equal(redactPublic(input), input);
  const proxy = `http://user:${password}@my&#xFE34;proxy:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note user:${password}@my&#65076;proxy:7890`, email: 'a@example.test', last_error: `dial user:${password}@my${mark}proxy:7890 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my_proxy:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial my_proxy:7890 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by the remaining low lines', () => {
  const password = 's3cret-token';
  const marks = ['\uFE4D', '\uFE4E', '\uFE4F', '\uFF3F'];
  const nest = (token, extra) => {
    let out = token;
    for (let layer = 0; layer < extra; layer += 1) out = out.replace(/%/g, '%25');
    return out;
  };
  const body = value => value.split('').map(char => `%${char.charCodeAt(0).toString(16).toUpperCase()}`).join('');
  for (const mark of marks) {
    const encoded = encodeURIComponent(mark);
    const cp = mark.codePointAt(0);
    const hex = cp.toString(16).toUpperCase();
    const dec = String(cp);
    const cases = [
      [`user:${password}@my${mark}proxy:7890`, 'my_proxy:7890'],
      [`user:${password}@my${mark}${mark}proxy:7890`, 'my__proxy:7890'],
      [`http://user:${password}@my${mark}proxy:7890/x`, 'http://my_proxy:7890/x'],
      [`http://us${mark}er:${password}@ex-ample.com:8080/x`, 'http://ex-ample.com:8080/x'],
      [`socks5://alice:${password}@my${mark}proxy:7890`, 'socks5://my_proxy:7890'],
      [`(user:${password}@my${mark}proxy:7890)`, '(my_proxy:7890)'],
      [`user:${password}@my${encoded}proxy:7890`, 'my_proxy:7890'],
      [`user:${password}@my${encoded.toLowerCase()}proxy:7890`, 'my_proxy:7890'],
      [`user:${password}@my${nest(encoded, 1)}proxy:7890`, 'my_proxy:7890'],
      [`user:${password}@my${nest(encoded, 3)}proxy:7890`, 'my_proxy:7890'],
      [`user:${password}@my&#${dec};proxy:7890`, 'my_proxy:7890'],
      [`user:${password}@my&#x${hex};proxy:7890`, 'my_proxy:7890'],
      [`user:${password}@my&#x${hex}proxy:7890`, 'my_proxy:7890'],
      [`user:${password}@my&#x${hex.toLowerCase()};proxy:7890`, 'my_proxy:7890'],
      [`user:${password}@my&#X${hex};proxy:7890`, 'my_proxy:7890'],
      [`user:${password}@my&#${dec.padStart(7, '0')};proxy:7890`, 'my_proxy:7890'],
      [`user:${password}@my&amp;#${dec};proxy:7890`, 'my_proxy:7890'],
      [`user:${password}@my&#38;#x${hex};proxy:7890`, 'my_proxy:7890'],
      [`user:${password}@my%26%23${dec}%3Bproxy:7890`, 'my_proxy:7890'],
      [`user:${password}@my${nest(`%26%23x${hex}%3B`, 1)}proxy:7890`, 'my_proxy:7890'],
      [`user:${password}@my${body(`&#x${hex};`)}proxy:7890`, 'my_proxy:7890'],
      [`user:${password}@my${nest(body(`&#${dec};`), 3)}proxy:7890`, 'my_proxy:7890'],
      [`a=1&user:${password}@my&#${dec};proxy:7890&b=2`, 'a=1&my_proxy:7890&b=2'],
      [`note &#x${hex}; later user:${password}@10.1:8080`, 'note _ later 10.1:8080'],
      [`note ${mark} later user:${password}@10.1:8080`, 'note _ later 10.1:8080'],
      [`two user:${password}@my&#x${hex};proxy:7890) and user:other-secret@10.1:8080.`, 'two my_proxy:7890) and 10.1:8080.'],
      [`invalid proxy url "http://user:s3cret/token@my&#${dec};proxy:7890": invalid port ":s3cret" after host`, 'invalid proxy url "http://my_proxy:7890": invalid port ":[凭据已隐藏]" after host']
    ];
    for (const [input, expected] of cases) {
      const got = redactPublic(input);
      assert.equal(got, expected, input);
      assert.equal(redactPublic(got), got);
      assert.equal(got.toLowerCase().includes('s3cret'), false);
      assert.equal(got.includes('other-secret'), false);
    }
    const unchanged = [
      `Build v1${mark}2@beta`,
      `Build v1&#${dec};2@beta`,
      `file${mark}name.txt`,
      `score 1&#x${hex};2@10.5`,
      `user:${password}@my${mark}proxy`,
      `user:${password}@my&#${dec};proxy`,
      `user:${password}@10${mark}1:8080`,
      `user:${password}@ex${mark}ample.com:8080`,
      `user:${password}@ex${mark}ample.com`,
      `user:${password}@ex${encoded}ample.com:8080`,
      `note ${mark} later`,
      'http://user@127.0.0.1:7890'
    ];
    for (const input of unchanged) assert.equal(redactPublic(input), input, input);
    const proxy = `http://user:${password}@my&#x${hex};proxy:7890`;
    const snap = publicSnapshot({
      settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
      accounts: [{ id: 'acc-1', name: `note user:${password}@my&#${dec};proxy:7890`, email: 'a@example.test', last_error: `dial user:${password}@my${mark}proxy:7890 failed` }]
    });
    const delivered = rendererPayload(snap);
    assert.equal(delivered.settings.proxy_url, proxy);
    assert.equal(delivered.accounts[0].name, 'note my_proxy:7890');
    assert.equal(delivered.accounts[0].email, 'a@example.test');
    assert.equal(delivered.accounts[0].last_error, 'dial my_proxy:7890 failed');
    assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
    assert.equal(snap.settings.proxy_url, proxy);
  }
  const names = [
    [`user:${password}@my&lowbar;proxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my&UnderBar;proxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my&amp;lowbar;proxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my&#38;UnderBar;proxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my%26lowbar%3Bproxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my%26UnderBar%3bproxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my${nest('%26lowbar%3B', 1)}proxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my${body('&lowbar;')}proxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my${body('&UnderBar;')}proxy:7890`, 'my_proxy:7890'],
    [`user:${password}@my${nest(body('&UnderBar;'), 3)}proxy:7890`, 'my_proxy:7890'],
    [`http://us&lowbar;er:${password}@ex-ample.com:8080/x`, 'http://ex-ample.com:8080/x'],
    [`a=1&user:${password}@my&lowbar;proxy:7890&b=2`, 'a=1&my_proxy:7890&b=2'],
    [`note &UnderBar; later user:${password}@10.1:8080`, 'note _ later 10.1:8080'],
    [`two user:${password}@my&lowbar;proxy:7890) and user:other-secret@10.1:8080.`, 'two my_proxy:7890) and 10.1:8080.'],
    [`invalid proxy url "http://user:s3cret/token@my&UnderBar;proxy:7890": invalid port ":s3cret" after host`, 'invalid proxy url "http://my_proxy:7890": invalid port ":[凭据已隐藏]" after host']
  ];
  for (const [input, expected] of names) {
    const got = redactPublic(input);
    assert.equal(got, expected, input);
    assert.equal(redactPublic(got), got);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(got.includes('other-secret'), false);
  }
  const nameUnchanged = [
    `Build v1&lowbar;2@beta`,
    `file&UnderBar;name.txt`,
    `score 1&lowbar;2@10.5`,
    `user:${password}@my&lowbar;proxy`,
    `user:${password}@my&UnderBar;proxy`,
    `user:${password}@my&lowbarproxy:7890`,
    `user:${password}@my&UnderBarproxy:7890`,
    `user:${password}@my&underbar;proxy:7890`,
    `user:${password}@my&LowBar;proxy:7890`,
    `user:${password}@my&underscore;proxy:7890`,
    `user:${password}@ex&lowbar;ample.com:8080`,
    `user:${password}@10&UnderBar;1:8080`,
    `note &lowbar; later`,
    'http://user@127.0.0.1:7890'
  ];
  for (const input of nameUnchanged) assert.equal(redactPublic(input), input, input);
  const proxy = `http://user:${password}@my&lowbar;proxy:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note user:${password}@my&UnderBar;proxy:7890`, email: 'a@example.test', last_error: `dial user:${password}@my&lowbar;proxy:7890 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note my_proxy:7890');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial my_proxy:7890 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by a fullwidth letter', () => {
  const password = 's3cret-token';
  const nest = (token, extra) => {
    let out = token;
    for (let layer = 0; layer < extra; layer += 1) out = out.replace(/%/g, '%25');
    return out;
  };
  const body = value => value.split('').map(char => `%${char.charCodeAt(0).toString(16).toUpperCase()}`).join('');
  const asciiOf = mark => String.fromCharCode(mark.codePointAt(0) - 0xFEE0);
  for (let cp = 0xFF21; cp <= 0xFF3A; cp += 1) {
    const mark = String.fromCodePoint(cp);
    const got = redactPublic(`user:${password}@my${mark}proxy:7890`);
    assert.equal(got, `my${asciiOf(mark)}proxy:7890`);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
  }
  for (let cp = 0xFF41; cp <= 0xFF5A; cp += 1) {
    const mark = String.fromCodePoint(cp);
    const got = redactPublic(`user:${password}@${mark}x.example:8080`);
    assert.equal(got, `${asciiOf(mark)}x.example:8080`);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
  }
  const samples = ['\uFF21', '\uFF3A', '\uFF41', '\uFF4D', '\uFF5A'];
  for (const mark of samples) {
    const ascii = asciiOf(mark);
    const encoded = encodeURIComponent(mark);
    const cp = mark.codePointAt(0);
    const hex = cp.toString(16).toUpperCase();
    const dec = String(cp);
    const cases = [
      [`user:${password}@my${mark}${mark}proxy:7890`, `my${ascii}${ascii}proxy:7890`],
      [`http://user:${password}@ex${mark}mple.com:8080/x`, `http://ex${ascii}mple.com:8080/x`],
      [`http://us${mark}r:${password}@example.com:8080/x`, `http://example.com:8080/x`],
      [`socks5://alice:${password}@my${mark}proxy:7890`, `socks5://my${ascii}proxy:7890`],
      [`(user:${password}@my${mark}proxy:7890)`, `(my${ascii}proxy:7890)`],
      [`user:${password}@my${encoded}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my${encoded.toLowerCase()}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my${nest(encoded, 1)}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my${nest(encoded, 3)}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my&#${dec};proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my&#x${hex};proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my&#x${hex}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my&#x${hex.toLowerCase()};proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my&amp;#${dec};proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my%26%23x${hex}%3Bproxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my${nest(`%26%23x${hex}%3B`, 1)}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my${body(`&#x${hex};`)}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my${nest(body(`&#${dec};`), 3)}proxy:7890`, `my${ascii}proxy:7890`],
      [`a=1&user:${password}@my&#${dec};proxy:7890&b=2`, `a=1&my${ascii}proxy:7890&b=2`],
      [`note &#x${hex}; later user:${password}@10.1:8080`, `note ${ascii} later 10.1:8080`],
      [`two user:${password}@my${mark}proxy:7890) and user:other-secret@10.1:8080.`, `two my${ascii}proxy:7890) and 10.1:8080.`],
      [`invalid proxy url "http://user:s3cret/token@my&#${dec};proxy:7890": invalid port ":s3cret" after host`, `invalid proxy url "http://my${ascii}proxy:7890": invalid port ":[凭据已隐藏]" after host`]
    ];
    for (const [input, expected] of cases) {
      const got = redactPublic(input);
      assert.equal(got, expected, input);
      assert.equal(redactPublic(got), got);
      assert.equal(got.toLowerCase().includes('s3cret'), false);
      assert.equal(got.includes('other-secret'), false);
    }
    const unchanged = [
      `Build v1${mark}2@beta`,
      `file${mark}name.txt`,
      `user:${password}@my${mark}proxy`,
      `user:${password}@10${mark}.0.0.1:7890`,
      `note ${mark} later`,
      `user:${password}@my\u2160proxy:7890`,
      'http://user@127.0.0.1:7890'
    ];
    for (const input of unchanged) assert.equal(redactPublic(input), input, input);
  }
  const wide = '\uFF45\uFF58\uFF41\uFF4D\uFF50\uFF4C\uFF45';
  assert.equal(redactPublic(`user:${password}@${wide}.com:8080`), 'example.com:8080');
  const proxy = `http://user:${password}@my\uFF4Dproxy:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note user:${password}@ex\uFF41mple.com:8080`, email: 'a@example.test', last_error: `dial user:${password}@my&#65357;proxy:7890 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note example.com:8080');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial mymproxy:7890 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by a circled letter', () => {
  const password = 's3cret-token';
  const nest = (token, extra) => {
    let out = token;
    for (let layer = 0; layer < extra; layer += 1) out = out.replace(/%/g, '%25');
    return out;
  };
  const body = value => value.split('').map(char => `%${char.charCodeAt(0).toString(16).toUpperCase()}`).join('');
  const asciiOf = mark => {
    const cp = mark.codePointAt(0);
    return String.fromCharCode(cp <= 0x24CF ? cp - 0x24B6 + 0x41 : cp - 0x24D0 + 0x61);
  };
  for (let cp = 0x24B6; cp <= 0x24CF; cp += 1) {
    const mark = String.fromCodePoint(cp);
    const got = redactPublic(`user:${password}@my${mark}proxy:7890`);
    assert.equal(got, `my${asciiOf(mark)}proxy:7890`);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
  }
  for (let cp = 0x24D0; cp <= 0x24E9; cp += 1) {
    const mark = String.fromCodePoint(cp);
    const got = redactPublic(`user:${password}@${mark}x.example:8080`);
    assert.equal(got, `${asciiOf(mark)}x.example:8080`);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
  }
  const samples = ['\u24B6', '\u24CF', '\u24D0', '\u24DC', '\u24E9'];
  for (const mark of samples) {
    const ascii = asciiOf(mark);
    const encoded = encodeURIComponent(mark);
    const cp = mark.codePointAt(0);
    const hex = cp.toString(16).toUpperCase();
    const dec = String(cp);
    const cases = [
      [`user:${password}@my${mark}${mark}proxy:7890`, `my${ascii}${ascii}proxy:7890`],
      [`http://user:${password}@ex${mark}mple.com:8080/x`, `http://ex${ascii}mple.com:8080/x`],
      [`http://us${mark}r:${password}@example.com:8080/x`, `http://example.com:8080/x`],
      [`socks5://alice:${password}@my${mark}proxy:7890`, `socks5://my${ascii}proxy:7890`],
      [`(user:${password}@my${mark}proxy:7890)`, `(my${ascii}proxy:7890)`],
      [`user:${password}@my${encoded}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my${encoded.toLowerCase()}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my${nest(encoded, 1)}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my${nest(encoded, 3)}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my&#${dec};proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my&#x${hex};proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my&#x${hex}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my&#x${hex.toLowerCase()};proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my&amp;#${dec};proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my%26%23x${hex}%3Bproxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my${nest(`%26%23x${hex}%3B`, 1)}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my${body(`&#x${hex};`)}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my${nest(body(`&#${dec};`), 3)}proxy:7890`, `my${ascii}proxy:7890`],
      [`a=1&user:${password}@my&#${dec};proxy:7890&b=2`, `a=1&my${ascii}proxy:7890&b=2`],
      [`note &#x${hex}; later user:${password}@10.1:8080`, `note ${ascii} later 10.1:8080`],
      [`two user:${password}@my${mark}proxy:7890) and user:other-secret@10.1:8080.`, `two my${ascii}proxy:7890) and 10.1:8080.`],
      [`invalid proxy url "http://user:s3cret/token@my&#${dec};proxy:7890": invalid port ":s3cret" after host`, `invalid proxy url "http://my${ascii}proxy:7890": invalid port ":[凭据已隐藏]" after host`]
    ];
    for (const [input, expected] of cases) {
      const got = redactPublic(input);
      assert.equal(got, expected, input);
      assert.equal(redactPublic(got), got);
      assert.equal(got.toLowerCase().includes('s3cret'), false);
      assert.equal(got.includes('other-secret'), false);
    }
    const unchanged = [
      `Build v1${mark}2@beta`,
      `file${mark}name.txt`,
      `user:${password}@my${mark}proxy`,
      `user:${password}@10${mark}.0.0.1:7890`,
      `note ${mark} later`,
      `user:${password}@my\u2160proxy:7890`,
      `user:${password}@my\u24B5proxy:7890`,
      `user:${password}@my\u24EAproxy:7890`,
      `user:${password}@my\u2121proxy:7890`,
      `user:${password}@my\u00B5proxy:7890`,
      'http://user@127.0.0.1:7890'
    ];
    for (const input of unchanged) assert.equal(redactPublic(input), input, input);
  }
  const wide = '\u24D4\u24E7\u24D0\u24DC\u24DF\u24DB\u24D4';
  assert.equal(redactPublic(`user:${password}@${wide}.com:8080`), 'example.com:8080');
  const proxy = `http://user:${password}@my\u24DCproxy:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note user:${password}@ex\u24D0mple.com:8080`, email: 'a@example.test', last_error: `dial user:${password}@my&#9436;proxy:7890 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note example.com:8080');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial mymproxy:7890 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by a letterlike symbol', () => {
  const password = 's3cret-token';
  const nest = (token, extra) => {
    let out = token;
    for (let layer = 0; layer < extra; layer += 1) out = out.replace(/%/g, '%25');
    return out;
  };
  const body = value => value.split('').map(char => `%${char.charCodeAt(0).toString(16).toUpperCase()}`).join('');
  const letters = [
    ['\u2102', 'C'], ['\u210A', 'g'], ['\u210B', 'H'], ['\u210C', 'H'], ['\u210D', 'H'], ['\u210E', 'h'],
    ['\u2110', 'I'], ['\u2111', 'I'], ['\u2112', 'L'], ['\u2113', 'l'], ['\u2115', 'N'],
    ['\u2119', 'P'], ['\u211A', 'Q'], ['\u211B', 'R'], ['\u211C', 'R'], ['\u211D', 'R'],
    ['\u2124', 'Z'], ['\u2128', 'Z'], ['\u212A', 'K'], ['\u212C', 'B'], ['\u212D', 'C'],
    ['\u212F', 'e'], ['\u2130', 'E'], ['\u2131', 'F'], ['\u2133', 'M'], ['\u2134', 'o'], ['\u2139', 'i'],
    ['\u2145', 'D'], ['\u2146', 'd'], ['\u2147', 'e'], ['\u2148', 'i'], ['\u2149', 'j']
  ];
  for (const [mark, ascii] of letters) {
    const got = redactPublic(`user:${password}@my${mark}proxy:7890`);
    assert.equal(got, `my${ascii}proxy:7890`);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(mark.normalize('NFKC'), ascii);
  }
  const samples = [['\u2102', 'C'], ['\u210E', 'h'], ['\u212A', 'K'], ['\u2139', 'i'], ['\u2149', 'j']];
  for (const [mark, ascii] of samples) {
    const encoded = encodeURIComponent(mark);
    const cp = mark.codePointAt(0);
    const hex = cp.toString(16).toUpperCase();
    const dec = String(cp);
    const cases = [
      [`user:${password}@my${mark}${mark}proxy:7890`, `my${ascii}${ascii}proxy:7890`],
      [`http://user:${password}@ex${mark}mple.com:8080/x`, `http://ex${ascii}mple.com:8080/x`],
      [`http://us${mark}r:${password}@example.com:8080/x`, `http://example.com:8080/x`],
      [`socks5://alice:${password}@my${mark}proxy:7890`, `socks5://my${ascii}proxy:7890`],
      [`(user:${password}@my${mark}proxy:7890)`, `(my${ascii}proxy:7890)`],
      [`user:${password}@my${encoded}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my${encoded.toLowerCase()}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my${nest(encoded, 1)}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my${nest(encoded, 3)}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my&#${dec};proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my&#x${hex};proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my&#x${hex}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my&#x${hex.toLowerCase()};proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my&amp;#${dec};proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my%26%23x${hex}%3Bproxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my${nest(`%26%23x${hex}%3B`, 1)}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my${body(`&#x${hex};`)}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my${nest(body(`&#${dec};`), 3)}proxy:7890`, `my${ascii}proxy:7890`],
      [`a=1&user:${password}@my&#${dec};proxy:7890&b=2`, `a=1&my${ascii}proxy:7890&b=2`],
      [`note &#x${hex}; later user:${password}@10.1:8080`, `note ${ascii} later 10.1:8080`],
      [`two user:${password}@my${mark}proxy:7890) and user:other-secret@10.1:8080.`, `two my${ascii}proxy:7890) and 10.1:8080.`],
      [`invalid proxy url "http://user:s3cret/token@my&#${dec};proxy:7890": invalid port ":s3cret" after host`, `invalid proxy url "http://my${ascii}proxy:7890": invalid port ":[凭据已隐藏]" after host`]
    ];
    for (const [input, expected] of cases) {
      const got = redactPublic(input);
      assert.equal(got, expected, input);
      assert.equal(redactPublic(got), got);
      assert.equal(got.toLowerCase().includes('s3cret'), false);
      assert.equal(got.includes('other-secret'), false);
    }
    const unchanged = [
      `Build v1${mark}2@beta`,
      `file${mark}name.txt`,
      `user:${password}@my${mark}proxy`,
      `user:${password}@10${mark}.0.0.1:7890`,
      `note ${mark} later`,
      `user:${password}@my\u2160proxy:7890`,
      `user:${password}@my\u00B5proxy:7890`,
      `user:${password}@my\u2100proxy:7890`,
      `user:${password}@my\u2103proxy:7890`,
      `user:${password}@my\u210Fproxy:7890`,
      `user:${password}@my\u2116proxy:7890`,
      `user:${password}@my\u2121proxy:7890`,
      `user:${password}@my\u2126proxy:7890`,
      `user:${password}@my\u212Bproxy:7890`,
      `user:${password}@my\u213Bproxy:7890`,
      `user:${password}@my\u24B5proxy:7890`,
      `user:${password}@my\u24EAproxy:7890`,
      'http://user@127.0.0.1:7890'
    ];
    for (const input of unchanged) assert.equal(redactPublic(input), input, input);
  }
  assert.equal(redactPublic(`user:${password}@\u212A\u212Flvin.example:8080`), 'Kelvin.example:8080');
  assert.equal(redactPublic(`user:${password}@\uFF45\u24E7\u24D0\u24DC\uFF50\u2113\u212F.com:8080`), 'example.com:8080');
  const proxy = `http://user:${password}@my\u212Aproxy:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note user:${password}@\u212Fxample.com:8080`, email: 'a@example.test', last_error: `dial user:${password}@my&#8490;proxy:7890 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note example.com:8080');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial myKproxy:7890 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by a Latin compatibility letter', () => {
  const password = 's3cret-token';
  const nest = (token, extra) => {
    let out = token;
    for (let layer = 0; layer < extra; layer += 1) out = out.replace(/%/g, '%25');
    return out;
  };
  const body = value => value.split('').map(char => `%${char.charCodeAt(0).toString(16).toUpperCase()}`).join('');
  const letters = [['\u00AA', 'a'], ['\u00BA', 'o'], ['\u017F', 's']];
  for (const [mark, ascii] of letters) {
    assert.equal(mark.normalize('NFKC'), ascii);
    const encoded = encodeURIComponent(mark);
    const cp = mark.codePointAt(0);
    const hex = cp.toString(16).toUpperCase();
    const dec = String(cp);
    const cases = [
      [`user:${password}@my${mark}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my${mark}${mark}proxy:7890`, `my${ascii}${ascii}proxy:7890`],
      [`http://user:${password}@ex${mark}mple.com:8080/x`, `http://ex${ascii}mple.com:8080/x`],
      [`http://us${mark}r:${password}@example.com:8080/x`, `http://example.com:8080/x`],
      [`socks5://alice:${password}@my${mark}proxy:7890`, `socks5://my${ascii}proxy:7890`],
      [`(user:${password}@my${mark}proxy:7890)`, `(my${ascii}proxy:7890)`],
      [`user:${password}@my${encoded}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my${encoded.toLowerCase()}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my${nest(encoded, 1)}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my${nest(encoded, 3)}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my&#${dec};proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my&#x${hex};proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my&#x${hex}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my&#x${hex.toLowerCase()};proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my&amp;#${dec};proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my%26%23x${hex}%3Bproxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my${nest(`%26%23x${hex}%3B`, 1)}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my${body(`&#x${hex};`)}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my${nest(body(`&#${dec};`), 3)}proxy:7890`, `my${ascii}proxy:7890`],
      [`a=1&user:${password}@my&#${dec};proxy:7890&b=2`, `a=1&my${ascii}proxy:7890&b=2`],
      [`note &#x${hex}; later user:${password}@10.1:8080`, `note ${ascii} later 10.1:8080`],
      [`two user:${password}@my${mark}proxy:7890) and user:other-secret@10.1:8080.`, `two my${ascii}proxy:7890) and 10.1:8080.`],
      [`invalid proxy url "http://user:s3cret/token@my&#${dec};proxy:7890": invalid port ":s3cret" after host`, `invalid proxy url "http://my${ascii}proxy:7890": invalid port ":[凭据已隐藏]" after host`]
    ];
    for (const [input, expected] of cases) {
      const got = redactPublic(input);
      assert.equal(got, expected, input);
      assert.equal(redactPublic(got), got);
      assert.equal(got.toLowerCase().includes('s3cret'), false);
      assert.equal(got.includes('other-secret'), false);
    }
    const unchanged = [
      `Build v1${mark}2@beta`,
      `file${mark}name.txt`,
      `user:${password}@my${mark}proxy`,
      `user:${password}@10${mark}.0.0.1:7890`,
      `note ${mark} later`,
      `user:${password}@my\u2160proxy:7890`,
      `user:${password}@my\u00B5proxy:7890`,
      `user:${password}@my\u00C6proxy:7890`,
      `user:${password}@my\uFB00proxy:7890`,
      `user:${password}@my\u24EAproxy:7890`,
      'http://user@127.0.0.1:7890'
    ];
    for (const input of unchanged) assert.equal(redactPublic(input), input, input);
  }
  assert.equal(redactPublic(`user:${password}@\u017Focks.example:8080`), 'socks.example:8080');
  assert.equal(redactPublic(`user:${password}@my%E2%84%AAproxy:7890`), 'myKproxy:7890');
  const proxy = `http://user:${password}@my\u017Fproxy:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note user:${password}@ex\u00AAmple.com:8080`, email: 'a@example.test', last_error: `dial user:${password}@my&#383;proxy:7890 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note example.com:8080');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial mysproxy:7890 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by a modifier letter', () => {
  const password = 's3cret-token';
  const nest = (token, extra) => {
    let out = token;
    for (let layer = 0; layer < extra; layer += 1) out = out.replace(/%/g, '%25');
    return out;
  };
  const body = value => value.split('').map(char => `%${char.charCodeAt(0).toString(16).toUpperCase()}`).join('');
  const letters = [
    [0x02B0, 'h'], [0x02B2, 'j'], [0x02B3, 'r'], [0x02B7, 'w'], [0x02B8, 'y'],
    [0x02E1, 'l'], [0x02E2, 's'], [0x02E3, 'x'],
    [0x1D2C, 'A'], [0x1D2E, 'B'], [0x1D30, 'D'], [0x1D31, 'E'],
    [0x1D33, 'G'], [0x1D34, 'H'], [0x1D35, 'I'], [0x1D36, 'J'], [0x1D37, 'K'],
    [0x1D38, 'L'], [0x1D39, 'M'], [0x1D3A, 'N'], [0x1D3C, 'O'], [0x1D3E, 'P'],
    [0x1D3F, 'R'], [0x1D40, 'T'], [0x1D41, 'U'], [0x1D42, 'W'],
    [0x1D43, 'a'], [0x1D47, 'b'], [0x1D48, 'd'], [0x1D49, 'e'], [0x1D4D, 'g'],
    [0x1D4F, 'k'], [0x1D50, 'm'], [0x1D52, 'o'], [0x1D56, 'p'], [0x1D57, 't'],
    [0x1D58, 'u'], [0x1D5B, 'v'], [0x1D9C, 'c'], [0x1DA0, 'f'], [0x1DBB, 'z'],
    [0x2C7D, 'V'], [0xA7F1, 'S'], [0xA7F2, 'C'], [0xA7F3, 'F'], [0xA7F4, 'Q'],
    [0x107A5, 'q']
  ];
  for (const [cp, ascii] of letters) {
    const mark = String.fromCodePoint(cp);
    assert.equal(mark.normalize('NFKC'), ascii);
    const got = redactPublic(`user:${password}@my${mark}proxy:7890`);
    assert.equal(got, `my${ascii}proxy:7890`);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(redactPublic(`user:${password}@${mark}x.example:8080`), `${ascii}x.example:8080`);
  }
  const samples = [0x02B0, 0x1D43, 0xA7F1, 0x107A5, 0x2C7D];
  for (const cp of samples) {
    const mark = String.fromCodePoint(cp);
    const ascii = mark.normalize('NFKC');
    const encoded = encodeURIComponent(mark);
    const hex = cp.toString(16).toUpperCase();
    const dec = String(cp);
    const cases = [
      [`user:${password}@my${mark}${mark}proxy:7890`, `my${ascii}${ascii}proxy:7890`],
      [`http://user:${password}@ex${mark}mple.com:8080/x`, `http://ex${ascii}mple.com:8080/x`],
      [`http://us${mark}r:${password}@example.com:8080/x`, `http://example.com:8080/x`],
      [`socks5://alice:${password}@my${mark}proxy:7890`, `socks5://my${ascii}proxy:7890`],
      [`(user:${password}@my${mark}proxy:7890)`, `(my${ascii}proxy:7890)`],
      [`user:${password}@my${encoded}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my${encoded.toLowerCase()}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my${nest(encoded, 1)}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my${nest(encoded, 3)}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my&#${dec};proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my&#x${hex};proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my&#x${hex}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my&#x${hex.toLowerCase()};proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my&amp;#${dec};proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my%26%23x${hex}%3Bproxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my${nest(`%26%23x${hex}%3B`, 1)}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my${body(`&#x${hex};`)}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my${nest(body(`&#${dec};`), 3)}proxy:7890`, `my${ascii}proxy:7890`],
      [`a=1&user:${password}@my&#${dec};proxy:7890&b=2`, `a=1&my${ascii}proxy:7890&b=2`],
      [`note &#x${hex}; later user:${password}@10.1:8080`, `note ${ascii} later 10.1:8080`],
      [`two user:${password}@my${mark}proxy:7890) and user:other-secret@10.1:8080.`, `two my${ascii}proxy:7890) and 10.1:8080.`],
      [`invalid proxy url "http://user:s3cret/token@my&#${dec};proxy:7890": invalid port ":s3cret" after host`, `invalid proxy url "http://my${ascii}proxy:7890": invalid port ":[凭据已隐藏]" after host`]
    ];
    for (const [input, expected] of cases) {
      const got = redactPublic(input);
      assert.equal(got, expected, input);
      assert.equal(redactPublic(got), got);
      assert.equal(got.toLowerCase().includes('s3cret'), false);
      assert.equal(got.includes('other-secret'), false);
    }
    const unchanged = [
      `Build v1${mark}2@beta`,
      `file${mark}name.txt`,
      `user:${password}@my${mark}proxy`,
      `user:${password}@10${mark}.0.0.1:7890`,
      `note ${mark} later`,
      `user:${password}@my\u00B5proxy:7890`,
      `user:${password}@my\u2160proxy:7890`,
      `user:${password}@my\u{1D400}proxy:7890`,
      `user:${password}@my\uA7F8proxy:7890`,
      `user:${password}@my\u02B1proxy:7890`,
      `user:${password}@my%F0%90%9Eproxy:7890`,
      'http://user@127.0.0.1:7890'
    ];
    for (const input of unchanged) assert.equal(redactPublic(input), input, input);
  }
  const host = '\u1D49\u02E3\u1D43\u1D50\u1D56\u02E1\u1D49';
  assert.equal(redactPublic(`user:${password}@${host}.com:8080`), 'example.com:8080');
  assert.equal(redactPublic(`user:${password}@\u{107A5}proxy:7890`), 'qproxy:7890');
  const proxy = `http://user:${password}@my\u02B0proxy:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note user:${password}@ex\u1D43mple.com:8080`, email: 'a@example.test', last_error: `dial user:${password}@my&#67493;proxy:7890 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note example.com:8080');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial myqproxy:7890 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});

test('renderer text drops proxy passwords hidden by a superscript or subscript letter', () => {
  const password = 's3cret-token';
  const nest = (token, extra) => {
    let out = token;
    for (let layer = 0; layer < extra; layer += 1) out = out.replace(/%/g, '%25');
    return out;
  };
  const body = value => value.split('').map(char => `%${char.charCodeAt(0).toString(16).toUpperCase()}`).join('');
  const letters = [
    [0x1D62, 'i'], [0x1D63, 'r'], [0x1D64, 'u'], [0x1D65, 'v'],
    [0x2071, 'i'], [0x207F, 'n'],
    [0x2090, 'a'], [0x2091, 'e'], [0x2092, 'o'], [0x2093, 'x'], [0x2095, 'h'],
    [0x2096, 'k'], [0x2097, 'l'], [0x2098, 'm'], [0x2099, 'n'], [0x209A, 'p'],
    [0x209B, 's'], [0x209C, 't'], [0x2C7C, 'j']
  ];
  for (const [cp, ascii] of letters) {
    const mark = String.fromCodePoint(cp);
    assert.equal(mark.normalize('NFKC'), ascii);
    const got = redactPublic(`user:${password}@my${mark}proxy:7890`);
    assert.equal(got, `my${ascii}proxy:7890`);
    assert.equal(got.toLowerCase().includes('s3cret'), false);
    assert.equal(redactPublic(`user:${password}@${mark}x.example:8080`), `${ascii}x.example:8080`);
  }
  const samples = [0x2071, 0x207F, 0x2090, 0x1D62, 0x2C7C];
  for (const cp of samples) {
    const mark = String.fromCodePoint(cp);
    const ascii = mark.normalize('NFKC');
    const encoded = encodeURIComponent(mark);
    const hex = cp.toString(16).toUpperCase();
    const dec = String(cp);
    const cases = [
      [`user:${password}@my${mark}${mark}proxy:7890`, `my${ascii}${ascii}proxy:7890`],
      [`http://user:${password}@ex${mark}mple.com:8080/x`, `http://ex${ascii}mple.com:8080/x`],
      [`http://us${mark}r:${password}@example.com:8080/x`, `http://example.com:8080/x`],
      [`socks5://alice:${password}@my${mark}proxy:7890`, `socks5://my${ascii}proxy:7890`],
      [`(user:${password}@my${mark}proxy:7890)`, `(my${ascii}proxy:7890)`],
      [`user:${password}@my${encoded}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my${encoded.toLowerCase()}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my${nest(encoded, 1)}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my${nest(encoded, 3)}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my&#${dec};proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my&#x${hex};proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my&#x${hex}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my&#x${hex.toLowerCase()};proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my&amp;#${dec};proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my%26%23x${hex}%3Bproxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my${nest(`%26%23x${hex}%3B`, 1)}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my${body(`&#x${hex};`)}proxy:7890`, `my${ascii}proxy:7890`],
      [`user:${password}@my${nest(body(`&#${dec};`), 3)}proxy:7890`, `my${ascii}proxy:7890`],
      [`a=1&user:${password}@my&#${dec};proxy:7890&b=2`, `a=1&my${ascii}proxy:7890&b=2`],
      [`note &#x${hex}; later user:${password}@10.1:8080`, `note ${ascii} later 10.1:8080`],
      [`two user:${password}@my${mark}proxy:7890) and user:other-secret@10.1:8080.`, `two my${ascii}proxy:7890) and 10.1:8080.`],
      [`invalid proxy url "http://user:s3cret/token@my&#${dec};proxy:7890": invalid port ":s3cret" after host`, `invalid proxy url "http://my${ascii}proxy:7890": invalid port ":[凭据已隐藏]" after host`]
    ];
    for (const [input, expected] of cases) {
      const got = redactPublic(input);
      assert.equal(got, expected, input);
      assert.equal(redactPublic(got), got);
      assert.equal(got.toLowerCase().includes('s3cret'), false);
      assert.equal(got.includes('other-secret'), false);
    }
    const unchanged = [
      `Build v1${mark}2@beta`,
      `file${mark}name.txt`,
      `user:${password}@my${mark}proxy`,
      `user:${password}@10${mark}.0.0.1:7890`,
      `note ${mark} later`,
      `user:${password}@my\u00B5proxy:7890`,
      `user:${password}@my\u2160proxy:7890`,
      `user:${password}@my\u{1D400}proxy:7890`,
      `user:${password}@my\u2070proxy:7890`,
      `user:${password}@my%E2%81proxy:7890`,
      'http://user@127.0.0.1:7890'
    ];
    for (const input of unchanged) assert.equal(redactPublic(input), input, input);
  }
  const host = '\u2091\u2093\u2090\u2098\u209A\u2097\u2091';
  assert.equal(redactPublic(`user:${password}@${host}.com:8080`), 'example.com:8080');
  assert.equal(redactPublic(`user:${password}@\u207Fproxy:7890`), 'nproxy:7890');
  const proxy = `http://user:${password}@my\u2071proxy:7890`;
  const snap = publicSnapshot({
    settings: { proxy_url: proxy, auto_refresh: false, usage_probe: true },
    accounts: [{ id: 'acc-1', name: `note user:${password}@ex\u2090mple.com:8080`, email: 'a@example.test', last_error: `dial user:${password}@my&#8305;proxy:7890 failed` }]
  });
  const delivered = rendererPayload(snap);
  assert.equal(delivered.settings.proxy_url, proxy);
  assert.equal(delivered.accounts[0].name, 'note example.com:8080');
  assert.equal(delivered.accounts[0].email, 'a@example.test');
  assert.equal(delivered.accounts[0].last_error, 'dial myiproxy:7890 failed');
  assert.equal(delivered.accounts[0].last_error.includes('s3cret'), false);
  assert.equal(snap.settings.proxy_url, proxy);
});
