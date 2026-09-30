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
