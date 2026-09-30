'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { cleanSettings, cleanLaunch, cleanProbe, cleanPreferences, applyPreferences, redactPublic, withoutSecrets, requireID, safeError, publicSnapshot, publicLogs, publicProbe, publicImport } = require('../lib/policy.cjs');
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

test('connection probe rejects a substitute model or effort instead of rewriting it', () => {
  assert.deepEqual(cleanProbe({ account_id: 'acc-abcdef123', model: 'gpt-5.6-terra', effort: 'low', channel: 'codex' }), { account_id: 'acc-abcdef123', model: 'gpt-5.6-terra', effort: 'low', channel: 'codex' });
  assert.throws(() => cleanProbe({ account_id: 'acc-abcdef123', model: 'gpt-5.6-terra', effort: 'max', channel: 'bps' }));
  assert.throws(() => cleanProbe({ account_id: 'acc-abcdef123', model: '', effort: 'high' }));
  assert.throws(() => cleanProbe({ account_id: 'acc-abcdef123', model: 'not a model', effort: 'high' }));
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
  assert.equal(view.preferences.app_path, undefined);
  assert.equal(view.preferences.api_key, undefined);
  assert.equal(view.preferences.pelican_model, 'gpt-5.6-sol');
  assert.deepEqual(view.preferences.account_speeds, { 'acc-1': 'fast' });
  const logs = publicLogs({ records: [{ model: 'gpt-6-astra', effort: 'high', route: 'bps', status: 200, duration_ms: 10, error: 'Bearer ' + 'a'.repeat(20), access_token: 'raw-token', account: 'hidden' }] });
  assert.equal(logs.records[0].access_token, undefined);
  assert.equal(logs.records[0].account, undefined);
  assert.match(logs.records[0].error, /Bearer \[凭据已隐藏\]/);
  const probe = publicProbe({ ok: true, model: 'gpt-6-astra', effort: 'low', duration_ms: 12, text: 'CONNECTION OK ' + jwt, account: 'raw-token' });
  assert.equal(probe.text, undefined);
  assert.equal(probe.account, undefined);
  assert.equal(probe.ok, true);
  const imported = publicImport({ imported: 1, merged: 0, skipped: 1, ids: ['acc-1'], warnings: ['skipped an entry without access_token or refresh_token', 'bad ' + jwt], accounts: [{ access_token: 'raw-token' }] });
  assert.equal(imported.accounts, undefined);
  assert.match(imported.warnings[0], /access_token or refresh_token/);
  assert.match(imported.warnings[1], /凭据已隐藏/);
  assert.equal(publicImport(null), null);
});
