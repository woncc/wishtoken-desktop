'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { cleanSettings, cleanLaunch, cleanProbe, redactPublic, requireID, safeError } = require('../lib/policy.cjs');
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
