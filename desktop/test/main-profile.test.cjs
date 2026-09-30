'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const profile=require('../lib/main-profile.cjs');
const runtime=require('../lib/codex-app.cjs');
function fixture(t) {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'wishtoken-main-test-'));
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const dataHome=path.join(root,'client'), home=path.join(root,'primary'), profileHome=path.join(root,'prepared');
  for(const p of [dataHome,home,profileHome])fs.mkdirSync(p);
  const original='# existing settings\nmodel_provider = "original_provider"\nmodel = "old-model"\nservice_tier = "priority"\nprofile = "work"\n[projects."/work/project"]\ntrust_level = "trusted"\n[mcp_servers.example]\ncommand = "node"\nargs = [\n "server.js",\n]\n[profiles.work]\nmodel = "old-profile-model"\nmodel_provider = "original_provider"\n[desktop]\ndefault-service-tier = "priority"\ncustom = true\n[model_providers.original_provider]\nbase_url = "https://example.test/v1"\n[model_providers.original_provider.http_headers]\nCustom = "old"\n[model_providers.untouched]\nname = "retained"\n[misc]\nnote = """\n[model_providers.fake]\nmodel = "not a setting"\n"""\n[[misc.entries]]\nname = "first"\n';
  fs.writeFileSync(path.join(home,'config.toml'),original);
  fs.writeFileSync(path.join(home,'auth.json'),'{"original":true}');
  fs.mkdirSync(path.join(home,'sessions'));fs.writeFileSync(path.join(home,'sessions','fixture.txt'),'original conversation');
  fs.writeFileSync(path.join(home,'state_5.sqlite'),'unchanged fixture database bytes');
  fs.writeFileSync(path.join(profileHome,'config.toml'),'model_provider = "gptbridge"\nmodel = "gpt-6-astra"\nmodel_reasoning_effort = "high"\nservice_tier = "default"\nmodel_catalog_json = "temporary"\nmodel_context_window = 272000\nmodel_auto_compact_token_limit = 200000\n[model_providers.gptbridge]\nbase_url = "http://127.0.0.1:8792/v1"\nenv_key = "GPTBRIDGE_CODEX_KEY"\nrequires_openai_auth = true\nwire_api = "responses"\nhttp_headers = { "X-GPTBridge-Account" = "acc-first", "X-GPTBridge-Channel" = "codex" }\n');
  fs.writeFileSync(path.join(profileHome,'auth.json'),'{"personal_access_token":"synthetic-placeholder"}');
  fs.writeFileSync(path.join(profileHome,'bridge-identity.json'),'{"auth_api_url":"http://127.0.0.1:8792/fixture"}');
  fs.writeFileSync(path.join(profileHome,'models.json'),'{"models":[]}');
  return {dataHome,home,profileHome,original,key:'local-test-key',accountID:'acc-first',channel:'codex'};
}
test('main switch preserves provider, projects, sessions and unrelated TOML',t=>{
  const f=fixture(t), change=profile.apply(profile.prepare(f));
  const config=fs.readFileSync(path.join(f.home,'config.toml'),'utf8');
  assert.equal(change.provider,'original_provider');
  assert.match(config,/model_provider = "original_provider"/);
  assert.match(config,/\[projects\."\/work\/project"\]\ntrust_level = "trusted"/);
  assert.match(config,/args = \[\n "server.js",\n\]/);
  assert.match(config,/\[\[misc.entries\]\]\nname = "first"/);
  assert.match(config,/\[model_providers.untouched\]\nname = "retained"/);
  assert.match(config,/experimental_bearer_token = "local-test-key"/);
  assert.doesNotMatch(config,/old-profile-model|https:\/\/example.test|default-service-tier = "priority"/);
  assert.match(config,/not a setting/);
  assert.equal(fs.readFileSync(path.join(f.home,'state_5.sqlite'),'utf8'),'unchanged fixture database bytes');
  assert.equal(fs.readFileSync(path.join(f.home,'sessions/fixture.txt'),'utf8'),'original conversation');
  assert.equal(fs.existsSync(path.join(f.home,'app-data')),false);
  assert.equal(profile.status(f.dataHome,f.home).active,true);
  // Multiple switches keep the first backup, while launch failure restores the immediately preceding projection.
  const before=fs.readFileSync(path.join(f.home,'config.toml'),'utf8');
  const second=profile.apply(profile.prepare({...f,key:'second-local-key',accountID:'acc-second'}));
  assert.equal(second.backup,change.backup);
  assert.equal(profile.status(f.dataHome,f.home).account_id,'acc-second');
  second.rollback();
  assert.equal(fs.readFileSync(path.join(f.home,'config.toml'),'utf8'),before);
  assert.equal(profile.status(f.dataHome,f.home).account_id,'acc-first');
  profile.restore(f.dataHome,f.home);
  assert.equal(fs.readFileSync(path.join(f.home,'config.toml'),'utf8'),f.original);
  assert.equal(fs.readFileSync(path.join(f.home,'auth.json'),'utf8'),'{"original":true}');
  assert.equal(fs.existsSync(path.join(f.home,'wishtoken-models.json')),false);
  assert.equal(fs.existsSync(path.join(f.home,'bridge-identity.json')),false);
  assert.equal(profile.status(f.dataHome,f.home).active,false);
});
test('external edits prevent stale apply and destructive restore',t=>{
  const f=fixture(t), plan=profile.prepare(f);
  fs.appendFileSync(path.join(f.home,'config.toml'),'# edit\n');
  assert.throws(()=>profile.apply(plan),/发生变化/);
  assert.equal(profile.status(f.dataHome,f.home).active,false);
  const projected=profile.apply(profile.prepare(f));
  fs.appendFileSync(path.join(f.home,'config.toml'),'# new edit\n');
  assert.throws(()=>profile.restore(f.dataHome,f.home),/其他程序修改/);
  assert.throws(()=>projected.rollback(),/其他程序修改/);
  assert.match(fs.readFileSync(path.join(f.home,'config.toml'),'utf8'),/# new edit/);
});
test('missing identity and ambiguous TOML fail before changing the main profile',t=>{
  const f=fixture(t);
  fs.unlinkSync(path.join(f.profileHome,'auth.json'));
  assert.throws(()=>profile.prepare(f),/身份信息/);
  assert.equal(fs.readFileSync(path.join(f.home,'config.toml'),'utf8'),f.original);
  assert.throws(()=>profile.mergeConfig('model_providers = {}','',f.home,f.key),/内联/);
});
test('built-in OpenAI retains its provider ID through a scoped base URL',t=>{
  const f=fixture(t);
  fs.writeFileSync(path.join(f.home,'config.toml'),'model = "old"\n');
  profile.apply(profile.prepare(f));
  const config=fs.readFileSync(path.join(f.home,'config.toml'),'utf8');
  assert.match(config,/model_provider = "openai"/);
  assert.doesNotMatch(config,/\[model_providers.openai\]/);
  assert.match(config,/openai_base_url = "http:\/\/127.0.0.1:8792\/desktop-api\/[a-f0-9]{64}\/acc-first\/codex\/v1"/);
  assert.doesNotMatch(config,/local-test-key/);
});
test('main launch uses original Electron data and excludes isolated and child processes',t=>{
  const f=fixture(t);
  const env=runtime.launchEnvironment(f.home,f.key,{PATH:'safe',CODEX_ELECTRON_USER_DATA_PATH:'old',CODEX_AUTHAPI_BASE_URL:'old',OPENAI_API_KEY:'old'},'main');
  assert.equal(env.CODEX_HOME,f.home);assert.equal(env.CODEX_ELECTRON_USER_DATA_PATH,undefined);
  assert.equal(env.CODEX_AUTHAPI_BASE_URL,undefined);assert.equal(env.OPENAI_API_KEY,undefined);
  assert.deepEqual(runtime.launchArguments(f.home,'main'),[]);
  assert.equal(runtime.launchArguments(f.home,'isolated').length,1);
  assert.equal(runtime.isMainProcess('"C:\\App\\ChatGPT.exe"','win32'),true);
  assert.equal(runtime.isMainProcess('app --type=renderer','win32'),false);
  assert.equal(runtime.isMainProcess('app "--user-data-dir=C:\\isolated profile\\app-data"','win32'),false);
  assert.equal(runtime.isMainProcess('app --user-data-dir="C:\\data\\Codex"','win32',{APPDATA:'C:\\data'}),true);
  assert.equal(runtime.isMainProcess('/Applications/Codex.app/Contents/MacOS/Codex --user-data-dir=/tmp/private','darwin'),false);
});

test('app identity URL must stay on loopback HTTP', t => {
  const local = 'http://127.0.0.1:8792/cockpit-auth/synthetic';
  assert.equal(runtime.loopbackIdentityURL(local), local);
  assert.equal(runtime.loopbackIdentityURL('http://localhost:8792/cockpit-auth/synthetic'), 'http://localhost:8792/cockpit-auth/synthetic');
  assert.equal(runtime.loopbackIdentityURL('http://[::1]:8792/cockpit-auth/synthetic'), 'http://[::1]:8792/cockpit-auth/synthetic');
  for (const bad of ['https://127.0.0.1:8792/cockpit-auth/synthetic', 'http://evil.test/cockpit-auth/synthetic', 'http://user:pw@127.0.0.1:8792/x', 'http://127.0.0.1:8792/x?token=synthetic', local + '#frag', 'http://10.0.0.8:8792/x', 'http://127.0.0.1:8792/x`id', '', 'http://0x7f000001:8792/x', 'http://2130706433:8792/x', 'http://127.1:8792/x', 'http://0177.0.0.1:8792/x', 'http://127.0.0.1.:8792/x', 'http://[::0001]:8792/x', 'HTTP://127.0.0.1:8792/x', 'http://127.0.0.1:08792/x']) {
    assert.equal(runtime.loopbackIdentityURL(bad), '');
  }
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wishtoken-identity-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const env = { PATH: 'safe', CODEX_AUTHAPI_BASE_URL: 'http://evil.test/old' };
  assert.equal(runtime.launchEnvironment(home, 'local-test-key', env).CODEX_AUTHAPI_BASE_URL, undefined);
  fs.writeFileSync(path.join(home, 'bridge-identity.json'), JSON.stringify({ auth_api_url: local }));
  assert.equal(runtime.launchEnvironment(home, 'local-test-key', env).CODEX_AUTHAPI_BASE_URL, local);
  fs.writeFileSync(path.join(home, 'bridge-identity.json'), JSON.stringify({ auth_api_url: 'https://evil.test/cockpit-auth/synthetic' }));
  assert.throws(() => runtime.launchEnvironment(home, 'local-test-key', env), error => {
    assert.match(error.message, /本地服务/);
    assert.equal(error.message.includes('evil.test'), false);
    return true;
  });
  fs.writeFileSync(path.join(home, 'bridge-identity.json'), JSON.stringify({ auth_api_url: 'http://0x7f000001:8792/cockpit-auth/synthetic' }));
  assert.throws(() => runtime.launchEnvironment(home, 'local-test-key', env), error => {
    assert.match(error.message, /本地服务/);
    assert.equal(error.message.includes('0x7f000001'), false);
    return true;
  });
  fs.writeFileSync(path.join(home, 'bridge-identity.json'), 'not-json secret-token');
  assert.throws(() => runtime.launchEnvironment(home, 'local-test-key', env), error => {
    assert.match(error.message, /本地服务/);
    assert.equal(error.message.includes('secret-token'), false);
    return true;
  });
  const source = fs.readFileSync(path.join(__dirname, '../lib/codex-app.cjs'), 'utf8');
  assert.doesNotMatch(source, /ConvertFrom-Json\)\.auth_api_url/);
});
