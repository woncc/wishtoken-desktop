'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { Pelican, extractHTML } = require('../lib/pelican.cjs');
const { launchEnvironment } = require('../lib/codex-app.cjs');
const { cleanLaunch } = require('../lib/policy.cjs');
const delay = ms => new Promise(r => setTimeout(r, ms));
const accounts = [1,2,3].map(n => ({id:`acc-test${n}`,email:`test${n}@example.test`}));
const input = {account_ids:accounts.map(a=>a.id),model:'gpt-6-astra',effort:'high',concurrency:2};
const result = {text:'<!doctype html><html><body><svg></svg><script>window.animation=true;</script></body></html>',duration_ms:100,usage:{output_tokens:42}};
test('channel persists in generation, history, retry and legacy defaults', async t => {
 const home=fs.mkdtempSync(path.join(os.tmpdir(),'gptbridge-channels-'));
 const seen=[]; const p=new Pelican(home,async body=>{seen.push(body);return result;});
 t.after(async()=>{await p.close();fs.rmSync(home,{recursive:true,force:true});});
 p.start({...input,channel:'codex'},accounts); await p.running;
 assert.ok(seen.every(body=>body.channel==='codex'));
 const batch=p.snapshot()[0]; assert.equal(batch.channel,'codex');
 assert.equal(p.artifact(batch.items[0].id).channel,'codex');
 assert.equal(batch.items[0].response_model,null); // never invent a returned model
 assert.equal(batch.items[0].route,null);
 const recovered=new Pelican(home,async()=>result); assert.equal(recovered.snapshot()[0].channel,'codex');
 recovered.start({...batch,account_ids:accounts.map(a=>a.id)},accounts); await recovered.running;
 assert.equal(recovered.snapshot()[0].channel,'codex');
 delete recovered.batches[0].channel; recovered.save();
 const legacy=new Pelican(home,()=>{}); assert.equal(legacy.snapshot()[0].channel,'bps');
 assert.throws(()=>p.start({...input,channel:'invalid'},accounts));
});
test('batch concurrency, pinned accounts, persistence, preview containment and deletion', async t => {
 const home = fs.mkdtempSync(path.join(os.tmpdir(),'gptbridge-pelican-test-'));
 let count=0,peak=0; const seen=[];
 const p = new Pelican(home,async (body) => { count++; peak=Math.max(peak,count); seen.push(body.account_id); await delay(30); count--; return result; });
 t.after(async()=>{await p.close();fs.rmSync(home,{recursive:true,force:true});});
 await p.listen();
 const id = p.start(input,accounts); assert.throws(()=>p.start(input,accounts));
 await p.running; assert.equal(peak,2); assert.deepEqual(seen.sort(),accounts.map(a=>a.id));
 assert.equal(p.snapshot()[0].status,'completed');
 const item=p.snapshot()[0].items[0];
 const response=await fetch(item.preview); const text=await response.text();
 assert.match(response.headers.get('content-security-policy'),/sandbox allow-scripts/);
 assert.match(response.headers.get('content-security-policy'),/connect-src 'none'/);
 assert.ok(text.indexOf('RTCPeerConnection') < text.indexOf('window.animation'));
 assert.equal((await fetch(`${p.origin}/wrong/${item.id}`)).status,404);
 assert.equal(p.allowedPreview(item.preview), true);
 assert.equal(p.allowedPreview(`${item.preview}/extra`), false);
 assert.equal(p.allowedPreview(`${item.preview}?next=1`), false);
 assert.equal(p.allowedPreview(`${item.preview}#frag`), false);
 assert.equal(p.allowedPreview(`http://127.0.0.1:9/${p.token}/${item.id}`), false);
 assert.throws(()=>p.artifact('../config'));
 const recovered=new Pelican(home,()=>{}); assert.equal(recovered.batches[0].items[0].status,'completed');
 p.remove(id); assert.equal(p.snapshot().length,0); assert.throws(()=>p.artifact(item.id));
});
test('cancel aborts running requests, drops queued work and survives restart', async t => {
 const home=fs.mkdtempSync(path.join(os.tmpdir(),'gptbridge-pelican-cancel-')); let started=0;
 const p=new Pelican(home,(_body,signal)=>new Promise((resolve,reject)=>{started++;signal.addEventListener('abort',()=>reject(new Error('aborted')),{once:true});}));
 t.after(async()=>{await p.close();fs.rmSync(home,{recursive:true,force:true});});
 p.start({...input,concurrency:1},accounts); p.cancel(); await p.running;
 assert.equal(started,1); assert.ok(p.batches[0].items.every(i=>i.status==='cancelled'));
 p.batches[0].status='running';p.batches[0].items[0].status='running';p.save();
 const recovered=new Pelican(home,()=>{}); assert.equal(recovered.batches[0].status,'interrupted'); assert.equal(recovered.batches[0].items[0].status,'interrupted');
});
test('App launch has no directory requirement and never inherits the host Codex identity',()=>{
 const request=cleanLaunch({target:'app',account_id:'acc-test1',model:'gpt-6-astra',effort:'xhigh',resume:true});
 assert.equal(request.directory,'');assert.equal(request.resume,false);
 const env=launchEnvironment('/private/profile','test-key',{CODEX_HOME:'/original',CODEX_CLI_PATH:'original',ELECTRON_RUN_AS_NODE:'1',GPTBRIDGE_OTHER:'bad',PATH:'system',OPENAI_API_KEY:'original'});
 assert.equal(env.CODEX_HOME,'/private/profile');assert.equal(env.GPTBRIDGE_CODEX_KEY,'test-key');assert.equal(env.CODEX_CLI_PATH,undefined);assert.equal(env.ELECTRON_RUN_AS_NODE,undefined);assert.equal(env.OPENAI_API_KEY,undefined);
 assert.throws(()=>extractHTML('partial <html><body>'));
 assert.match(extractHTML('```html\n<html></html>\n```'),/<html>/);
});

test('compare snapshots and saved artifacts cannot carry oauth material', async t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'gptbridge-pelican-redact-'));
  const leaked = 'Bearer ' + 'a'.repeat(24) + ' rt_refreshvalue eyJaaaaaaaaaa.bbbbbbbbbb.cccccccccc';
  const p = new Pelican(home, async () => ({
    text: `<!doctype html><html><body>${leaked}</body></html>`,
    access_token: 'raw-token',
    personal_access_token: 'pat-value',
    response_id: 'resp-secret',
    duration_ms: 5,
    usage: { output_tokens: 3, access_token: 'nested-token' },
    response_model: 'gpt-6-astra',
    route: 'bps'
  }));
  t.after(async () => { await p.close(); fs.rmSync(home, { recursive: true, force: true }); });
  await p.listen();
  p.start({ account_ids: ['acc-test1'], model: 'gpt-6-astra', effort: 'high', channel: 'codex', concurrency: 1 }, accounts.slice(0, 1));
  await p.running;
  const realId = p.batches[0].items[0].id;
  assert.equal(p.snapshot()[0].channel, 'codex');
  assert.equal(p.snapshot()[0].items[0].route, 'bps');
  assert.equal(typeof p.snapshot()[0].items[0].preview, 'string');
  p.batches[0].access_token = 'raw-token';
  p.batches[0].items[0].personal_access_token = 'pat-value';
  p.batches[0].items[0].note = 'Bearer ' + 'b'.repeat(24);
  p.batches[0].items[0].id = 'not-a-uuid';
  const tampered = p.snapshot()[0];
  assert.equal(tampered.access_token, undefined);
  assert.equal(tampered.items[0].personal_access_token, undefined);
  assert.equal(tampered.items[0].note, undefined);
  assert.equal(tampered.items[0].preview, null);
  p.batches[0].items[0].id = realId;
  const artifact = p.artifact(realId);
  const raw = fs.readFileSync(path.join(home, 'pelican', `${realId}.json`), 'utf8');
  assert.equal(artifact.access_token, undefined);
  assert.equal(artifact.response_id, undefined);
  assert.equal(artifact.usage.access_token, undefined);
  assert.equal(artifact.usage.output_tokens, 3);
  assert.match(artifact.html, /<html>/);
  assert.doesNotMatch(artifact.text, /rt_refresh|Bearer a{12}|eyJaaa/);
  assert.doesNotMatch(artifact.html, /rt_refresh|Bearer a{12}|eyJaaa/);
  assert.doesNotMatch(raw, /raw-token|personal_access_token|resp-secret|nested-token/);
});
