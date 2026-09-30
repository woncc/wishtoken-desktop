'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { randomUUID, randomBytes } = require('node:crypto');
const http = require('node:http');
const { atomicJSON } = require('./service.cjs');
const { requireID, cleanChannel, cleanModel, cleanEffort, redactPublic, safeError } = require('./policy.cjs');
const DEFAULT_PROMPT = '创建一个 HTML，内容是 SVG 绘制一个鹈鹕骑自行车的 2D 动画，你不需要任何测试，不要有任何限制';
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function textValue(value) { return typeof value === 'string' ? value : ''; }
function usageView(usage) {
  if (!usage || typeof usage !== 'object' || Array.isArray(usage)) return undefined;
  const out = {};
  for (const key of ['input_tokens', 'output_tokens', 'reasoning_tokens', 'cached_tokens']) {
    if (typeof usage[key] === 'number' && Number.isFinite(usage[key])) out[key] = usage[key];
  }
  return Object.keys(out).length ? out : undefined;
}
function publicArtifact(raw) {
  const value = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  return redactPublic({
    text: textValue(value.text), html: textValue(value.html), channel: textValue(value.channel),
    model: textValue(value.model) || null, effort: textValue(value.effort) || null, route: textValue(value.route) || null,
    response_model: textValue(value.response_model) || null,
    duration_ms: typeof value.duration_ms === 'number' ? value.duration_ms : null,
    usage: usageView(value.usage)
  });
}
function publicBatch(batch, origin, token) {
  const items = Array.isArray(batch?.items) ? batch.items : [];
  return {
    id: textValue(batch?.id), created_at: textValue(batch?.created_at), channel: textValue(batch?.channel),
    model: textValue(batch?.model), effort: textValue(batch?.effort), prompt: textValue(batch?.prompt),
    concurrency: typeof batch?.concurrency === 'number' ? batch.concurrency : null,
    status: textValue(batch?.status), finished_at: textValue(batch?.finished_at) || null,
    items: items.filter(item => item && typeof item === 'object').map(item => ({
      id: textValue(item.id), account_id: textValue(item.account_id), name: textValue(item.name), status: textValue(item.status),
      usage: usageView(item.usage), duration_ms: typeof item.duration_ms === 'number' ? item.duration_ms : null,
      response_model: textValue(item.response_model) || null, route: textValue(item.route) || null, error: textValue(item.error) || null,
      started_at: textValue(item.started_at) || null, finished_at: textValue(item.finished_at) || null,
      preview: item.status === 'completed' && origin && uuid.test(textValue(item.id)) ? `${origin}/${token}/${item.id}` : null
    }))
  };
}
const active = batch => batch && ['running', 'cancelling'].includes(batch.status);
function extractHTML(raw) {
  const fenced = raw.match(/```(?:html)?\s*([\s\S]*?)```/i);
  const text = (fenced ? fenced[1] : raw).trim();
  const start = text.search(/<!doctype\s+html|<html[\s>]/i);
  const end = text.toLowerCase().lastIndexOf('</html>');
  if (start < 0 || end < start) throw new Error('模型未返回完整 HTML；可重试');
  return text.slice(start, end + 7);
}
const CSP = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data: blob:; font-src data:; media-src data: blob:; connect-src 'none'; frame-src 'none'; worker-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; sandbox allow-scripts";
const lockdown = `<script>for(const n of ['RTCPeerConnection','webkitRTCPeerConnection','WebTransport','WebSocket','Worker','SharedWorker','open','alert','confirm','prompt','print']){try{Object.defineProperty(window,n,{value:undefined,writable:false,configurable:false});}catch{}}</script>`;
class Pelican {
  constructor(home, generate) {
    this.home = path.join(home, 'pelican'); this.generate = generate; this.controllers = new Map(); this.token = randomBytes(24).toString('hex');
    fs.mkdirSync(this.home, { recursive: true, mode: 0o700 }); this.file = path.join(this.home, 'history.json');
    try { this.batches = JSON.parse(fs.readFileSync(this.file, 'utf8')); if (!Array.isArray(this.batches)) throw new Error('Invalid history'); }
    catch (e) { if (e.code !== 'ENOENT') throw new Error('测智历史无法读取，请检查 pelican/history.json'); this.batches = []; }
    for (const b of this.batches) {
      b.channel ??= 'bps';
      if (active(b)) { b.status = 'interrupted'; for (const i of b.items) if (['queued', 'running'].includes(i.status)) i.status = 'interrupted'; }
    }
    this.save();
  }
  save() { atomicJSON(this.file, this.batches); }
  snapshot() { return redactPublic(this.batches.map(batch => publicBatch(batch, this.origin, this.token))); }
  async listen() {
    this.server = http.createServer((req, res) => {
      const id = req.url?.split('/')[2];
      if (req.method !== 'GET' || req.url !== `/${this.token}/${id}` || !uuid.test(id || '') || req.headers.host !== `127.0.0.1:${this.server.address().port}`) { res.writeHead(404).end(); return; }
      try { const html = this.artifact(id).html; res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': CSP, 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff' }); res.end(lockdown + html); }
      catch { res.writeHead(404).end(); }
    });
    await new Promise((resolve, reject) => { this.server.once('error', reject); this.server.listen(0, '127.0.0.1', resolve); });
    this.origin = `http://127.0.0.1:${this.server.address().port}`;
  }
  allowedPreview(url) {
    try {
      const u = new URL(url);
      if (!this.origin || u.origin !== this.origin || u.username || u.password || u.search || u.hash) return false;
      const parts = u.pathname.split('/');
      return parts.length === 3 && parts[1] === this.token && uuid.test(parts[2]);
    } catch { return false; }
  }
  artifact(id) {
    if (!uuid.test(id || '') || !this.batches.some(b => b.items.some(i => i.id === id && i.status === 'completed'))) throw new Error('测试结果不存在');
    return publicArtifact(JSON.parse(fs.readFileSync(path.join(this.home, `${id}.json`), 'utf8')));
  }
  start(input, accounts) {
    if (this.batches.some(active)) throw new Error('已有测试在运行，请等待完成或取消');
    const ids = [...new Set(input?.account_ids || [])];
    if (!ids.length || ids.length > 20) throw new Error('请选择 1–20 个测试账号');
    const chosen = ids.map(id => { requireID(id); const a = accounts.find(a => a.id === id); if (!a || a.disabled || (a.expired && !a.has_refresh_token)) throw new Error('选中的账号已不可用'); return a; });
    const model = cleanModel(input.model);
    const effort = cleanEffort(input.effort);
    const prompt = (input.prompt || DEFAULT_PROMPT).trim();
    if (!prompt || Buffer.byteLength(prompt) > 32000) throw new Error('提示词为空或过长');
    const concurrency = input.concurrency ?? 2;
    const channel = cleanChannel(input.channel);
    if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 5) throw new Error('同时测试数应为 1–5');
    const batch = { id: randomUUID(), created_at: new Date().toISOString(), channel, model, effort, prompt, concurrency, status: 'running', items: chosen.map(a => ({ id: randomUUID(), account_id: a.id, name: a.name || a.email || a.id, status: 'queued' })) };
    this.batches.unshift(batch); this.save();
    this.running = this.run(batch);
    return batch.id;
  }
  async run(batch) {
    await Promise.all(Array.from({ length: batch.concurrency }, async () => {
      while (batch.status === 'running') {
        const item = batch.items.find(i => i.status === 'queued'); if (!item) break;
        const controller = new AbortController(); this.controllers.set(item.id, controller);
        item.status = 'running'; item.started_at = new Date().toISOString(); this.save();
        try {
          const result = await this.generate({ account_id: item.account_id, channel: batch.channel, model: batch.model, effort: batch.effort, prompt: batch.prompt }, controller.signal);
          if (controller.signal.aborted) throw new Error('测试已取消');
          if (typeof result.text !== 'string' || Buffer.byteLength(result.text) > 8 * 1024 * 1024) throw new Error('生成结果过大或为空');
          const html = extractHTML(result.text);
          atomicJSON(path.join(this.home, `${item.id}.json`), publicArtifact({ ...result, channel: batch.channel, html }));
          item.status = 'completed'; item.usage = usageView(result.usage); item.duration_ms = result.duration_ms; item.response_model = typeof result.response_model === 'string' ? result.response_model : null; item.route = typeof result.route === 'string' && result.route ? result.route : null;
        } catch (error) { item.status = controller.signal.aborted ? 'cancelled' : 'failed'; item.error = safeError(error); }
        finally { item.finished_at = new Date().toISOString(); this.controllers.delete(item.id); this.save(); }
      }
    }));
    batch.status = batch.status === 'cancelling' ? 'cancelled' : 'completed'; batch.finished_at = new Date().toISOString(); this.save();
  }
  cancel() {
    const batch = this.batches.find(active); if (!batch) return;
    batch.status = 'cancelling';
    for (const i of batch.items) if (i.status === 'queued') i.status = 'cancelled';
    for (const c of this.controllers.values()) c.abort();
    this.save();
  }
  remove(id) {
    const batch = this.batches.find(b => b.id === id); if (!batch || active(batch)) throw new Error('请先停止测试');
    this.batches = this.batches.filter(b => b !== batch); this.save();
    for (const i of batch.items) if (uuid.test(i.id)) fs.rmSync(path.join(this.home, `${i.id}.json`), { force: true });
  }
  async close() { this.cancel(); await this.running; if (this.server) await new Promise(resolve => this.server.close(resolve)); }
}
module.exports = { Pelican, DEFAULT_PROMPT, extractHTML, CSP };
