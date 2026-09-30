'use strict';

const accountID = /^acc-[a-zA-Z0-9-]{1,80}$/;
function cleanChannel(value) {
  const channel = value ?? 'bps';
  if (!['bps', 'codex'].includes(channel)) throw new Error('请选择 BPS 或原生通道');
  return channel;
}
function requireChannel(value) {
  if (value !== 'bps' && value !== 'codex') throw new Error('请选择 BPS 或原生通道');
  return value;
}
function cleanModel(value) {
  if (typeof value !== 'string' || !/^[a-zA-Z0-9.-]{1,80}$/.test(value)) throw new Error('模型无效');
  return value;
}
function cleanEffort(value) {
  if (!['low', 'medium', 'high', 'xhigh'].includes(value)) throw new Error('推理档位无效');
  return value;
}
function cleanProbe(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('测试参数无效');
  return { account_id: requireID(input.account_id), model: cleanModel(input.model), effort: cleanEffort(input.effort), channel: requireChannel(input.channel) };
}
const SECRET_KEYS = new Set(['access_token', 'accesstoken', 'refresh_token', 'refreshtoken', 'id_token', 'idtoken', 'api_key', 'apikey', 'authorization', 'password', 'secret', 'client_secret', 'clientsecret', 'cockpit_key', 'cockpitkey', 'gptbridge_codex_key', 'personal_access_token', 'personalaccesstoken', 'openai_api_key', 'openaiapikey', 'experimental_bearer_token', 'bearer_token', 'bearertoken', 'auth_token', 'authtoken', 'response_id', 'responseid']);
const SECRET_TEXT = [
  [/eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g, '[凭据已隐藏]'],
  [/\bBearer\s+[A-Za-z0-9._~+/-]{12,}/gi, 'Bearer [凭据已隐藏]'],
  [/\brt_[A-Za-z0-9_-]{8,}\b/g, '[凭据已隐藏]'],
  [/\b(?:sk|rk)-[A-Za-z0-9_-]{12,}\b/g, '[凭据已隐藏]'],
  [/(cockpit-auth\/)[A-Fa-f0-9]{32,}/gi, '$1[凭据已隐藏]'],
  [/((?:access_token|refresh_token|id_token|api_key|cockpit_key|client_secret|personal_access_token|experimental_bearer_token|openai_api_key|response_id)["'\s:=]{1,8})[^\s"',&<]{8,}/gi, '$1[凭据已隐藏]']
];
// A space, newline, or extra @ defeats a normal URL parse. Those passwords are
// removed from renderer text too. Username-only values stay; the settings
// field is copied back after this pass so the editor can round-trip.
const PROXY_HOST = '(?:\\[[0-9A-Fa-f:.%]+\\]|(?:\\d{1,3}\\.){3}\\d{1,3}|localhost|[A-Za-z0-9.-]+\\.[A-Za-z]{2,})(?::\\d+)?(?=$|[\\s/?#])';
const PROXY_BOUND = '[\\s"\'()<>]';
function redactProxyCredentials(text) {
  const compact = /\b([a-z][a-z0-9+.-]*:\/\/)[^\s\/?#:@]+:[^\s\/?#@]+(?:@[^\s\/?#@]+)*@/gi;
  const spaced = new RegExp(String.raw`\b([a-z][a-z0-9+.-]*:\/\/)[^\s\/?#:@]+:[^\/?#]*\s[^\/?#]{0,200}?@(?=${PROXY_HOST})`, 'gi');
  const relative = new RegExp(String.raw`(^|${PROXY_BOUND})(\/\/)[^\s\/?#:@]+:[^\s\/?#@]+(?:@[^\s\/?#@]+)*@`, 'g');
  const relativeSpaced = new RegExp(String.raw`(^|${PROXY_BOUND})(\/\/)[^\s\/?#:@]+:[^\/?#]*\s[^\/?#]{0,200}?@(?=${PROXY_HOST})`, 'g');
  const bare = new RegExp(String.raw`(^|${PROXY_BOUND})[^\s\/?#:@]+:[^\s\/?#@]+(?:@[^\s\/?#@]+)*@(?=${PROXY_HOST})`, 'g');
  const bareSpaced = new RegExp(String.raw`(^|${PROXY_BOUND})[^\s\/?#:@]+:[^\/?#]*\s[^\/?#]{0,200}?@(?=${PROXY_HOST})`, 'g');
  return text
    .replace(compact, '$1')
    .replace(spaced, '$1')
    .replace(relative, '$1$2')
    .replace(relativeSpaced, '$1$2')
    .replace(bare, '$1')
    .replace(bareSpaced, '$1');
}
function redactText(value) {
  let text = String(value);
  for (const [pattern, replacement] of SECRET_TEXT) text = text.replace(pattern, replacement);
  return redactProxyCredentials(text);
}
function blockedKey(key) {
  const name = String(key);
  return name === '__proto__' || name === 'constructor' || name === 'prototype' || SECRET_KEYS.has(name.toLowerCase());
}
function redactPublic(value) {
  if (typeof value === 'string') return redactText(value);
  if (Array.isArray(value)) return value.map(redactPublic);
  if (value == null || typeof value !== 'object') return value;
  const out = {};
  for (const [key, item] of Object.entries(value)) {
    if (blockedKey(key)) continue;
    if (typeof item === 'string') out[key] = redactText(item);
    else if (item && typeof item === 'object') out[key] = redactPublic(item);
    else out[key] = item;
  }
  return out;
}
function withoutSecrets(value) {
  if (Array.isArray(value)) return value.map(withoutSecrets);
  if (!value || typeof value !== 'object') return value;
  const out = {};
  for (const [key, item] of Object.entries(value)) {
    if (blockedKey(key)) continue;
    out[key] = item && typeof item === 'object' ? withoutSecrets(item) : item;
  }
  return out;
}
function requireID(id) {
  if (typeof id !== 'string' || !accountID.test(id)) throw new Error('账号标识无效');
  return id;
}
function cleanSettings(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('设置无效');
  const out = {};
  for (const k of ['auto_refresh', 'usage_probe']) {
    if (k in input) {
      if (typeof input[k] !== 'boolean') throw new Error('设置类型无效');
      out[k] = input[k];
    }
  }
  if ('proxy_url' in input) {
    if (typeof input.proxy_url !== 'string' || input.proxy_url.length > 2048) throw new Error('代理地址无效');
    out.proxy_url = input.proxy_url.trim();
  }
  return out;
}
function cleanLaunch(input) {
  if (!input || typeof input !== 'object') throw new Error('启动参数无效');
  requireID(input.account_id);
  const target = input.target || 'cli';
  if (!['cli', 'app'].includes(target)) throw new Error('启动目标无效');
  if (target === 'cli' && (typeof input.directory !== 'string' || !input.directory.trim() || input.directory.length > 4096)) throw new Error('请选择项目目录');
  const model = cleanModel(input.model);
  const effort = cleanEffort(input.effort);
  const channel = cleanChannel(input.channel), speed = input.speed ?? 'standard';
  if (!['standard', 'fast'].includes(speed)) throw new Error('请选择标准或快速模式');
  if (channel === 'bps' && speed !== 'standard') throw new Error('BPS 暂不支持快速模式，请选择标准速度或原生通道');
  const out = { account_id: input.account_id, directory: target === 'app' ? '' : input.directory, model, effort, resume: target === 'cli' && input.resume === true, target, channel, speed };
  if (target === 'app') {
    out.app_mode = input.app_mode ?? 'main';
    if (!['main', 'isolated'].includes(out.app_mode)) throw new Error('请选择主应用或独立实例');
  }
  for (const k of ['context_window', 'compact_limit']) {
    if (input[k] != null) {
      if (!Number.isSafeInteger(input[k])) throw new Error('上下文设置必须为整数');
      out[k] = input[k];
    }
  }
  return out;
}
function cleanPreferences(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('设置无效');
  const out = {};
  if ('account_speed' in input && input.account_speed != null) {
    const speed = input.account_speed;
    if (!speed || typeof speed !== 'object' || Array.isArray(speed)) throw new Error('速度设置无效');
    const value = speed.speed;
    if (value !== 'standard' && value !== 'fast') throw new Error('速度设置无效');
    out.account_speed = { id: requireID(speed.id), speed: value };
  }
  if ('compact_view' in input) {
    if (typeof input.compact_view !== 'boolean') throw new Error('设置类型无效');
    out.compact_view = input.compact_view;
  }
  for (const key of ['channel', 'pelican_channel']) if (key in input) out[key] = requireChannel(input[key]);
  if ('pelican_model' in input) out.pelican_model = cleanModel(input.pelican_model);
  if ('pelican_effort' in input) out.pelican_effort = cleanEffort(input.pelican_effort);
  if ('theme' in input) {
    if (!['system', 'light', 'dark'].includes(input.theme)) throw new Error('外观设置无效');
    out.theme = input.theme;
  }
  return out;
}
// Native theme only accepts three values. An unknown stored choice is left
// untouched and the control falls back without rewriting that preference.
function appliedTheme(value) {
  return value === 'light' || value === 'dark' || value === 'system' ? value : 'system';
}
function applyPreferences(prefs, input) {
  const patch = cleanPreferences(input);
  const next = withoutSecrets(prefs && typeof prefs === 'object' && !Array.isArray(prefs) ? prefs : {});
  if (patch.account_speed) next.account_speeds = { ...next.account_speeds, [patch.account_speed.id]: patch.account_speed.speed };
  for (const key of ['compact_view', 'channel', 'pelican_channel', 'pelican_model', 'pelican_effort', 'theme']) {
    if (Object.hasOwn(patch, key)) next[key] = patch[key];
  }
  return { prefs: next, theme: patch.theme };
}
function safeError(error) {
  return redactText(String(error?.message || error || '操作失败')).slice(0, 1200);
}
function asString(value) { return typeof value === 'string' ? value : ''; }
function asNumber(value) { return typeof value === 'number' && Number.isFinite(value) ? value : null; }
function publicWindow(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const out = {};
  if (typeof value.used_percent === 'number') out.used_percent = value.used_percent;
  if (typeof value.window_seconds === 'number') out.window_seconds = value.window_seconds;
  if (typeof value.reset_at === 'string') out.reset_at = value.reset_at;
  return Object.keys(out).length ? out : undefined;
}
function publicUsage(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const out = {};
  if (value.limit_reached === true) out.limit_reached = true;
  if (typeof value.updated_at === 'string') out.updated_at = value.updated_at;
  const primary = publicWindow(value.primary);
  const secondary = publicWindow(value.secondary);
  if (primary) out.primary = primary;
  if (secondary) out.secondary = secondary;
  return Object.keys(out).length ? out : undefined;
}
function publicAccount(account) {
  if (!account || typeof account !== 'object' || Array.isArray(account)) return null;
  return {
    id: asString(account.id), name: asString(account.name), email: asString(account.email), account_id: asString(account.account_id),
    plan_type: asString(account.plan_type), disabled: account.disabled === true, has_refresh_token: account.has_refresh_token === true,
    has_access_token: account.has_access_token === true, expired: account.expired === true, status: asString(account.status),
    last_error: asString(account.last_error), cooldown_until: asString(account.cooldown_until), expires_at: asString(account.expires_at),
    usage: publicUsage(account.usage)
  };
}
function publicHistory(record) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) return null;
  const out = {};
  for (const key of ['id', 'account_id', 'directory', 'model', 'effort', 'channel', 'speed', 'target', 'app_mode']) {
    if (typeof record[key] === 'string') out[key] = record[key];
  }
  for (const key of ['context_window', 'compact_limit']) if (typeof record[key] === 'number') out[key] = record[key];
  if (typeof record.last_used === 'string') out.last_used = record.last_used;
  return out;
}
function publicModel(model) {
  if (!model || typeof model !== 'object' || typeof model.id !== 'string' || !model.id) return null;
  const out = { id: model.id };
  if (typeof model.display_name === 'string' && model.display_name) out.display_name = model.display_name;
  return out;
}
function publicPreferences(prefs) {
  const source = prefs && typeof prefs === 'object' && !Array.isArray(prefs) ? prefs : {};
  const out = {};
  for (const key of ['directory', 'target', 'app_mode', 'channel', 'account_id', 'model', 'effort', 'pelican_channel', 'pelican_model', 'pelican_effort', 'theme']) {
    if (typeof source[key] === 'string') out[key] = source[key];
  }
  for (const key of ['context_window', 'compact_limit']) if (typeof source[key] === 'number') out[key] = source[key];
  if (typeof source.compact_view === 'boolean') out.compact_view = source.compact_view;
  if (source.account_speeds && typeof source.account_speeds === 'object' && !Array.isArray(source.account_speeds)) {
    const speeds = {};
    for (const [id, speed] of Object.entries(source.account_speeds)) if (speed === 'standard' || speed === 'fast') speeds[id] = speed;
    out.account_speeds = speeds;
  }
  return out;
}
function publicSnapshot(input) {
  const status = input?.status && typeof input.status === 'object' ? input.status : {};
  const codex = input?.codex && typeof input.codex === 'object' ? input.codex : {};
  const app = codex.app && typeof codex.app === 'object' ? codex.app : {};
  const mainApp = codex.main_app && typeof codex.main_app === 'object' ? codex.main_app : {};
  const models = input?.models && typeof input.models === 'object' ? input.models : {};
  const settings = input?.settings && typeof input.settings === 'object' ? input.settings : {};
  const catalog = (list) => (Array.isArray(list) ? list.map(publicModel).filter(Boolean) : []);
  const view = redactPublic({
    status: { home: asString(status.home) },
    accounts: Array.isArray(input?.accounts) ? input.accounts.map(publicAccount).filter(Boolean) : [],
    codex: {
      installed: codex.installed === true, binary: asString(codex.binary), error: asString(codex.error),
      active_account_id: asString(codex.active_account_id), model: asString(codex.model), effort: asString(codex.effort),
      app: { installed: app.installed === true, binary: asString(app.binary), error: asString(app.error) },
      main_app: { active: mainApp.active === true, home: asString(mainApp.home) },
      history: Array.isArray(codex.history) ? codex.history.map(publicHistory).filter(Boolean) : []
    },
    models: { catalog: catalog(models.catalog), native_catalog: catalog(models.native_catalog), bps_models: Array.isArray(models.bps_models) ? models.bps_models.filter(id => typeof id === 'string') : [] },
    settings: { proxy_url: asString(settings.proxy_url), auto_refresh: settings.auto_refresh === true, usage_probe: settings.usage_probe === true },
    preferences: publicPreferences(input?.preferences),
    platform: asString(input?.platform), version: asString(input?.version)
  });
  // The proxy field is an editor. Redact the same URL everywhere else, but
  // keep this copy intact so saving the form does not drop its password.
  view.settings.proxy_url = asString(settings.proxy_url);
  return view;
}
function publicLogs(payload) {
  const records = Array.isArray(payload?.records) ? payload.records : [];
  return redactPublic({ records: records.filter(record => record && typeof record === 'object').map(record => ({
    time: asString(record.time), model: asString(record.model), response_model: asString(record.response_model), effort: asString(record.effort),
    route: asString(record.route), service_tier: asString(record.service_tier), response_service_tier: asString(record.response_service_tier),
    status: asNumber(record.status), stream_status: asString(record.stream_status), error: asString(record.error), duration_ms: asNumber(record.duration_ms)
  })) });
}
function publicProbe(result) {
  const value = result && typeof result === 'object' ? result : {};
  // Route is the observed upstream choice. Leave it empty when missing so the
  // renderer cannot relabel the probe as the channel currently selected.
  const out = { ok: value.ok === true, model: asString(value.model), effort: asString(value.effort), route: asString(value.route), duration_ms: asNumber(value.duration_ms) };
  if (typeof value.error === 'string' && value.error) out.error = value.error;
  return redactPublic(out);
}
function publicImport(result) {
  if (result == null) return null;
  const value = result && typeof result === 'object' ? result : {};
  return redactPublic({
    imported: asNumber(value.imported) || 0, merged: asNumber(value.merged) || 0, skipped: asNumber(value.skipped) || 0,
    warnings: Array.isArray(value.warnings) ? value.warnings.filter(item => typeof item === 'string') : [],
    ids: Array.isArray(value.ids) ? value.ids.filter(item => typeof item === 'string') : [],
    ...(typeof value.files === 'number' ? { files: value.files } : {})
  });
}
function objectValue(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}
function publicLaunch(result, options) {
  const value = objectValue(result);
  if (value.cancelled === true) return { cancelled: true };
  const requested = objectValue(options);
  const out = { ok: true };
  if (requested.target === 'app' && (requested.app_mode === 'main' || requested.app_mode === 'isolated')) out.app_mode = requested.app_mode;
  if (typeof value.warning === 'string' && value.warning) out.warning = value.warning;
  return redactPublic(out);
}
function publicRestore(result) {
  const value = objectValue(result);
  if (value.cancelled === true) return { cancelled: true };
  const out = {};
  if (value.restored === true) out.restored = true;
  if (typeof value.warning === 'string' && value.warning) out.warning = value.warning;
  return redactPublic(out);
}
function publicAccountAction(result) {
  const value = objectValue(result);
  if (typeof value.id === 'string' && value.id) return redactPublic(publicAccount(value));
  return { ok: true };
}
function publicUsageResult(result) {
  return redactPublic({ ok: true, ...(publicUsage(result) || {}) });
}
function publicSettings(result) {
  const value = objectValue(result);
  const proxy = asString(value.proxy_url);
  const out = redactPublic({ proxy_url: proxy, auto_refresh: value.auto_refresh === true, usage_probe: value.usage_probe === true });
  out.proxy_url = proxy;
  return out;
}
function publicApp(app) {
  const value = objectValue(app);
  const out = { installed: value.installed === true };
  if (typeof value.error === 'string' && value.error) out.error = value.error;
  return redactPublic(out);
}
function publicServiceState(result) {
  return { reused: objectValue(result).reused === true };
}
function publicAbout(info) {
  const value = objectValue(info);
  return { version: asString(value.version), platform: asString(value.platform), arch: asString(value.arch) };
}
function publicSelection(accountID) {
  return { account_id: accountID };
}
const PROXY_EDITOR_KEYS = new Set(['proxy_url', 'auto_refresh', 'usage_probe']);
function proxyEditor(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  return keys.length > 0 && keys.every(key => PROXY_EDITOR_KEYS.has(key));
}
// IPC redacts the finished result. Restore only the proxy editor afterwards so
// the settings field still round-trips, while every other copy loses userinfo.
function rendererPayload(value) {
  const redacted = redactPublic(value);
  if (!value || typeof value !== 'object' || Array.isArray(value) || !redacted || typeof redacted !== 'object' || Array.isArray(redacted)) return redacted;
  const settings = value.settings;
  if (settings && typeof settings === 'object' && !Array.isArray(settings) && typeof settings.proxy_url === 'string' && redacted.settings && typeof redacted.settings === 'object' && !Array.isArray(redacted.settings)) {
    redacted.settings.proxy_url = settings.proxy_url;
  }
  if (proxyEditor(value) && typeof value.proxy_url === 'string') redacted.proxy_url = value.proxy_url;
  return redacted;
}
module.exports = { requireID, cleanSettings, cleanLaunch, cleanChannel, requireChannel, cleanModel, cleanEffort, cleanProbe, cleanPreferences, applyPreferences, appliedTheme, redactPublic, withoutSecrets, safeError, publicSnapshot, publicLogs, publicProbe, publicImport, publicLaunch, publicRestore, publicAccountAction, publicUsageResult, publicSettings, publicPreferences, publicApp, publicServiceState, publicAbout, publicSelection, rendererPayload };
