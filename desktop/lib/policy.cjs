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
  return { account_id: requireID(input.account_id), model: cleanModel(input.model), effort: cleanEffort(input.effort), channel: cleanChannel(input.channel) };
}
const SECRET_KEYS = new Set(['access_token', 'accesstoken', 'refresh_token', 'refreshtoken', 'id_token', 'idtoken', 'api_key', 'apikey', 'authorization', 'password', 'secret', 'client_secret', 'clientsecret', 'cockpit_key', 'cockpitkey', 'gptbridge_codex_key', 'personal_access_token', 'personalaccesstoken', 'openai_api_key', 'openaiapikey', 'experimental_bearer_token', 'bearer_token', 'bearertoken', 'auth_token', 'authtoken']);
const SECRET_TEXT = [
  [/eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g, '[凭据已隐藏]'],
  [/\bBearer\s+[A-Za-z0-9._~+/-]{12,}/gi, 'Bearer [凭据已隐藏]'],
  [/\brt_[A-Za-z0-9_-]{8,}\b/g, '[凭据已隐藏]'],
  [/\b(?:sk|rk)-[A-Za-z0-9_-]{12,}\b/g, '[凭据已隐藏]'],
  [/(cockpit-auth\/)[A-Fa-f0-9]{32,}/gi, '$1[凭据已隐藏]'],
  [/((?:access_token|refresh_token|id_token|api_key|cockpit_key|client_secret|personal_access_token|experimental_bearer_token|openai_api_key)["'\s:=]{1,8})[^\s"',&<]{8,}/gi, '$1[凭据已隐藏]']
];
function redactText(value) {
  let text = String(value);
  for (const [pattern, replacement] of SECRET_TEXT) text = text.replace(pattern, replacement);
  return text;
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
module.exports = { requireID, cleanSettings, cleanLaunch, cleanChannel, requireChannel, cleanModel, cleanEffort, cleanProbe, cleanPreferences, applyPreferences, redactPublic, withoutSecrets, safeError };
