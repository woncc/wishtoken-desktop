'use strict';

const accountID = /^acc-[a-zA-Z0-9-]{1,80}$/;
function cleanChannel(value) {
  const channel = value ?? 'bps';
  if (!['bps', 'codex'].includes(channel)) throw new Error('请选择 BPS 或原生通道');
  return channel;
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
  if (typeof input.model !== 'string' || !/^[a-zA-Z0-9.-]{1,80}$/.test(input.model)) throw new Error('模型无效');
  if (!['low', 'medium', 'high', 'xhigh'].includes(input.effort)) throw new Error('推理档位无效');
  const channel = cleanChannel(input.channel), speed = input.speed ?? 'standard';
  if (!['standard', 'fast'].includes(speed)) throw new Error('请选择标准或快速模式');
  if (channel === 'bps' && speed !== 'standard') throw new Error('BPS 暂不支持快速模式，请选择标准速度或原生通道');
  const out = { account_id: input.account_id, directory: target === 'app' ? '' : input.directory, model: input.model, effort: input.effort, resume: target === 'cli' && input.resume === true, target, channel, speed };
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
function safeError(error) {
  return String(error?.message || error || '操作失败').replace(/eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g, '[凭据已隐藏]').slice(0, 1200);
}
module.exports = { requireID, cleanSettings, cleanLaunch, cleanChannel, safeError };
