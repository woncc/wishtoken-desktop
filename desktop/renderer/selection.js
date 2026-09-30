'use strict';
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module != null && module.exports && typeof require === 'function') module.exports = api;
  else root.wishSelection = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  const EFFORTS = ['low', 'medium', 'high', 'xhigh'];
  function modelEntries(list) {
    if (!Array.isArray(list)) return [];
    return list.filter(model => model && typeof model.id === 'string' && model.id);
  }
  function modelsForChannel(payload, channel) {
    const catalog = payload && typeof payload === 'object' ? payload : {};
    if (channel === 'codex') return modelEntries(catalog.native_catalog);
    if (channel === 'bps') {
      const allowed = new Set(Array.isArray(catalog.bps_models) ? catalog.bps_models : []);
      return modelEntries(catalog.catalog).filter(model => allowed.has(model.id));
    }
    return [];
  }
  // Keep an explicit choice that the current list cannot serve. Callers must
  // not replace it with another model, channel, effort, or account.
  function resolveModelChoice(models, preferred) {
    const options = modelEntries(models);
    const ids = new Set(options.map(model => model.id));
    if (typeof preferred === 'string' && preferred) return { value: preferred, explicit: true, available: ids.has(preferred) };
    if (options.length) return { value: options[0].id, explicit: false, available: true };
    return { value: '', explicit: false, available: false };
  }
  function resolveChannel(value) {
    if (value == null || value === '') return { value: 'bps', explicit: false, available: true };
    if (value === 'bps' || value === 'codex') return { value, explicit: true, available: true };
    return { value: String(value), explicit: true, available: false };
  }
  function resolveEffort(value) {
    if (value == null || value === '') return { value: 'xhigh', explicit: false, available: true };
    if (EFFORTS.includes(value)) return { value, explicit: true, available: true };
    return { value: String(value), explicit: true, available: false };
  }
  function resolveAccountChoice(accounts, input) {
    const list = Array.isArray(accounts) ? accounts.filter(account => account && typeof account.id === 'string' && account.id) : [];
    const activeId = input?.activeId || '';
    const preferredId = input?.preferredId || '';
    const has = id => !!id && list.some(account => account.id === id);
    if (has(activeId)) return { id: activeId, reason: 'active' };
    if (has(preferredId)) return { id: preferredId, reason: 'preferred' };
    if (activeId || preferredId) return { id: '', reason: 'missing' };
    const fallback = list.find(account => !account.disabled);
    return { id: fallback ? fallback.id : '', reason: fallback ? 'initial' : 'none' };
  }
  function channelName(channel) {
    if (channel === 'codex') return '原生 Codex';
    if (channel == null || channel === '' || channel === 'bps') return 'BPS';
    return '';
  }
  function resolveChoice(value, allowed, fallback) {
    const options = Array.isArray(allowed) ? allowed : [];
    if (value == null || value === '') return { value: fallback, explicit: false, available: options.includes(fallback) };
    const text = String(value);
    return { value: text, explicit: true, available: options.includes(text) };
  }
  function explicitNumber(value, fallback) {
    return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
  }
  // Missing legacy speed is standard. Any other recorded value stays unnamed
  // so the history row cannot present it as standard.
  function speedName(speed) {
    if (speed == null || speed === '' || speed === 'standard') return '标准';
    if (speed === 'fast') return '快速';
    return '';
  }
  function historyPlace(record) {
    const value = record && typeof record === 'object' && !Array.isArray(record) ? record : {};
    const target = value.target;
    if (target == null || target === '' || target === 'cli') {
      const directory = typeof value.directory === 'string' ? value.directory : '';
      return { kind: 'directory', title: directory, text: directory };
    }
    if (target === 'app') {
      if (value.app_mode === 'main') return { kind: 'app', title: '主应用 · 原有项目与会话', text: '主应用 · 原有项目与会话' };
      if (value.app_mode === 'isolated') return { kind: 'app', title: '独立实例 · 单独工作空间', text: '独立实例 · 单独工作空间' };
      return { kind: 'app', title: '未标明 App 工作空间', text: '未标明 App 工作空间' };
    }
    return { kind: 'other', title: String(target), text: String(target) };
  }
  function recorded(value, fallback) {
    return value == null || value === '' ? fallback : value;
  }
  // Replay a saved launch exactly. Absent legacy fields keep their original
  // meaning; an explicit value is never rewritten, and App mode is never invented.
  function replayLaunch(record, resume) {
    if (!record || typeof record !== 'object' || Array.isArray(record)) return { ok: false, error: '启动记录无效' };
    const target = recorded(record.target, 'cli');
    if (target !== 'cli' && target !== 'app') return { ok: false, error: '启动目标无效，未自动更换' };
    const channel = recorded(record.channel, 'bps');
    if (channel !== 'bps' && channel !== 'codex') return { ok: false, error: '记录中的通道无效，未自动更换' };
    const speed = recorded(record.speed, 'standard');
    if (speed !== 'standard' && speed !== 'fast') return { ok: false, error: '记录中的速度无效，未自动更换' };
    if (channel === 'bps' && speed !== 'standard') return { ok: false, error: 'BPS 暂不支持快速模式，未改成标准速度' };
    if (typeof record.model !== 'string' || !record.model) return { ok: false, error: '记录中没有模型，未自动更换' };
    if (typeof record.effort !== 'string' || !record.effort) return { ok: false, error: '记录中没有推理档位，未自动更换' };
    const options = {
      account_id: record.account_id,
      channel,
      speed,
      directory: typeof record.directory === 'string' ? record.directory : '',
      target,
      model: record.model,
      effort: record.effort,
      context_window: record.context_window,
      compact_limit: record.compact_limit,
      resume: target === 'cli' && resume === true
    };
    if (target === 'app') {
      if (record.app_mode !== 'main' && record.app_mode !== 'isolated') return { ok: false, error: '这条记录没有明确的 App 工作空间，未自动改为独立实例' };
      options.app_mode = record.app_mode;
    }
    return { ok: true, options };
  }
  // A saved pelican choice stays put. Launch-panel values are only the
  // initial default when the compare view has never recorded its own.
  function resolvePelicanDefaults(preferences, launch) {
    const prefs = preferences && typeof preferences === 'object' ? preferences : {};
    const launchModel = launch && typeof launch.model === 'string' ? launch.model : '';
    const launchEffort = launch && typeof launch.effort === 'string' ? launch.effort : '';
    const model = typeof prefs.pelican_model === 'string' && prefs.pelican_model ? prefs.pelican_model : launchModel;
    const effortValue = typeof prefs.pelican_effort === 'string' && prefs.pelican_effort ? prefs.pelican_effort : launchEffort;
    return { channel: resolveChannel(prefs.pelican_channel), model, effort: resolveEffort(effortValue) };
  }
  return { modelsForChannel, resolveModelChoice, resolveChannel, resolveEffort, resolveAccountChoice, channelName, resolveChoice, explicitNumber, speedName, historyPlace, resolvePelicanDefaults, replayLaunch };
});
