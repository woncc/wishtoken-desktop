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
  return { modelsForChannel, resolveModelChoice, resolveChannel, resolveEffort, resolveAccountChoice, channelName, resolvePelicanDefaults };
});
