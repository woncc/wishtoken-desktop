'use strict';
const $ = id => document.getElementById(id);
const api = window.bridge;
const state = { data: null, selected: '', page: 'accounts', effort: 'xhigh', effortAvailable: true, loading: false, initialized: false, connected: false, usageErrors: new Map(), busy: new Set(), accountSignature: '' };
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const icon = name => `<svg aria-hidden="true"><use href="#i-${name}"/></svg>`;
const accountByID = id => state.data?.accounts.find(account => account.id === id);
const label = account => account?.name || account?.email || account?.account_id || '未命名账号';
const planLabel = account => /business|team/i.test(account.plan_type || '') ? 'Business · Team' : (account.plan_type || 'Team').replaceAll('_', ' ');
function date(value) { if (!value || value.startsWith('0001-')) return '—'; return new Date(value).toLocaleString('zh-CN', { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false }); }
function ago(value) { if (!value || value.startsWith('0001-')) return '尚未查询'; const mins = Math.max(0, Math.round((Date.now() - new Date(value)) / 60000)); return mins < 1 ? '刚刚更新' : mins < 60 ? `${mins} 分钟前更新` : `${Math.floor(mins / 60)} 小时前更新`; }
function remaining(value) { const secs = Math.max(0, Math.ceil((new Date(value) - Date.now()) / 1000)); return secs > 3600 ? `${Math.ceil(secs / 3600)} 小时` : secs > 60 ? `${Math.ceil(secs / 60)} 分钟` : `${secs} 秒`; }
function visibleStatus(account) {
  if (account.last_error?.startsWith('bps_access_restricted:')) return { key: 'error', text: 'BPS 通道受限' };
  if (account.status === 'error' && account.last_error?.startsWith('rate limited (')) return { key: 'ready', text: '冷却结束 · 可重试' };
  const statuses = { ready: '凭据就绪', disabled: '已停用', expired: account.has_refresh_token ? '等待续期' : '凭据到期', cooldown: '冷却中', error: '待检查', no_credentials: '缺少凭据', needs_refresh: '待完善身份' };
  return { key: account.status, text: statuses[account.status] || account.status };
}
function statusHTML(account) { const status = visibleStatus(account); return `<span class="state ${esc(status.key)}"><span class="dot"></span>${esc(status.text)}${account.cooldown_until ? ` · <span data-countdown="${esc(account.cooldown_until)}">${remaining(account.cooldown_until)}</span>` : ''}</span>`; }
function toast(message, type = 'success', duration = 5000) {
  const node = document.createElement('div'); node.className = `toast ${type}`; node.textContent = message; $('toasts').append(node); setTimeout(() => node.remove(), duration);
}
function modal(html) { $('modal-content').innerHTML = html; if (!$('modal').open) $('modal').showModal(); }
function closeModal() { $('modal').close(); }
function empty(title, detail, action = '') { return `<div class="empty"><div class="empty-icon">${icon('grid')}</div><h2>${esc(title)}</h2><p>${esc(detail)}</p>${action}</div>`; }
async function action(key, fn) {
  if (state.busy.has(key)) return;
  state.busy.add(key); updateButtons();
  try { return await fn(); } catch (error) { toast(error.message, 'error', 9000); }
  finally { state.busy.delete(key); updateButtons(); }
}
function updateButtons() {
  for (const [id, key] of [['refresh-all', 'refresh-all'], ['import-files', 'import'], ['launch', 'launch'], ['resume', 'launch'], ['save-settings', 'settings'], ['repair-service', 'repair']]) {
    const button = $(id); button.disabled = state.busy.has(key); button.classList.toggle('spin', state.busy.has(key) && key === 'refresh-all');
  }
  const account = accountByID(state.selected);
  const appMode = $('launch-target').value === 'app';
  const selectionReady = $('channel').dataset.available !== 'false' && $('model').dataset.available !== 'false' && state.effortAvailable !== false && Boolean($('model').value);
  const unavailable = !selectionReady || !state.connected || !account || account.disabled || (account.expired && !account.has_refresh_token) || !(appMode ? state.data?.codex.app?.installed : state.data?.codex.installed) || (!appMode && !($('directory').value.trim())) || state.busy.has('launch');
  $('launch').disabled = unavailable;
  $('resume').disabled = unavailable || !state.data?.codex.history.some(item => item.account_id === state.selected && sameDir(item.directory, $('directory').value));
  $('launch').innerHTML = state.busy.has('launch') ? '正在启动…' : `切换并启动 ${appMode ? 'App' : 'CLI'}${icon('arrow')}`;
  $('resume').hidden = appMode; $('directory-field').hidden = appMode; $('app-directory-note').hidden = !appMode;
  $('choose-app').hidden = !appMode;
  $('app-mode-field').hidden = !appMode;
  $('app-directory-note').textContent = $('app-mode').value === 'main' ? '默认切换主 Codex App，沿用原有项目和已保存会话。重启前请保存正在运行的任务。' : '独立实例使用单独工作空间，不显示主应用项目与会话。';
  $('restore-main-app').disabled = !state.data?.codex.main_app?.active || state.busy.has('launch');
  $('main-app-home').textContent = state.data?.codex.main_app?.home || '—';
  $('select-account').disabled = !account || account.disabled || state.busy.has('select') || !state.connected;
  if (state.data) {
    const ready = appMode ? state.data.codex.app?.installed : state.data.codex.installed;
    $('cli-status').textContent = ready ? `已检测到 Codex ${appMode ? 'App' : 'CLI'}` : `未检测到 Codex ${appMode ? 'App' : 'CLI'}`;
    $('cli-status').title = appMode ? state.data.codex.app?.binary || '' : state.data.codex.binary || '';
    $('copy-install').hidden = appMode || ready;
  }
  document.querySelectorAll('[data-action="usage"], [data-action="test"]').forEach(button => { button.disabled = state.busy.has(`${button.dataset.action}-${button.dataset.id}`); });
}
function sameDir(a, b) { const normalize = value => value.trim().replace(/[\\/]+$/, ''); return state.data?.platform === 'win32' ? normalize(a).toLowerCase() === normalize(b).toLowerCase() : normalize(a) === normalize(b); }
function applyTheme(theme) {
  const dark = theme === 'dark' || (theme === 'system' && matchMedia('(prefers-color-scheme: dark)').matches);
  document.documentElement.dataset.theme = dark ? 'dark' : 'light';
}
function windowLabel(window, fallback) {
  if (!window) return fallback;
  const seconds = window.window_seconds;
  if (seconds === 18000) return '5 小时额度';
  if (seconds === 604800) return '7 天额度';
  return seconds >= 86400 ? `${Math.round(seconds / 86400)} 天额度` : `${Math.round(seconds / 3600)} 小时额度`;
}
function quotaHTML(window, fallback) {
  if (!window) return `<div><div class="quota-heading">${fallback}</div><div class="quota-missing">—</div><progress value="0" max="100"></progress><div class="quota-reset">接口暂未返回此窗口</div></div>`;
  const left = Math.max(0, Math.min(100, 100 - window.used_percent));
  return `<div><div class="quota-heading"><span>${esc(windowLabel(window, fallback))}</span><strong>${Number.isInteger(left) ? left : left.toFixed(1)}<small>% 剩余</small></strong></div><progress value="${left}" max="100" class="${left < 20 ? 'low' : ''}" aria-label="${esc(windowLabel(window, fallback))}剩余 ${left}%"></progress><div class="quota-reset">${date(window.reset_at)} 重置</div></div>`;
}
function renderAccounts() {
  const data = state.data; if (!data) return;
  $('nav-count').textContent = data.accounts.length;
  $('total-count').textContent = data.accounts.length;
  $('ready-count').textContent = data.accounts.filter(account => visibleStatus(account).key === 'ready').length;
  const active = accountByID(data.codex.active_account_id);
  $('current-label').textContent = active ? label(active) : '尚未启动';
  const query = $('search').value.trim().toLowerCase();
  const filter = $('filter').value;
  const accounts = data.accounts.filter(account => {
    const status = visibleStatus(account).key;
    const statusMatches = filter === 'all' || status === filter || (filter === 'error' && ['expired', 'no_credentials', 'needs_refresh'].includes(status));
    return statusMatches && `${label(account)} ${account.email} ${account.account_id}`.toLowerCase().includes(query);
  });
  const left = a => Math.min(...[a.usage?.primary, a.usage?.secondary].filter(Boolean).map(w => 100 - w.used_percent), 100);
  accounts.sort((a,b) => $('account-sort').value === 'name' ? label(a).localeCompare(label(b)) : $('account-sort').value === 'quota' ? (a.usage ? 0 : 1) - (b.usage ? 0 : 1) || left(b) - left(a) : Number(b.id === data.codex.active_account_id) - Number(a.id === data.codex.active_account_id));
  $('account-list').classList.toggle('compact', $('compact-view').checked);
  const options = data.accounts.map(a => `<option value="${esc(a.id)}" ${a.disabled ? 'disabled' : ''}>${esc(label(a))}${a.id === data.codex.active_account_id ? ' · 当前' : ''}</option>`).join('');
  if ($('quick-account').innerHTML !== options) $('quick-account').innerHTML = options;
  $('quick-account').value = state.selected;
  if (!accounts.length) {
    $('account-list').innerHTML = data.accounts.length ? empty('没有匹配的账号', '试试其他邮箱、备注或状态。') : empty('把你的 Team 子号带进来', '导入账号 JSON，即可查看额度并启动 Codex。', `<button class="primary" data-action="import">${icon('upload')}导入第一个账号</button>`);
    renderSelected(); return;
  }
  $('account-list').innerHTML = accounts.map(account => {
    const selected = account.id === state.selected;
    const warning = state.usageErrors.get(account.id);
    const current = account.id === data.codex.active_account_id;
    const secondaryLabel = account.usage?.primary?.window_seconds === 604800 ? '其他额度窗口' : '7 天额度';
    return `<article class="account-card${selected ? ' selected' : ''}" data-id="${esc(account.id)}" tabindex="0" role="button" aria-pressed="${selected}" aria-label="选择 ${esc(label(account))}">
      <div class="card-top"><div class="avatar">${esc(label(account).slice(0, 1).toUpperCase())}</div><div class="card-identity"><div class="card-name" title="${esc(label(account))}">${esc(label(account))}</div><div class="card-email" title="${esc(account.account_id)}">${esc(account.name ? account.email : `Team ${account.account_id}`)}</div></div>${selected ? `<span class="card-selected">${icon('check')}</span>` : ''}</div>
      <div class="card-tags"><span class="tag team">${esc(planLabel(account))}</span>${current ? '<span class="tag active">当前启动账号</span>' : ''}<span class="tag">${account.has_refresh_token ? '支持自动续期' : '到期后重新导入'}</span>${account.usage?.limit_reached ? '<span class="tag">额度已用尽</span>' : ''}</div>
      <div class="card-health">${statusHTML(account)}<span>${esc(ago(account.usage?.updated_at))}</span></div>
      <div class="quotas">${quotaHTML(account.usage?.primary, '5 小时额度')}${!account.usage || account.usage.secondary ? quotaHTML(account.usage?.secondary, secondaryLabel) : ''}</div>
      ${warning ? `<div class="card-warning">额度查询失败：${esc(warning)}${account.usage ? '；仍显示上次快照' : ''}</div>` : ''}
      ${account.last_error && account.status !== 'cooldown' && !account.last_error.startsWith('rate limited (') ? `<div class="card-warning">${esc(account.last_error)}</div>` : ''}
      <div class="card-speed"><span>${icon('bolt')}响应速度</span><select data-speed-id="${esc(account.id)}" aria-label="${esc(label(account))} 响应速度" ${nativeSpeed() ? '' : 'disabled title="仅原生通道可选快速"'}><option value="standard" ${accountSpeed(account.id) === 'standard' ? 'selected' : ''}>标准</option><option value="fast" ${accountSpeed(account.id) === 'fast' ? 'selected' : ''}>快速</option></select></div>
      <div class="card-bottom"><button class="card-launch" data-action="launch" data-id="${esc(account.id)}" ${account.disabled ? 'disabled' : ''}>${icon('arrow')}切换并启动</button><button data-action="pelican" data-id="${esc(account.id)}" title="鹈鹕测智">${icon('bolt')}测智</button><button data-action="usage" data-id="${esc(account.id)}" title="刷新额度">${icon('refresh')}</button><button data-action="edit" data-id="${esc(account.id)}" aria-label="管理 ${esc(label(account))}" title="管理账号">${icon('more')}</button></div>
    </article>`;
  }).join('');
  renderSelected(); updateButtons();
}
function renderSelected() {
  const account = accountByID(state.selected);
  $('selected-summary').innerHTML = account ? `<strong title="${esc(label(account))}">${esc(label(account))}</strong>${statusHTML(account)}` : '<span class="muted">先从左侧选择一个账号</span>';
  renderSpeed();
  updateButtons();
}
function setEffort(effort) {
  const choice = wishSelection.resolveEffort(effort);
  state.effort = choice.value;
  state.effortAvailable = choice.available;
  document.querySelectorAll('[data-effort]').forEach(button => { const chosen = choice.available && button.dataset.effort === choice.value; button.classList.toggle('chosen', chosen); button.setAttribute('aria-pressed', String(chosen)); });
  const hint = $('effort-hint');
  if (hint) { hint.hidden = choice.available; hint.textContent = choice.available ? '' : '当前推理档位不在可选列表中，未自动更换。'; }
}
function renderHistory() {
  const entries = state.data?.codex.history || [];
  $('history-list').innerHTML = entries.length ? entries.map(record => {
    const account = accountByID(record.account_id);
    const disabled = !account || account.disabled ? 'disabled' : '';
    const basename = record.target === 'app' ? 'Codex App' : record.directory.split(/[\\/]/).filter(Boolean).at(-1) || record.directory;
    return `<article class="history-row"><span class="icon-box">${icon('folder')}</span><div class="history-info"><strong>${esc(basename)}</strong><p title="${esc(record.directory)}">${record.target === 'app' ? record.app_mode === 'main' ? '主应用 · 原有项目与会话' : '独立实例 · 单独工作空间' : esc(record.directory)}</p><div class="history-meta"><span>${esc(account ? label(account) : '账号已移除')}</span><span>${channelLabel(record.channel)} · ${esc(record.model)} · ${esc(record.effort)}</span><span>${date(record.last_used)}</span></div></div><div class="history-actions"><button class="secondary" data-history="${esc(record.id)}" data-resume="false" ${disabled}>${record.target === 'app' ? '打开 App' : '新会话'}</button>${record.target === 'app' ? '' : `<button class="primary" data-history="${esc(record.id)}" data-resume="true" ${disabled}>继续会话${icon('arrow')}</button>`}</div></article>`;
  }).join('') : empty('还没有最近项目', '选择账号和项目目录，首次启动后会保存在这里。');
}
const channelLabel = channel => wishSelection.channelName(channel) || String(channel || 'BPS');
const speedLabel = speed => speed === 'fast' ? '快速' : '标准';
function nativeSpeed() { return $('channel').dataset.available !== 'false' && $('channel').value === 'codex'; }
function accountSpeed(id) { return nativeSpeed() ? state.data?.preferences.account_speeds?.[id] || 'standard' : 'standard'; }
function renderSpeed() {
  $('speed').value = accountSpeed(state.selected);
  $('speed').disabled = !nativeSpeed() || !state.selected;
  $('speed-hint').textContent = nativeSpeed() ? '按账号保存；快速模式会发送 priority。能否使用由账号和模型权限决定。' : ($('channel').value === 'bps' ? 'BPS 暂仅支持标准速度。切换到原生通道可选择快速。' : '当前通道不可用，未更换速度。');
}
async function saveSpeed(id, speed) { state.data.preferences = await api.preferences({account_speed:{id,speed}}); renderAccounts(); }
function pinExplicitOption(select, choice, labelFor) {
  [...select.options].filter(option => option.dataset.explicit === 'missing').forEach(option => option.remove());
  if (!choice.available && choice.value) {
    const option = document.createElement('option');
    option.value = choice.value;
    option.dataset.explicit = 'missing';
    option.textContent = labelFor(choice.value);
    select.append(option);
  }
  select.value = choice.value;
  select.dataset.available = String(choice.available && select.value === choice.value);
}
function channelModels(channel, select, preferred) {
  const models = wishSelection.modelsForChannel(state.data?.models, channel);
  const choice = wishSelection.resolveModelChoice(models, preferred);
  const options = models.map(model => `<option value="${esc(model.id)}">${esc(model.display_name || model.id)}</option>`);
  if (choice.explicit && !choice.available) options.unshift(`<option value="${esc(choice.value)}" data-explicit="missing">${esc(choice.value)} · 不在此通道</option>`);
  select.innerHTML = options.join('');
  select.value = choice.value;
  select.dataset.available = String(choice.available && select.value === choice.value);
  const hint = select.id === 'model' ? $('model-hint') : select.id === 'pelican-model' ? $('pelican-model-hint') : null;
  if (hint) { hint.hidden = choice.available; hint.textContent = choice.available ? '' : '此模型不在当前通道中，未自动更换。'; }
  return choice;
}
function launchChannel(channel, preferred) {
  const choice = wishSelection.resolveChannel(channel);
  pinExplicitOption($('channel'), choice, value => `${value} · 不在通道列表`);
  channelModels($('channel').value, $('model'), preferred);
  $('route-label').textContent = choice.available ? `${channelLabel(choice.value)} 通道` : '未选择有效通道';
  renderSpeed();
}
function applyInitial(data) {
  const preferences = data.preferences;
  state.selected = wishSelection.resolveAccountChoice(data.accounts, { activeId: data.codex.active_account_id, preferredId: preferences.account_id }).id;
  $('launch-target').value = preferences.target || (data.codex.app?.installed ? 'app' : 'cli');
  $('app-mode').value = preferences.app_mode || 'main';
  $('compact-view').checked = preferences.compact_view === true;
  launchChannel(preferences.channel, preferences.model || data.codex.model);
  setEffort(preferences.effort || data.codex.effort);
  $('directory').value = preferences.directory || '';
  $('context-window').value = preferences.context_window || 272000;
  $('compact-limit').value = preferences.compact_limit || 200000;
  $('proxy').value = data.settings.proxy_url || '';
  $('auto-refresh').checked = data.settings.auto_refresh;
  $('usage-probe').checked = data.settings.usage_probe;
  $('theme').value = preferences.theme || 'system'; applyTheme($('theme').value);
  $('data-home').textContent = data.status.home;
  $('platform').textContent = {darwin:'macOS',win32:'Windows',linux:'Linux'}[data.platform] || data.platform;
  $('version').textContent = `v${data.version}`;
  updateContextLabel();
}
async function refresh(quiet = false) {
  if (state.loading) return;
  state.loading = true;
  try {
    const data = await api.snapshot(); state.data = data; state.connected = true;
    if (!state.initialized) { applyInitial(data); state.initialized = true; }
    if (!accountByID(state.selected)) state.selected = '';
    $('connection-error').hidden = true; $('service-label').textContent = '本地服务运行中'; $('service-dot').classList.remove('danger-text');
    $('cli-status').innerHTML = data.codex.installed ? `${icon('check')}已检测到 Codex CLI` : '未检测到 Codex CLI';
    $('cli-status').title = data.codex.binary || data.codex.error;
    $('copy-install').hidden = data.codex.installed;
    const signature = JSON.stringify([data.accounts, data.codex.active_account_id, state.selected, [...state.usageErrors]]);
    if (signature !== state.accountSignature) { state.accountSignature = signature; renderAccounts(); }
    if (state.page === 'history') renderHistory();
    updateButtons();
  } catch (error) {
    state.connected = false;
    $('connection-error').hidden = false; $('connection-error').querySelector('span').textContent = `本地服务连接失败：${error.message}`;
    $('service-label').textContent = '本地服务未连接';
    $('launch').disabled = true; $('resume').disabled = true;
    if (!quiet) toast('本地服务尚未就绪，可点击“重新连接”。', 'error');
  } finally { state.loading = false; }
}
function switchPage(page) {
  state.page = page;
  document.querySelectorAll('.page').forEach(element => element.hidden = element.id !== `page-${page}`);
  document.querySelectorAll('[data-page]').forEach(button => { const current = button.dataset.page === page; button.classList.toggle('active', current); if (current) button.setAttribute('aria-current', 'page'); else button.removeAttribute('aria-current'); });
  $('page-title').textContent = { accounts: 'Team 账号', history: '最近项目', logs: '运行记录', settings: '设置', pelican: '鹈鹕测智' }[page];
  $('refresh-all').hidden = page !== 'accounts'; $('import-files').hidden = page !== 'accounts';
  if (page === 'history') renderHistory();
  if (page === 'logs') void loadLogs();
  if (page === 'pelican') void loadPelican();
}
async function refreshUsage(id, silent = false) {
  return action(`usage-${id}`, async () => {
    try { await api.usage(id); state.usageErrors.delete(id); if (!silent) toast('额度已更新'); }
    catch (error) { state.usageErrors.set(id, error.message); if (!silent) toast(error.message, 'error'); }
    await refresh(true);
  });
}
async function refreshMany(ids) {
  const queue = [...new Set(ids)];
  await Promise.all([0, 1].map(async () => { while (queue.length) await refreshUsage(queue.shift(), true); }));
  await refresh(true);
}
async function importResult(result) {
  if (!result) return;
  await refresh(true);
  if (result.ids?.length) { state.selected = result.ids[0]; renderAccounts(); }
  const message = `新增 ${result.imported} 个 · 更新 ${result.merged} 个${result.skipped ? ` · 跳过 ${result.skipped} 个` : ''}`;
  if (result.warnings?.length || (!result.imported && !result.merged)) {
    modal(`<h2>导入结果</h2><p>${esc(message)}</p><div class="import-results">${esc(result.warnings?.join('\n') || '没有识别到账号，请检查 JSON 中的 access_token 或 refresh_token。')}</div><div class="modal-actions"><button class="primary" id="close-results">知道了</button></div>`);
    $('close-results').onclick = closeModal;
  } else toast(message);
  if (result.ids?.length) { toast('正在查询新账号额度…', 'info', 2500); void refreshMany(result.ids); }
}
async function importFiles() { await action('import', async () => importResult(await api.importFiles())); }
function pasteDialog() {
  modal('<h2>粘贴账号 JSON</h2><p>支持单个 Team 子号、账号数组和常见导出格式。</p><textarea id="json-text" spellcheck="false" placeholder="在此粘贴 JSON…" aria-label="账号 JSON"></textarea><div class="modal-actions"><button class="secondary" id="cancel-paste">取消</button><button class="primary" id="submit-paste">导入账号</button></div>');
  $('cancel-paste').onclick = closeModal;
  $('submit-paste').onclick = () => action('import', async () => { const input = $('json-text').value.trim(); if (!input) throw new Error('请先粘贴 JSON'); $('submit-paste').disabled = true; try { const result = await api.importText(input); closeModal(); await importResult(result); } finally { if ($('submit-paste')) $('submit-paste').disabled = false; } });
  $('json-text').focus();
}
function editDialog(id) {
  const account = accountByID(id); if (!account) return;
  modal(`<h2>管理账号</h2><p>${esc(account.email || account.account_id)}</p><label class="field-label" for="account-name">备注名称</label><input class="full" id="account-name" value="${esc(account.name)}" placeholder="给这个账号起个备注"><label class="toggle-row"><span><strong>启用此账号</strong><small>停用后，该账号的 Codex 请求会被拒绝</small></span><input id="account-enabled" type="checkbox" ${account.disabled ? '' : 'checked'}></label><div class="info-row"><span>凭据到期</span><strong>${date(account.expires_at)}</strong></div><div class="modal-actions"><button class="secondary danger-text" id="remove-account">移除</button>${account.has_refresh_token ? '<button class="secondary" id="refresh-token">续期凭据</button>' : ''}${account.status === 'cooldown' ? '<button class="secondary" id="clear-cooldown">重试连接</button>' : ''}<button class="primary" id="save-account">保存</button></div>`);
  $('save-account').onclick = () => action('edit', async () => { await api.account({ id, action: 'update', name: $('account-name').value, disabled: !$('account-enabled').checked }); closeModal(); await refresh(true); toast('账号已保存'); });
  if ($('refresh-token')) $('refresh-token').onclick = () => action('edit', async () => { $('refresh-token').disabled = true; try { await api.account({ id, action: 'refresh' }); closeModal(); await refreshUsage(id); toast('凭据已续期'); } finally { if ($('refresh-token')) $('refresh-token').disabled = false; } });
  if ($('clear-cooldown')) $('clear-cooldown').onclick = () => action('edit', async () => { await api.account({ id, action: 'clear-cooldown' }); closeModal(); await testAccount(id); });
  $('remove-account').onclick = () => {
    modal(`<h2>移除这个账号？</h2><p>${esc(label(account))}</p><p>只移除本地凭据，已有项目记录会保留。正在使用该账号的 Codex 将无法继续请求。</p><div class="modal-actions"><button class="secondary" id="cancel-remove">取消</button><button class="primary" id="confirm-remove">移除账号</button></div>`);
    $('cancel-remove').onclick = closeModal;
    $('confirm-remove').onclick = () => action('edit', async () => { await api.account({ id, action: 'delete' }); closeModal(); state.usageErrors.delete(id); await refresh(true); toast('账号已移除'); });
  };
}
function launchOptions() { return { account_id: state.selected, app_mode: $('app-mode').value, channel: $('channel').value, speed: $('speed').value, directory: $('directory').value.trim(), target: $('launch-target').value, model: $('model').value, effort: state.effort, context_window: Number($('context-window').value), compact_limit: Number($('compact-limit').value) }; }
async function launch(resume = false, record) {
  await action('launch', async () => {
    const options = record ? { account_id: record.account_id, app_mode: record.app_mode || 'isolated', channel: record.channel || 'bps', speed:record.speed || 'standard', directory: record.directory, target: record.target || 'cli', model: record.model, effort: record.effort, context_window: record.context_window, compact_limit: record.compact_limit, resume } : { ...launchOptions(), resume };
    const result = await api.launch(options);
    if (result.cancelled) return;
    state.selected = options.account_id;
    $('launch-target').value = options.target;
    $('app-mode').value = options.app_mode || 'main';
    launchChannel(options.channel, options.model);
    $('directory').value = options.directory; $('model').value = options.model; setEffort(options.effort);
    $('context-window').value = options.context_window; $('compact-limit').value = options.compact_limit; updateContextLabel();
    await refresh(true); renderAccounts();
    toast(options.target === 'app' ? result.app_mode === 'main' ? '已切换主 Codex App，可继续原有项目和会话' : '已为该子号打开独立 Codex App' : resume ? '已打开终端，继续该项目上次的 Codex 会话' : '已切换账号并打开 Codex 终端');
    if (result.warning) toast(result.warning, 'error');
  });
}
async function testAccount(id) {
  await action(`test-${id}`, async () => {
    toast('正在测试模型连接，可能需要一两分钟…', 'info', 4500);
    const result = await api.test({ account_id: id, channel: $('channel').value, model: $('model').value, effort: state.effort });
    await refresh(true);
    if (!result.ok) throw new Error(result.error || '连接测试失败');
    toast(`连接成功 · ${result.model} / ${result.effort} · ${(result.duration_ms / 1000).toFixed(1)} 秒`, 'success', 8000);
  });
}
async function loadLogs() {
  try {
    const data = await api.logs();
    $('logs-list').innerHTML = data.records?.length ? `<table class="log-table"><thead><tr><th>时间</th><th>模型 / 推理</th><th>通道 / 速度</th><th>结果</th><th>耗时</th></tr></thead><tbody>${data.records.map(record => `<tr><td>${date(record.time)}</td><td><strong>${esc(record.model)}</strong><br><small>返回 ${esc(record.response_model || '未报告')}</small><br><span class="muted">${esc(record.effort)}</span></td><td><code>${esc(record.route)}</code><br><small>请求 ${esc(record.service_tier || 'standard')} → 返回 ${esc(record.response_service_tier || '未报告')}</small></td><td class="${record.status >= 400 || record.stream_status === 'failed' ? 'danger-text' : ''}" title="${esc(record.error)}">${record.status} ${esc(record.stream_status || '连接已建立')}${record.error ? `<br><small>${esc(record.error.slice(0, 180))}</small>` : ''}</td><td>${(record.duration_ms / 1000).toFixed(1)} s</td></tr>`).join('')}</tbody></table>` : empty('暂无请求记录', '启动 Codex 或测试连接后，实际请求会显示在这里。');
  } catch (error) { toast(error.message, 'error'); }
}
function updateContextLabel() { document.querySelector('.advanced summary span').textContent = `${Math.round(Number($('context-window').value) / 1000)}k / ${Math.round(Number($('compact-limit').value) / 1000)}k`; }

document.querySelector('nav').addEventListener('click', event => { const button = event.target.closest('[data-page]'); if (button) switchPage(button.dataset.page); });
$('import-files').onclick = importFiles;
$('paste-json').onclick = pasteDialog;
$('refresh-all').onclick = () => action('refresh-all', async () => { const ids = state.data?.accounts.filter(account => !account.disabled).map(account => account.id) || []; await refreshMany(ids); const failed = ids.filter(id => state.usageErrors.has(id)).length; toast(failed ? `${failed} 个账号查询失败，详情见账号卡片` : '全部额度已更新', failed ? 'error' : 'success'); });
$('search').oninput = renderAccounts; $('filter').onchange = renderAccounts;
$('account-sort').onchange = renderAccounts; $('compact-view').onchange = () => { renderAccounts(); void api.preferences({compact_view:$('compact-view').checked}); };
$('speed').onchange = () => action('speed', () => saveSpeed(state.selected, $('speed').value));
$('account-list').onchange = event => { if (event.target.dataset.speedId) void action('speed', () => saveSpeed(event.target.dataset.speedId, event.target.value)); };
$('quick-account').onchange = () => { state.selected = $('quick-account').value; renderAccounts(); };
async function selectAccount(id) { await action('select', async () => { await api.selectAccount(id); state.selected = id; await refresh(true); renderAccounts(); toast('当前账号已切换；已打开的会话仍使用原账号'); }); }
$('select-account').onclick = () => selectAccount(state.selected);
$('launch-target').onchange = updateButtons;
$('app-mode').onchange = updateButtons;
$('restore-main-app').onclick = () => action('launch', async () => { const result = await api.restoreMainApp(); if (result.cancelled) return; await refresh(true); toast('已恢复接管前的主应用配置'); if (result.warning) toast(result.warning, 'error'); });
$('choose-app').onclick = () => action('app-path', async () => { await api.chooseApp(); await refresh(true); });
$('account-list').onclick = event => {
  if (event.target.closest('[data-speed-id]')) return;
  const button = event.target.closest('[data-action]');
  if (button?.dataset.action === 'launch') { state.selected = button.dataset.id; renderAccounts(); if ($('launch').disabled) { toast('请先完成右侧启动设置', 'info'); $('launch-target').focus(); } else void launch(false); return; }
  if (button) { const { action, id } = button.dataset; if (action === 'usage') void refreshUsage(id); if (action === 'test') void testAccount(id); if (action === 'edit') editDialog(id); if (action === 'import') void importFiles(); if (action === 'switch') void selectAccount(id); if (action === 'pelican') { pelicanState.selected = new Set([id]); switchPage('pelican'); } return; }
  const card = event.target.closest('.account-card'); if (card) { state.selected = card.dataset.id; renderAccounts(); }
};
$('account-list').onkeydown = event => { if (event.target.classList.contains('account-card') && ['Enter', ' '].includes(event.key)) { event.preventDefault(); state.selected = event.target.dataset.id; renderAccounts(); } };
$('efforts').onclick = event => { const button = event.target.closest('[data-effort]'); if (button) setEffort(button.dataset.effort); };
$('choose-folder').onclick = () => action('folder', async () => { const directory = await api.chooseFolder(); if (directory) $('directory').value = directory; });
$('directory').oninput = updateButtons;
$('context-window').oninput = updateContextLabel; $('compact-limit').oninput = updateContextLabel;
$('launch').onclick = () => launch(false); $('resume').onclick = () => launch(true);
$('history-list').onclick = event => { const button = event.target.closest('[data-history]'); if (button) { const record = state.data.codex.history.find(record => record.id === button.dataset.history); if (record) void launch(button.dataset.resume === 'true', record); } };
$('save-settings').onclick = () => action('settings', async () => { await api.saveSettings({ proxy_url: $('proxy').value, auto_refresh: $('auto-refresh').checked, usage_probe: $('usage-probe').checked }); toast('连接设置已保存'); });
$('theme').onchange = () => action('theme', async () => { applyTheme($('theme').value); await api.preferences({ theme: $('theme').value }); });
$('channel').onchange = () => action('channel', async () => { launchChannel($('channel').value, $('model').value); if ($('channel').dataset.available !== 'false') await api.preferences({ channel: $('channel').value }); renderAccounts(); });
$('model').onchange = () => { channelModels($('channel').value, $('model'), $('model').value); updateButtons(); };
matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => applyTheme($('theme').value));
document.querySelectorAll('[data-link]').forEach(button => { button.onclick = () => action('link', () => api.openLink(button.dataset.link)); });
$('open-data').onclick = () => action('data', () => api.openData());
$('copy-install').onclick = () => action('install', async () => { await api.copyInstall(); toast('已复制安装命令，请在终端运行后重启客户端'); });
$('repair-service').onclick = () => action('repair', async () => { await api.repairService(); await refresh(); });
$('reload-logs').onclick = loadLogs;
$('modal').addEventListener('click', event => { if (event.target === $('modal')) { const r = $('modal').getBoundingClientRect(); if (event.clientX < r.left || event.clientX > r.right || event.clientY < r.top || event.clientY > r.bottom) closeModal(); } });
let dragDepth = 0;
document.addEventListener('dragenter', event => { if (event.dataTransfer.types.includes('Files')) { event.preventDefault(); dragDepth++; $('drop-overlay').hidden = false; } });
document.addEventListener('dragover', event => { event.preventDefault(); });
document.addEventListener('dragleave', () => { dragDepth--; if (dragDepth <= 0) $('drop-overlay').hidden = true; });
document.addEventListener('drop', event => { event.preventDefault(); dragDepth = 0; $('drop-overlay').hidden = true; const files = Array.from(event.dataTransfer.files); if (files.length) void action('import', async () => importResult(await api.importDropped(files))); });
setInterval(() => { document.querySelectorAll('[data-countdown]').forEach(node => node.textContent = remaining(node.dataset.countdown)); }, 1000);
setInterval(() => { if (!$('modal').open) void refresh(true); }, 8000);
void refresh(true);
