'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { modelsForChannel, resolveModelChoice, resolveChannel, resolveEffort, resolveAccountChoice, channelName, resolvePelicanDefaults, replayLaunch } = require('../renderer/selection.js');

const catalog = {
  catalog: [
    { id: 'gpt-6-astra', display_name: 'GPT-6 Astra' },
    { id: 'gpt-5.6-terra', display_name: 'GPT-5.6 Terra' },
    { id: 'gpt-5.6-sol', display_name: 'GPT-5.6 Sol' }
  ],
  native_catalog: [
    { id: 'gpt-6-astra', display_name: 'GPT-6 Astra' },
    { id: 'gpt-5.6-terra', display_name: 'GPT-5.6 Terra' }
  ],
  bps_models: ['gpt-6-astra', 'gpt-5.6-sol']
};

test('an explicit model outside the channel list is kept and not replaced', () => {
  const bps = modelsForChannel(catalog, 'bps');
  const choice = resolveModelChoice(bps, 'gpt-5.6-terra');
  assert.deepEqual(bps.map(model => model.id), ['gpt-6-astra', 'gpt-5.6-sol']);
  assert.equal(choice.value, 'gpt-5.6-terra');
  assert.equal(choice.explicit, true);
  assert.equal(choice.available, false);
  assert.equal(resolveModelChoice(modelsForChannel(catalog, 'codex'), 'gpt-5.6-terra').available, true);
  assert.deepEqual(modelsForChannel(catalog, 'automatic'), []);
  assert.equal(resolveModelChoice(bps, '').explicit, false);
  assert.equal(resolveModelChoice(bps, '').value, 'gpt-6-astra');
});

test('unknown channel and effort stay explicit instead of becoming the defaults', () => {
  assert.deepEqual(resolveChannel('codex'), { value: 'codex', explicit: true, available: true });
  assert.deepEqual(resolveChannel(undefined), { value: 'bps', explicit: false, available: true });
  assert.equal(resolveChannel('automatic').available, false);
  assert.equal(resolveChannel('automatic').value, 'automatic');
  assert.equal(resolveEffort('max').value, 'max');
  assert.equal(resolveEffort('max').available, false);
  assert.equal(resolveEffort(undefined).value, 'xhigh');
  assert.equal(channelName('codex'), '原生 Codex');
  assert.equal(channelName('bps'), 'BPS');
  assert.equal(channelName('automatic'), '');
});

test('a missing explicit account is not replaced by another account', () => {
  const accounts = [{ id: 'acc-a', disabled: true }, { id: 'acc-b', disabled: false }, { id: 'acc-c', disabled: false }];
  assert.equal(resolveAccountChoice(accounts, { activeId: 'acc-c', preferredId: 'acc-b' }).id, 'acc-c');
  assert.equal(resolveAccountChoice(accounts, { preferredId: 'acc-a' }).id, 'acc-a');
  assert.deepEqual(resolveAccountChoice(accounts, { preferredId: 'acc-gone' }), { id: '', reason: 'missing' });
  assert.deepEqual(resolveAccountChoice(accounts, { activeId: 'acc-gone' }), { id: '', reason: 'missing' });
  assert.equal(resolveAccountChoice(accounts, {}).id, 'acc-b');
});

test('renderer no longer falls back to the first listed model', () => {
  const app = fs.readFileSync(path.join(__dirname, '../renderer/app.js'), 'utf8');
  const pelican = fs.readFileSync(path.join(__dirname, '../renderer/pelican.js'), 'utf8');
  assert.equal(app.includes('selectedIndex'), false);
  assert.match(app, /resolveModelChoice/);
  assert.match(app, /resolveAccountChoice/);
  assert.match(app, /speedLabel\(record\.speed\)/);
  assert.match(pelican, /dataset\.available/);
  assert.match(pelican, /resolvePelicanDefaults/);
  assert.match(pelican, /pelican_model/);
  assert.doesNotMatch(pelican, /channelModels\(\$\('pelican-channel'\)\.value, \$\('pelican-model'\), \$\('model'\)\.value\)/);
  assert.match(app, /replayLaunch/);
  assert.doesNotMatch(app, /app_mode \|\| 'isolated'/);
  assert.doesNotMatch(pelican, /item\.route \|\| b\.channel/);
  assert.match(pelican, /返回通道/);
  assert.doesNotMatch(app, /service_tier \|\| 'standard'/);
  assert.match(app, /service_tier \|\| '未报告'/);
  assert.match(app, /record\.route \|\| '未报告'/);
});
test('a saved pelican model is not replaced by the launch-panel model', () => {
  const saved = resolvePelicanDefaults({ pelican_channel: 'bps', pelican_model: 'gpt-5.6-sol', pelican_effort: 'low' }, { model: 'gpt-6-astra', effort: 'xhigh' });
  assert.equal(saved.channel.value, 'bps');
  assert.equal(saved.model, 'gpt-5.6-sol');
  assert.equal(saved.effort.value, 'low');
  const initial = resolvePelicanDefaults({ pelican_channel: 'codex' }, { model: 'gpt-5.6-terra', effort: 'high' });
  assert.equal(initial.model, 'gpt-5.6-terra');
  assert.equal(initial.effort.value, 'high');
  const kept = resolvePelicanDefaults({ pelican_model: 'gpt-5.6-terra', pelican_effort: 'max' }, { model: 'gpt-6-astra', effort: 'xhigh' });
  assert.equal(kept.model, 'gpt-5.6-terra');
  assert.equal(kept.effort.value, 'max');
  assert.equal(kept.effort.available, false);
});

test('history replay keeps explicit choices and does not invent an app workspace', () => {
  const legacy = replayLaunch({ account_id: 'acc-1', directory: '/work', model: 'gpt-6-astra', effort: 'high' }, true);
  assert.equal(legacy.ok, true);
  assert.equal(legacy.options.target, 'cli');
  assert.equal(legacy.options.channel, 'bps');
  assert.equal(legacy.options.speed, 'standard');
  assert.equal(legacy.options.resume, true);
  assert.equal(legacy.options.app_mode, undefined);
  const native = replayLaunch({ account_id: 'acc-1', directory: '/work', model: 'gpt-5.6-terra', effort: 'max', channel: 'codex', speed: 'fast', target: 'cli' }, false);
  assert.equal(native.options.channel, 'codex');
  assert.equal(native.options.speed, 'fast');
  assert.equal(native.options.effort, 'max');
  assert.equal(native.options.resume, false);
  const main = replayLaunch({ account_id: 'acc-1', model: 'gpt-6-astra', effort: 'xhigh', target: 'app', app_mode: 'main', channel: 'codex', speed: 'standard' }, true);
  assert.equal(main.options.app_mode, 'main');
  assert.equal(main.options.resume, false);
  assert.equal(replayLaunch({ account_id: 'acc-1', model: 'gpt-6-astra', effort: 'xhigh', target: 'app', app_mode: 'isolated', channel: 'bps' }).options.app_mode, 'isolated');
  const missing = replayLaunch({ account_id: 'acc-1', model: 'gpt-6-astra', effort: 'xhigh', target: 'app', channel: 'codex' }, false);
  assert.equal(missing.ok, false);
  assert.match(missing.error, /未自动改为独立实例/);
  assert.equal(replayLaunch({ account_id: 'acc-1', model: 'gpt-6-astra', effort: 'high', channel: 'automatic' }).ok, false);
  assert.equal(replayLaunch({ account_id: 'acc-1', model: 'gpt-6-astra', effort: 'high', speed: 'ultrafast' }).ok, false);
  assert.equal(replayLaunch({ account_id: 'acc-1', model: 'gpt-6-astra', effort: 'high', channel: 'bps', speed: 'fast' }).ok, false);
  assert.equal(replayLaunch({ account_id: 'acc-1', effort: 'high', channel: 'codex' }).ok, false);
});
