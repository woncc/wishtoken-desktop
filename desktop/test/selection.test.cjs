'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { modelsForChannel, resolveModelChoice, resolveChannel, resolveEffort, resolveAccountChoice, channelName } = require('../renderer/selection.js');

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
  assert.match(pelican, /dataset\.available/);
});
