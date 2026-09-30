'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const preload = fs.readFileSync(path.join(__dirname, '../preload.cjs'), 'utf8');
const main = fs.readFileSync(path.join(__dirname, '../main.cjs'), 'utf8');
const methods = [...preload.matchAll(/^  ([A-Za-z]+):/gm)].map(match => match[1]);

test('preload exposes only named bridge methods and main keeps the renderer sandbox', () => {
  assert.deepEqual(methods, ['snapshot', 'importFiles', 'importText', 'importDropped', 'chooseFolder', 'usage', 'account', 'launch', 'restoreMainApp', 'selectAccount', 'chooseApp', 'pelicanHistory', 'pelicanStart', 'pelicanCancel', 'pelicanDelete', 'pelicanSource', 'pelicanExport', 'test', 'saveSettings', 'preferences', 'logs', 'openLink', 'openData', 'repairService', 'copyInstall', 'about']);
  assert.match(preload, /contextBridge\.exposeInMainWorld\('bridge'/);
  assert.doesNotMatch(preload, /ipcRenderer\.send|exposeInMainWorld\('require'|exposeInMainWorld\('electron'/);
  assert.match(main, /contextIsolation: true/);
  assert.match(main, /nodeIntegration: false/);
  assert.match(main, /sandbox: true/);
  assert.match(main, /will-frame-navigate/);
  assert.match(main, /allowedPreview/);
  assert.match(main, /redactPublic\(await handle/);
  assert.match(main, /applyPreferences/);
  assert.match(main, /withoutSecrets\(prefs\)/);
  assert.doesNotMatch(main, /nodeIntegration: true|sandbox: false|webviewTag: true/);
});
