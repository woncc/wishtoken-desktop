'use strict';
const { contextBridge, ipcRenderer, webUtils } = require('electron');
const invoke = (method, data) => ipcRenderer.invoke('gptbridge', method, data).then(result => {
  if (!result.ok) throw new Error(result.error);
  return result.data;
});
contextBridge.exposeInMainWorld('bridge', Object.freeze({
  snapshot: () => invoke('snapshot'),
  importFiles: () => invoke('importFiles'),
  importText: text => invoke('importText', text),
  importDropped: files => invoke('importPaths', Array.from(files, file => webUtils.getPathForFile(file))),
  chooseFolder: () => invoke('chooseFolder'),
  usage: id => invoke('usage', id),
  account: data => invoke('account', data),
  launch: data => invoke('launch', data),
  selectAccount: id => invoke('selectAccount', id),
  chooseApp: () => invoke('chooseApp'),
  pelicanHistory: () => invoke('pelicanHistory'),
  pelicanStart: data => invoke('pelicanStart', data),
  pelicanCancel: () => invoke('pelicanCancel'),
  pelicanDelete: id => invoke('pelicanDelete', id),
  pelicanSource: id => invoke('pelicanSource', id),
  pelicanExport: id => invoke('pelicanExport', id),
  test: data => invoke('test', data),
  saveSettings: data => invoke('saveSettings', data),
  preferences: data => invoke('preferences', data),
  logs: () => invoke('logs'),
  openLink: name => invoke('openLink', name),
  openData: () => invoke('openData'),
  repairService: () => invoke('repairService'),
  copyInstall: () => invoke('copyInstall'),
  about: () => invoke('about')
}));
