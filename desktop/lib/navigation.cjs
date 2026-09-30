'use strict';
const path = require('node:path');
const { fileURLToPath } = require('node:url');

const SAFE_PROTOCOLS = new Set(['data:', 'blob:', 'about:', 'devtools:', 'chrome-devtools:', 'chrome-extension:']);
const NETWORK_PROTOCOLS = new Set(['http:', 'https:', 'ws:', 'wss:']);

function fileInsideApp(url, appRoot) {
  if (typeof appRoot !== 'string' || !appRoot) return false;
  let target;
  try { target = fileURLToPath(url); } catch { return false; }
  const root = path.resolve(appRoot);
  const resolved = path.resolve(target);
  const relative = path.relative(root, resolved);
  return relative === '' || (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

// The renderer and model previews share one session. Network URLs are rejected
// unless they are the exact loopback preview; other files stay inside the app.
function rendererRequestAllowed(rawURL, appRoot, previewAllowed) {
  let url;
  try { url = new URL(String(rawURL)); } catch { return false; }
  if (url.protocol === 'file:') return fileInsideApp(url, appRoot);
  if (NETWORK_PROTOCOLS.has(url.protocol)) {
    if (typeof previewAllowed !== 'function') return false;
    try { return previewAllowed(String(rawURL)) === true; } catch { return false; }
  }
  return SAFE_PROTOCOLS.has(url.protocol);
}

module.exports = { rendererRequestAllowed };
