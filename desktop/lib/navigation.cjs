'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { fileURLToPath } = require('node:url');

const SAFE_PROTOCOLS = new Set(['data:', 'blob:', 'about:', 'devtools:', 'chrome-devtools:', 'chrome-extension:']);
const NETWORK_PROTOCOLS = new Set(['http:', 'https:', 'ws:', 'wss:']);

function insideRoot(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

// Lexical containment is not enough: a symlink inside the app can point at
// another directory. Missing files may stay, but every existing ancestor,
// including a broken symlink, has to resolve inside the real app root.
function resolvedInside(root, candidate) {
  let realRoot;
  try { realRoot = fs.realpathSync(root); }
  catch { return false; }
  let cursor = candidate;
  for (;;) {
    try { fs.lstatSync(cursor); }
    catch (error) {
      if (error.code !== 'ENOENT') return false;
      const parent = path.dirname(cursor);
      if (parent === cursor) return false;
      cursor = parent;
      continue;
    }
    try { return insideRoot(realRoot, fs.realpathSync(cursor)); }
    catch { return false; }
  }
}

function fileInsideApp(url, appRoot) {
  if (typeof appRoot !== 'string' || !appRoot) return false;
  let target;
  try { target = fileURLToPath(url); } catch { return false; }
  const root = path.resolve(appRoot);
  const resolved = path.resolve(target);
  if (!insideRoot(root, resolved)) return false;
  return resolvedInside(root, resolved);
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
