'use strict';
// Cross-host, unsigned development packaging. Native signed releases use electron-builder.
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { downloadArtifact } = require('@electron/get');
const asar = require('@electron/asar');

async function main() {
  const desktop = path.resolve(__dirname, '..');
  const root = path.dirname(desktop);
  const pkg = require('../package.json');
  const electronVersion = require('electron/package.json').version;
  const requested = process.argv.slice(2);
  const architectures = requested.length ? requested : ['arm64', 'x64'];
  if (architectures.some(a => !['arm64', 'x64'].includes(a))) throw new Error('Expected arm64 or x64');
  const stagingRoot = path.join(root, 'build', 'mac-staging');
  await fs.mkdir(stagingRoot, { recursive: true });
  const stage = await fs.mkdtemp(path.join(stagingRoot, 'app-'));
  const payload = path.join(stage, 'payload');
  await fs.mkdir(payload);
  // Fixed allowlist: no node_modules, account data, diagnostic captures or test fixtures.
  for (const item of ['main.cjs', 'preload.cjs', 'lib', 'renderer', 'assets/icon.png']) {
    const output = path.join(payload, item);
    await fs.mkdir(path.dirname(output), { recursive: true });
    await fs.cp(path.join(desktop, item), output, { recursive: true });
  }
  const metadata = Object.fromEntries(['name', 'productName', 'version', 'description', 'main', 'author', 'license'].filter(k => pkg[k] !== undefined).map(k => [k, pkg[k]]));
  await fs.writeFile(path.join(payload, 'package.json'), JSON.stringify(metadata, null, 2) + '\n');
  const appAsar = path.join(stage, 'app.asar');
  await asar.createPackage(payload, appAsar);
  const integrity = crypto.createHash('sha256').update(asar.getRawHeader(appAsar).headerString).digest('hex');
  const python = process.env.PYTHON_BINARY || (process.platform === 'win32' ? 'python' : 'python3');
  const runtimes = await Promise.all(architectures.map(async arch => ({ arch, archive: await downloadArtifact({ version: electronVersion, artifactName: 'electron', platform: 'darwin', arch, cacheRoot: process.env.ELECTRON_CACHE || path.join(root, 'build', 'electron-cache') }) })));
  for (const { arch, archive } of runtimes) {
    const result = spawnSync(python, [path.join(__dirname, 'package-mac.py'), '--runtime', archive, '--arch', arch, '--asar', appAsar, '--integrity', integrity], { cwd: root, stdio: 'inherit', windowsHide: true });
    if (result.error) throw result.error;
    if (result.status) throw new Error(`Mac ${arch} package failed (${result.status})`);
  }
  console.log('Unsigned Mac development packages created. Native macOS launch/signing verification remains required.');
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
