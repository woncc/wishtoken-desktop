'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { externalLink } = require('../lib/links.cjs');
test('external navigation accepts only named HTTPS destinations', () => {
  assert.equal(new URL(externalLink('website')).hostname, 'wishtoken.team');
  for (const value of ['file:///tmp/a', 'javascript:alert(1)', 'https://evil.test', '__proto__', 'toString', null, {}]) assert.throws(() => externalLink(value));
});
