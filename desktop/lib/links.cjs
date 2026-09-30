'use strict';
const LINKS = Object.freeze({
  website: 'https://wishtoken.team/?utm_source=wishtoken-desktop&utm_medium=app',
  project: 'https://github.com/xxx-holic/wishtoken-desktop',
  community: 'https://t.me/shouhouqun',
  releases: 'https://github.com/xxx-holic/wishtoken-desktop/releases',
  invitations: 'https://github.com/xxx-holic/wishtoken-desktop/discussions/categories/announcements'
});
function externalLink(name) {
  if (typeof name !== 'string' || !Object.hasOwn(LINKS, name)) throw new Error('Unknown external destination');
  return LINKS[name];
}
module.exports = { externalLink };
