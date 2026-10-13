// Resource names describe routes, not users, roles or access permission.
export const RESOURCE_IDS = Object.freeze({ notes: 'notes', notices: 'notices' });

export function resourceIdForPath(path) {
  if (typeof path !== 'string') return null;
  const match = /^\/api\/(notes|notices)(?:\/([1-9][0-9]{0,9}))?$/u.exec(path);
  if (!match || (match[2] && Number(match[2]) > 2147483647)) return null;
  return match[2] ? `${RESOURCE_IDS[match[1]]}:${match[2]}` : RESOURCE_IDS[match[1]];
}
