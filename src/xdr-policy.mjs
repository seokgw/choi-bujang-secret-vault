import { readFile } from 'node:fs/promises';

export const XDR_RULE_ID = 'xdr.brute-force.deny';
const patterns = new Set(['rapid-login-failures', 'password-spraying']);

// Only the trusted engine may supply these bindings. Never infer them from an IP,
// a browser request body, an email address or a Supabase user ID.
export function matchBoundDeny(request, document, now = Date.now()) {
  if (document?.schema !== 'aleph.xdr.bound-deny.v1' || !Array.isArray(document.rules)
      || request?.schema !== 'aleph.decision.v1' || !Number.isFinite(now)) return null;
  return document.rules.find(rule => {
    if (rule?.action !== 'block' || !Number.isFinite(rule.confidence) || rule.confidence < 0.85
        || rule.confidence > 1 || !patterns.has(rule.pattern)
        || typeof rule.alertId !== 'string' || !/^[a-zA-Z0-9_-]{1,80}$/.test(rule.alertId)) return false;
    const start = Date.parse(rule.issuedAt), end = Date.parse(rule.expiresAt);
    if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start
        || end - start > 15 * 60_000 || now < start || now >= end) return false;
    return ['classId', 'projectId', 'subjectId', 'deviceId'].every(field =>
      typeof rule[field] === 'string' && rule[field].length > 0
      && typeof request[field] === 'string' && request[field] === rule[field]);
  }) ?? null;
}

export async function activeDeny(request) {
  try {
    const document = JSON.parse(await readFile(new URL('../xdr/brute-force/active-rules.json', import.meta.url), 'utf8'));
    return matchBoundDeny(request, document);
  } catch {
    // Preserve the existing baseline policy when the optional rules are unavailable.
    return null;
  }
}
