import { createHash } from 'node:crypto';
import config from '../aleph.config.json' with { type: 'json' };

const schema = 'aleph.vault.xdr-deny.v1';
const patterns = new Set(['rapid-login-failures', 'password-spraying',
  'sql-injection', 'script-tag-injection', 'repeated-path-traversal']);
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function subjectHash(userId) {
  if (typeof userId !== 'string' || !uuid.test(userId)) return null;
  return createHash('sha256').update(`${config.identityProvider.issuer}\n${userId}`).digest('hex');
}

// Bindings must be supplied by a trusted server-side incident investigation.
// Never derive a user binding from an IP, alert account name or request body.
export function createVaultDenyRules(decisions, bindings, issuedAt = Date.now()) {
  if (!Array.isArray(decisions) || !Array.isArray(bindings) || !Number.isFinite(issuedAt)) {
    throw new Error('invalid_vault_xdr_input');
  }
  const rules = [];
  for (const decision of decisions) {
    const matches = bindings.filter(b => b.alertId === decision.alertId);
    if (matches.length !== 1 || decision.action !== 'block'
        || !Number.isFinite(decision.confidence) || decision.confidence < 0.85
        || decision.confidence > 1 || !patterns.has(decision.reason)
        || typeof decision.alertId !== 'string' || !/^[a-zA-Z0-9_-]{1,80}$/.test(decision.alertId)) continue;
    const hash = subjectHash(matches[0].userId);
    if (!hash) continue;
    rules.push({ action: 'block', confidence: decision.confidence, pattern: decision.reason,
      alertId: decision.alertId, subjectHash: hash,
      issuedAt: new Date(issuedAt).toISOString(),
      expiresAt: new Date(issuedAt + 15 * 60_000).toISOString() });
  }
  return { schema, rules };
}

export function matchVaultDeny(identity, document, now = Date.now()) {
  const hash = subjectHash(identity?.userId);
  if (!hash || document?.schema !== schema || !Array.isArray(document.rules)
      || !Number.isFinite(now)) return null;
  return document.rules.find(rule => {
    if (rule?.action !== 'block' || rule.subjectHash !== hash
        || !Number.isFinite(rule.confidence) || rule.confidence < 0.85 || rule.confidence > 1
        || !patterns.has(rule.pattern) || typeof rule.alertId !== 'string'
        || !/^[a-zA-Z0-9_-]{1,80}$/.test(rule.alertId)) return false;
    const start = Date.parse(rule.issuedAt), end = Date.parse(rule.expiresAt);
    return Number.isFinite(start) && Number.isFinite(end) && end > start
      && end - start <= 15 * 60_000 && now >= start && now < end;
  }) ?? null;
}

export async function activeVaultDeny(identity) {
  // Server-only setting; never return or copy its contents into the public build.
  const raw = process.env.VAULT_XDR_DENY_RULES_JSON;
  if (!raw || raw.length > 65536) return null;
  try { return matchVaultDeny(identity, JSON.parse(raw)); }
  catch { return null; }
}
