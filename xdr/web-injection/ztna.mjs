import { createVaultDenyRules, matchVaultDeny } from '../../src/vault-xdr.mjs';

const patterns = new Set(['sql-injection', 'script-tag-injection', 'repeated-path-traversal']);

// Supply bindings only from a trusted server investigation, never from the
// request body, source IP or a training account. Missing bindings create no rule.
export function createDenyRules(decisions, bindings, issuedAt = Date.now()) {
  if (!Array.isArray(decisions)) throw new Error('invalid_web_injection_decisions');
  return createVaultDenyRules(decisions.filter(d => patterns.has(d?.reason)), bindings, issuedAt);
}

// Existing notes API uses this same matcher and server-only rule document.
export function matchDeny(identity, document, now = Date.now()) {
  return matchVaultDeny(identity, document, now);
}
