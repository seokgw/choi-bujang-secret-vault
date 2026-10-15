import { appendFile } from 'node:fs/promises';
import { decide as existingDecide } from '../../src/decider.mjs';

const RULE_ID = 'xdr.known-cve.deny';
const ALLOWED = new Set(['log4shell-jndi-header', 'log4shell-jndi-query']);
const BIND_FIELDS = ['classId', 'projectId', 'subjectId', 'deviceId'];
const ID = /^[A-Za-z0-9_-]{1,80}$/;
const TTL = 15 * 60_000;

// Only incident-investigation bindings from a trusted server are usable.
// A Wazuh srcip, fictional account, or HTTP request body is NOT a binding.
export function createDenyRules(decisions, bindings = [], issuedAt = Date.now()) {
  if (!Array.isArray(decisions) || !Array.isArray(bindings) || !Number.isFinite(issuedAt)) {
    throw new Error('invalid_known_cve_input');
  }
  const rules = [];
  for (const d of decisions) {
    if (d?.action !== 'block' || !Number.isFinite(d.confidence)
        || d.confidence < 0.85 || d.confidence > 1 || !ALLOWED.has(d.reason)
        || typeof d.alertId !== 'string' || !ID.test(d.alertId)) continue;
    // Require exactly one server-verified binding to this exact alert.
    const matches = bindings.filter(b => b?.trusted === true && b.alertId === d.alertId
      && BIND_FIELDS.every(k => typeof b[k] === 'string' && b[k].length > 0));
    if (matches.length !== 1) continue;
    const binding = matches[0];
    rules.push({
      ruleId: RULE_ID, alertId: d.alertId, pattern: d.reason,
      action: 'block', confidence: d.confidence,
      ...Object.fromEntries(BIND_FIELDS.map(k => [k, binding[k]])),
      issuedAt: new Date(issuedAt).toISOString(),
      expiresAt: new Date(issuedAt + TTL).toISOString(),
    });
  }
  return { schema: 'aleph.xdr.bound-deny.v1', rules };
}

export function matchDeny(request, document, now = Date.now()) {
  if (request?.schema !== 'aleph.decision.v1'
      || document?.schema !== 'aleph.xdr.bound-deny.v1'
      || !Array.isArray(document.rules) || !Number.isFinite(now)) return null;
  return document.rules.find(r => {
    const issued = Date.parse(r.issuedAt), expires = Date.parse(r.expiresAt);
    return r.ruleId === RULE_ID && r.action === 'block' && ALLOWED.has(r.pattern)
      && ID.test(r.alertId ?? '') && Number.isFinite(r.confidence)
      && r.confidence >= 0.85 && r.confidence <= 1
      && Number.isFinite(issued) && Number.isFinite(expires)
      && expires - issued === TTL && issued <= now && now < expires
      && BIND_FIELDS.every(k => typeof request[k] === 'string' && request[k] === r[k]);
  }) ?? null;
}

// Opt-in wrapper for a trusted ZTNA caller. The existing decider is unchanged.
// With no verified rule, the baseline policy decides as before.
export async function decideWithDenyRules(request, { document, now = Date.now() } = {}) {
  const rule = matchDeny(request, document, now);
  if (!rule) return existingDecide(request);
  return { schema: 'aleph.decision.v1', requestId: request.requestId,
    decision: 'deny', reasonCode: 'starter_not_ready', ruleIds: [RULE_ID] };
}

// The only file writer here. Never store raw alerts, URLs, users or credentials.
export async function appendAlerts(decisions, path = new URL('../alerts.log', import.meta.url)) {
  if (!Array.isArray(decisions)) throw new Error('invalid_known_cve_decisions');
  let written = 0;
  for (const d of decisions) {
    if (!['block', 'alert'].includes(d?.action) || !ID.test(d?.alertId ?? '')
        || !Number.isFinite(d?.confidence) || d.confidence < 0 || d.confidence > 1) continue;
    const entry = { moduleKey: 'known-cve', alertId: d.alertId,
      action: d.action, confidence: d.confidence,
      reason: ALLOWED.has(d.reason) || d.reason === 'known-cve-probe-indicator'
        ? d.reason : 'unspecified', runAt: new Date().toISOString() };
    await appendFile(path, JSON.stringify(entry) + '\n', 'utf8');
    written += 1;
  }
  return written;
}
