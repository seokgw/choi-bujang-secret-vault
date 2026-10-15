import { appendFile } from 'node:fs/promises';
import { decide as baselineDecide } from '../../src/decider.mjs';

const RULE_ID = 'xdr.persistence.deny';
const SCHEMA = 'aleph.xdr.bound-deny.v1';
const PATTERNS = new Set([
  'unsigned-new-service',
  'unfamiliar-scheduled-task',
  'unfamiliar-startup-folder'
]);
const FIELDS = ['classId', 'projectId', 'subjectId', 'deviceId'];
const TTL_MS = 15 * 60 * 1000;
const validId = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,80}$/.test(value);
const validConfidence = value => Number.isFinite(value) && value >= 0.85 && value <= 1;

// Trust bindings supplied by server-side incident investigation only.
export function createDenyRules(decisions, bindings = [], now = Date.now()) {
  if (!Array.isArray(decisions) || !Array.isArray(bindings) || !Number.isFinite(now)) {
    throw new Error('invalid_persistence_input');
  }
  const rules = [];
  for (const d of decisions) {
    if (d?.action !== 'block' || !validConfidence(d.confidence)
        || !PATTERNS.has(d.reason) || !validId(d.alertId)) continue;
    const matches = bindings.filter(b => b?.trusted === true && b.alertId === d.alertId
      && FIELDS.every(field => typeof b[field] === 'string' && b[field].length > 0));
    if (matches.length !== 1) continue;
    const binding = matches[0];
    rules.push({
      ruleId: RULE_ID, alertId: d.alertId, action: 'block',
      pattern: d.reason, confidence: d.confidence,
      ...Object.fromEntries(FIELDS.map(field => [field, binding[field]])),
      issuedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + TTL_MS).toISOString()
    });
  }
  return { schema: SCHEMA, rules };
}

export function matchDeny(request, document, now = Date.now()) {
  if (request?.schema !== 'aleph.decision.v1' || document?.schema !== SCHEMA
      || !Array.isArray(document.rules) || !Number.isFinite(now)) return null;
  return document.rules.find(rule => {
    const issued = Date.parse(rule?.issuedAt);
    const expires = Date.parse(rule?.expiresAt);
    return rule?.ruleId === RULE_ID && rule.action === 'block'
      && PATTERNS.has(rule.pattern) && validId(rule.alertId)
      && validConfidence(rule.confidence)
      && Number.isFinite(issued) && Number.isFinite(expires)
      && expires - issued === TTL_MS && issued <= now && now < expires
      && FIELDS.every(field => typeof request[field] === 'string'
        && request[field] === rule[field]);
  }) ?? null;
}

export async function decideWithDenyRules(request, { document, now = Date.now() } = {}) {
  if (!matchDeny(request, document, now)) return baselineDecide(request);
  return {
    schema: 'aleph.decision.v1', requestId: request.requestId,
    decision: 'deny', reasonCode: 'starter_not_ready', ruleIds: [RULE_ID]
  };
}

// Logs only bounded classifications, never raw events or identifying fields.
export async function appendAlerts(decisions, output = new URL('../alerts.log', import.meta.url)) {
  if (!Array.isArray(decisions)) throw new Error('invalid_persistence_decisions');
  let written = 0;
  for (const d of decisions) {
    if (!['block', 'alert'].includes(d?.action) || !validId(d.alertId)
        || !Number.isFinite(d.confidence) || d.confidence < 0 || d.confidence > 1) continue;
    const entry = {
      moduleKey: 'persistence', alertId: d.alertId, action: d.action,
      confidence: d.confidence,
      reason: PATTERNS.has(d.reason) ? d.reason : 'unspecified',
      runAt: new Date().toISOString()
    };
    await appendFile(output, JSON.stringify(entry) + '\n', 'utf8');
    written += 1;
  }
  return written;
}
