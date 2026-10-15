import { appendFile } from 'node:fs/promises';
import { decide as baselineDecide } from '../../src/decider.mjs';

const RULE_ID = 'xdr.exfiltration.deny';
const SCHEMA = 'aleph.xdr.bound-deny.v1';
const PATTERNS = new Set([
  'unfamiliar-destination-bulk-transfer',
  'off-hours-compressed-transfer',
  'repeated-command-channel-transfer'
]);
const FIELDS = ['classId', 'projectId', 'subjectId', 'deviceId'];
const TTL = 15 * 60_000;
const isId = x => typeof x === 'string' && /^[A-Za-z0-9_-]{1,80}$/.test(x);
const high = x => Number.isFinite(x) && x >= 0.85 && x <= 1;
const validDestination = x => typeof x === 'string' && /^[0-9a-fA-F:.]{3,45}$/.test(x);

// Bindings MUST come from a trusted server-side investigation, not Wazuh
// source IPs, browser inputs, or user-controlled destination claims.
export function createDenyRules(decisions, bindings = [], now = Date.now()) {
  if (!Array.isArray(decisions) || !Array.isArray(bindings) || !Number.isFinite(now)) {
    throw Error('invalid_exfiltration_input');
  }
  const rules = [];
  for (const d of decisions) {
    if (d?.action !== 'block' || !high(d.confidence) ||
        !PATTERNS.has(d.reason) || !isId(d.alertId)) continue;
    const matches = bindings.filter(b => b?.trusted === true && b.alertId === d.alertId &&
      validDestination(b.destination) &&
      FIELDS.every(k => typeof b[k] === 'string' && b[k].length > 0));
    if (matches.length !== 1) continue;
    const b = matches[0];
    rules.push({
      ruleId: RULE_ID, action: 'block', alertId: d.alertId,
      pattern: d.reason, confidence: d.confidence, destination: b.destination,
      ...Object.fromEntries(FIELDS.map(k => [k, b[k]])),
      issuedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + TTL).toISOString()
    });
  }
  return { schema: SCHEMA, rules };
}

// The ALEPH request contract has no destination field. The optional destination
// here must be supplied separately by a trusted gateway, never request.body.
export function matchDeny(request, document, destination, now = Date.now()) {
  if (request?.schema !== 'aleph.decision.v1' || document?.schema !== SCHEMA ||
      !Array.isArray(document.rules) || !validDestination(destination) ||
      !Number.isFinite(now)) return null;
  return document.rules.find(r => {
    const start = Date.parse(r?.issuedAt), end = Date.parse(r?.expiresAt);
    return r?.ruleId === RULE_ID && r.action === 'block' &&
      PATTERNS.has(r.pattern) && high(r.confidence) && isId(r.alertId) &&
      r.destination === destination && Number.isFinite(start) &&
      Number.isFinite(end) && end - start === TTL && start <= now && now < end &&
      FIELDS.every(k => typeof request[k] === 'string' && request[k] === r[k]);
  }) ?? null;
}

// Opt-in wrapper; all requests without a verified destination match retain
// the unchanged baseline decision.
export async function decideWithDenyRules(request, { document, trustedDestination, now = Date.now() } = {}) {
  const rule = matchDeny(request, document, trustedDestination, now);
  if (!rule) return baselineDecide(request);
  return { schema: 'aleph.decision.v1', requestId: request.requestId,
    decision: 'deny', reasonCode: 'starter_not_ready', ruleIds: [RULE_ID] };
}

// Only sanitized classification metadata is appended; never raw Wazuh events.
export async function appendAlerts(decisions, output = new URL('../alerts.log', import.meta.url)) {
  if (!Array.isArray(decisions)) throw Error('invalid_exfiltration_decisions');
  let written = 0;
  for (const d of decisions) {
    if (!['block', 'alert'].includes(d?.action) || !isId(d.alertId) ||
        !Number.isFinite(d.confidence) || d.confidence < 0 || d.confidence > 1) continue;
    await appendFile(output, JSON.stringify({
      moduleKey: 'exfiltration', alertId: d.alertId, action: d.action,
      confidence: d.confidence, reason: PATTERNS.has(d.reason) ? d.reason : 'unspecified',
      runAt: new Date().toISOString()
    }) + '\n', 'utf8');
    written++;
  }
  return written;
}
