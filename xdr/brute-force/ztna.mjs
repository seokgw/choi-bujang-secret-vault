import { decide as existingDecide } from '../../src/decider.mjs';
import { extractAlert } from './read-alerts.mjs';

export function createDenyRules(alerts, decisions) {
  return decisions.filter(d => d.action === 'block').map(d => {
    const alert = alerts.find(a => a.id === d.alertId);
    const summary = extractAlert(alert);
    return { ruleId: 'xdr.brute-force.deny', alertId: d.alertId, source: summary.source,
      expiresAt: new Date(Date.parse(summary.timestamp) + 15 * 60_000).toISOString() };
  });
}

// trustedSource must come from a verified gateway, never from a request body.
// The existing engine contract has no IP-to-subject binding: production wiring is pending.
export async function decideWithDenyRules(request, { trustedSource, rules, now = Date.now() }) {
  const matched = rules.find(r => r.source === trustedSource && Number.isFinite(now)
    && now < Date.parse(r.expiresAt) && now >= Date.parse(r.expiresAt) - 15 * 60_000);
  if (!matched) return existingDecide(request);
  return { schema: 'aleph.decision.v1', requestId: request.requestId, decision: 'deny',
    reasonCode: 'starter_not_ready', ruleIds: [matched.ruleId] };
}
