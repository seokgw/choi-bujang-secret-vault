import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { extractAlert } from './read-alerts.mjs';
import { askJev } from './jev.mjs';

const patterns = JSON.parse(await readFile(new URL('./patterns.json', import.meta.url), 'utf8'));
const signals = new Set(['rapid-login-failures', 'password-spraying', 'normal-event', 'ambiguous-failures', 'repeated-login-failures-policy']);
function summaryOf(alert) {
  if (alert?.rule) return extractAlert(alert);
  // Accept the five-field output of readAlerts without re-extracting it as Wazuh.
  // Only known signal labels survive; free text and additional fields are discarded.
  const time = Date.parse(alert?.timestamp);
  return {
    timestamp: Number.isFinite(time) ? new Date(time).toISOString() : null,
    source: typeof alert?.source === 'string' && isIP(alert.source) ? alert.source : null,
    account: typeof alert?.account === 'string' && /^user\d{2}$/.test(alert.account) ? alert.account : null,
    level: Number.isInteger(alert?.level) ? alert.level : null,
    description: signals.has(alert?.description) ? alert.description : 'unknown',
  };
}
function response(confidence, reason) {
  return { action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record', confidence, reason };
}
export async function decide(alert) {
  const summary = summaryOf(alert);
  if (summary.description === 'normal-event') return response(0.1, 'normal-event');
  const matched = patterns.find(p => summary.source && summary.timestamp
    && (summary.description === p.condition.description || p.condition.alternativeDescriptions?.includes(summary.description))
    && (p.condition.minimumLevel === 0 || (Number.isInteger(summary.level) && summary.level >= p.condition.minimumLevel)));
  if (matched) return response(summary.description === matched.condition.description
    ? matched.condition.confidence : matched.condition.alternativeConfidence, matched.name);
  try {
    const confidence = await askJev(summary);
    if (!Number.isFinite(confidence) || confidence < 0 || confidence > 1) throw new Error('Invalid confidence');
    return response(confidence, 'ambiguous-failures');
  } catch {
    return response(0.5, 'ambiguous-failures');
  }
}
