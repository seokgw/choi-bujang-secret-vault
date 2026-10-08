import { readFile } from 'node:fs/promises';
import { extractAlert } from './read-alerts.mjs';
import { askJev } from './jev.mjs';

const patterns = JSON.parse(await readFile(new URL('./patterns.json', import.meta.url), 'utf8'));
function response(confidence, reason) {
  return { action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record', confidence, reason };
}
export async function decide(alert) {
  const summary = extractAlert(alert);
  if (summary.description === 'normal-event') return response(0.1, 'normal-event');
  const matched = patterns.find(p => summary.source && summary.timestamp
    && summary.description === p.condition.description && summary.level >= p.condition.minimumLevel);
  if (matched) return response(matched.condition.confidence, matched.name);
  try {
    const confidence = await askJev(summary);
    if (!Number.isFinite(confidence) || confidence < 0 || confidence > 1) throw new Error('Invalid confidence');
    return response(confidence, 'ambiguous-failures');
  } catch {
    return response(0.5, 'ambiguous-failures');
  }
}
