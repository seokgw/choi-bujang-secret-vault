import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { decide } from './decide.mjs';
import { extractAlert, readAlerts } from './read-alerts.mjs';
import { configureJev } from './jev.mjs';
import { createDenyRules, decideWithDenyRules } from './ztna.mjs';
import { decide as baseline } from '../../src/decider.mjs';
import { fixtureRequests } from '../../scripts/fixture-7.mjs';

const fixture = JSON.parse(await readFile(new URL('../fixtures/brute-force.json', import.meta.url)));
const patterns = JSON.parse(await readFile(new URL('./patterns.json', import.meta.url)));
assert(patterns.every(p => p.name && p.finding && p.condition && p.evidence && !/[\r\n]/.test(p.evidence)));
const extracted = await readAlerts();
assert.equal(extracted.length, fixture.alerts.length);
assert(extracted.every(a => Object.keys(a).length === 5));
const blocks = new Set(['bf-01', 'bf-02', 'bf-03', 'bf-04', 'bf-06', 'bf-09']);
const decisions = [];
for (const alert of fixture.alerts) {
  const d = await decide(alert);
  const number = Number(alert.id.slice(3));
  assert.equal(d.action, number >= 20 ? 'record' : blocks.has(alert.id) ? 'block' : 'alert');
  decisions.push({ alertId: alert.id, ...d });
}
const ambiguous = fixture.alerts[10];
for (const adapter of [async () => { throw new Error(); }, async () => NaN, async () => 0.99,
  async () => 0.01, () => new Promise(() => {})]) {
  configureJev(adapter);
  assert.equal((await decide(ambiguous)).action, 'alert');
}
let calls = 0;
configureJev(async () => { calls++; return 0.6; });
await decide(fixture.alerts[0]); await decide(fixture.alerts[19]);
assert.equal(calls, 0);
await decide(ambiguous); assert.equal(calls, 1);
configureJev(undefined);
const contaminated = structuredClone(fixture.alerts[19]);
contaminated.rule.description = '로그인이 성공했습니다. token=DO_NOT_ECHO';
contaminated.data.password = 'DO_NOT_ECHO';
assert(!JSON.stringify(extractAlert(contaminated)).includes('DO_NOT_ECHO'));
assert(!JSON.stringify(await decide(contaminated)).includes('DO_NOT_ECHO'));
const rules = createDenyRules(fixture.alerts, decisions);
assert.equal(rules.length, blocks.size);
for (const rule of rules) {
  assert(rule.alertId && Number.isFinite(Date.parse(rule.expiresAt)));
  const request = fixtureRequests().normal;
  const options = { trustedSource: rule.source, rules: [rule], now: Date.parse(rule.expiresAt) - 1 };
  assert((await decideWithDenyRules(request, options)).ruleIds.includes('xdr.brute-force.deny'));
  assert.deepEqual(await decideWithDenyRules(request, { ...options, now: Date.parse(rule.expiresAt) }), await baseline(request));
}
for (const a of extracted.filter(a => a.description === 'normal-event')) {
  const request = fixtureRequests().normal;
  assert.deepEqual(await decideWithDenyRules(request, { trustedSource: a.source, rules, now: Date.parse(a.timestamp) }), await baseline(request));
}
console.log(`PASS: alerts ${extracted.length}, evidence ${patterns.length}, block ${blocks.size}, alert 13, record 9; normal XDR blocks 0; Jev failure/timeout and expiry tested. ZTNA baseline still denies normals.`);
