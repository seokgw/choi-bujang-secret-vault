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
const blocks = new Set(['bf-01', 'bf-02', 'bf-03', 'bf-04', 'bf-05', 'bf-06', 'bf-07', 'bf-08', 'bf-09', 'bf-10', 'bf-13', 'bf-14', 'bf-15', 'bf-16', 'bf-18', 'bf-19']);
const recovered = new Set(['bf-11', 'bf-12', 'bf-17']);
const decisions = [];
for (const alert of fixture.alerts) {
  const d = await decide(alert);
  const number = Number(alert.id.slice(3));
  assert.equal(d.action, number >= 20 || recovered.has(alert.id) ? 'record' : blocks.has(alert.id) ? 'block' : 'alert');
  decisions.push({ alertId: alert.id, ...d });
  assert.deepEqual(await decide(extractAlert(alert)), d);
}
const ambiguous = { ...fixture.alerts[12], rule: { level: 5, description: '로그인 실패 2건입니다.' } };
for (const adapter of [async () => { throw new Error(); }, async () => NaN,
  async () => -0.1, async () => 1.1, () => new Promise(() => {})]) {
  configureJev(adapter);
  assert.equal((await decide(ambiguous)).action, 'alert');
}
for (const [confidence, action] of [[0, 'record'], [0.49, 'record'], [0.5, 'alert'],
  [0.84, 'alert'], [0.85, 'block'], [1, 'block']]) {
  configureJev(async () => confidence);
  const out = await decide(ambiguous);
  assert.equal(out.action, action);
  assert.equal(out.confidence, confidence);
  assert.deepEqual(Object.keys(out).sort(), ['action', 'confidence', 'reason']);
  assert(!/[\r\n]/.test(out.reason));
}
let calls = 0;
configureJev(async () => { calls++; return 0.6; });
await decide(fixture.alerts[0]); await decide(fixture.alerts[19]);
assert.equal(calls, 0);
await decide(ambiguous); assert.equal(calls, 1);
configureJev(undefined);
for (const description of ['로그인 실패 29건이 이어졌습니다.',
  '같은 주소가 계정 9개에 같은 간격으로 로그인 실패를 넣었습니다.',
  '100분 동안 로그인 실패 40건이 이어졌습니다.']) {
  assert.equal((await decide({ ...fixture.alerts[0], rule: { level: 12, description } })).action, 'alert');
}
assert.equal((await decide({ ...fixture.alerts[0], rule: { level: 6,
  description: '로그인 실패 40건이 이어졌습니다.' } })).action, 'block');
assert.equal((await decide({ ...fixture.alerts[10], rule: { level: 6, description: '로그인 실패 4건입니다.' } })).action, 'block');
for (const description of ['로그인 실패 7건 뒤에 성공했습니다.',
  '여러 계정에 로그인 실패 4건 뒤에 성공했습니다.']) {
  const event = { ...fixture.alerts[10], rule: { level: 6, description } };
  assert.equal((await decide(event)).action, 'alert');
}
assert.equal((await decide({ ...fixture.alerts[0], rule: { level: 12,
  description: '같은 주소에서 2분 안에 로그인 실패 48건 뒤에 성공했습니다.' } })).action, 'block');
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
console.log(`PASS: alerts ${extracted.length}, evidence ${patterns.length}, block ${blocks.size}, alert 0, record 12; fixture normal XDR blocks 0; stricter unresolved-failure policy, recovered-login boundaries, Jev failure/timeout and expiry tested. ZTNA baseline still denies normals.`);
