import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createNotesHandler } from '../../api/notes.js';
import { decide } from './decide.mjs';
import { readAlerts } from './read-alerts.mjs';
import { createDenyRules, matchDeny } from './ztna.mjs';

const fixture = JSON.parse(await readFile(new URL('../fixtures/web-injection.json', import.meta.url)));
const extracted = await readAlerts();
assert.equal(extracted.length, fixture.alerts.length);
const decisions = [];
for (const a of fixture.alerts) decisions.push({ alertId: a.id, ...await decide(a) });
const now = Date.parse('2026-10-08T00:00:00Z');
// Fictional bindings solely for API replay; never persisted as operating rules.
const bindings = fixture.alerts.map((a, i) => ({ alertId: a.id,
  userId: `00000000-0000-4000-8000-${String(i + 1).padStart(12, '0')}` }));
const document = createDenyRules(decisions, bindings, now);
assert.equal(createDenyRules(decisions, [], now).rules.length, 0);
assert.equal(createDenyRules(decisions, [...bindings, ...bindings], now).rules.length, 0);
assert.equal(document.rules.length, 8);
for (const rule of document.rules) {
  assert(rule.alertId && Number.isFinite(Date.parse(rule.expiresAt)));
  assert.equal(Date.parse(rule.expiresAt) - Date.parse(rule.issuedAt), 15 * 60_000);
  const identity = { userId: bindings.find(b => b.alertId === rule.alertId).userId };
  assert(matchDeny(identity, document, now));
  assert.equal(matchDeny(identity, document, now - 1), null);
  assert.equal(matchDeny(identity, document, now + 15 * 60_000), null);
}
const counts = { blocked: 0, ambiguousAllowed: 0, normalAllowed: 0 };
for (let i = 0; i < decisions.length; i++) {
  const d = decisions[i];
  const number = Number(d.alertId.slice(3));
  const expected = number >= 18 ? 'record' : number <= 8 ? 'block' : 'alert';
  assert.equal(d.action, expected, d.alertId);
  let dbCalls = 0;
  const handler = createNotesHandler({ verify: async () => ({ userId: bindings[i].userId }),
    deny: identity => matchDeny(identity, document, now),
    settings: () => ({ key: 'fixture-placeholder', url: new URL('https://fixture.invalid') }),
    fetcher: async () => { dbCalls++; return Response.json([]); } });
  const res = { setHeader() {}, status(code) { this.code = code; return this; }, json(body) { this.body = body; return this; } };
  // Shared IP and spoofed user ID must not override verified identity.
  await handler({ method: 'GET', query: {}, headers: { 'x-forwarded-for': '192.0.2.1' },
    body: { userId: bindings[0].userId } }, res);
  assert.equal(res.code, expected === 'block' ? 403 : 200);
  assert.equal(dbCalls, expected === 'block' ? 0 : 1);
  counts[expected === 'block' ? 'blocked' : expected === 'alert' ? 'ambiguousAllowed' : 'normalAllowed']++;
}
assert.deepEqual(counts, { blocked: 8, ambiguousAllowed: 9, normalAllowed: 9 });
for (const description of ['명령 구분자 표기가 1번 있습니다.',
  '이름 검색에 구분 문자가 11건 있습니다.',
  '명령 구분자 표기가 연속 요청 7번에 있습니다.',
  '명령 구분자 표기가 11번 있지만 반복은 없습니다.']) {
  assert.equal((await decide({ rule: { level: 11, description } })).action, 'alert');
}
console.log('PASS: fixture API replay: 8 block candidates denied, 9 ambiguous and 9 normal requests allowed; command-separator boundaries, expiry, missing/duplicate binding and identity isolation verified. Operating bindings are not installed.');
