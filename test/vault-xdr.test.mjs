import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { createNotesHandler } from '../api/notes.js';
import { createVaultDenyRules, matchVaultDeny, activeVaultDeny } from '../src/vault-xdr.mjs';
import { decide } from '../xdr/brute-force/decide.mjs';

const attacker = '00000000-0000-4000-8000-000000000001';
const normal = '00000000-0000-4000-8000-000000000002';
const now = Date.parse('2026-10-08T00:00:00Z');
const block = { alertId: 'bf-01', action: 'block', confidence: 0.95, reason: 'rapid-login-failures' };
function response() { return { setHeader() {}, status(n) { this.code = n; return this; }, json(body) { this.body = body; return this; } }; }

test('vault API rejects only bound block subjects before DB access; same IP and spoofed body do not block others', async () => {
  const document = createVaultDenyRules([block], [{ alertId: block.alertId, userId: attacker }], now);
  let calls = 0;
  for (const userId of [attacker, normal]) {
    const handler = createNotesHandler({ verify: async () => ({ userId }),
      deny: identity => matchVaultDeny(identity, document, now),
      settings: () => ({ key: 'fixture-placeholder', url: new URL('https://fixture.invalid') }),
      fetcher: async () => { calls++; return Response.json([]); } });
    const res = response();
    await handler({ method: 'GET', query: {}, headers: { 'x-forwarded-for': '192.0.2.1' },
      body: { userId: attacker } }, res);
    assert.equal(res.code, userId === attacker ? 403 : 200);
    if (res.code === 403) assert.deepEqual(res.body, { error: 'forbidden' });
  }
  assert.equal(calls, 1);
  assert(!JSON.stringify(document).includes(attacker));
  assert.equal(matchVaultDeny({ userId: attacker }, document, now + 15 * 60_000), null);
  assert.equal(matchVaultDeny({ userId: attacker }, document, now - 1), null);
});

test('alert, record, missing or duplicate binding and malformed rules never produce a vault block', () => {
  const bindings = [{ alertId: block.alertId, userId: attacker }];
  for (const action of ['alert', 'record']) assert.equal(createVaultDenyRules([{ ...block, action }], bindings, now).rules.length, 0);
  assert.equal(createVaultDenyRules([block], [], now).rules.length, 0);
  assert.equal(createVaultDenyRules([block], [...bindings, ...bindings], now).rules.length, 0);
  const document = createVaultDenyRules([block], bindings, now);
  for (const change of [{ alertId: '' }, { expiresAt: 'invalid' }, { confidence: 0.84 },
    { expiresAt: new Date(now + 16 * 60_000).toISOString() }, { pattern: 'invented' }]) {
    assert.equal(matchVaultDeny({ userId: attacker }, { ...document, rules: [{ ...document.rules[0], ...change }] }, now), null);
  }
});

test('actual notes handler uses the server setting; invalid optional setting preserves existing authentication', async () => {
  const saved = process.env.VAULT_XDR_DENY_RULES_JSON;
  try {
    const at = Date.now();
    process.env.VAULT_XDR_DENY_RULES_JSON = JSON.stringify(createVaultDenyRules([block], [{ alertId: block.alertId, userId: attacker }], at));
    const handler = createNotesHandler({ verify: async () => ({ userId: attacker }),
      settings: () => { assert.fail('blocked user must not reach DB'); } });
    const res = response(); await handler({ method: 'GET', headers: {} }, res);
    assert.equal(res.code, 403);
    process.env.VAULT_XDR_DENY_RULES_JSON = '{invalid';
    assert.equal(await activeVaultDeny({ userId: attacker }), null);
  } finally {
    if (saved === undefined) delete process.env.VAULT_XDR_DENY_RULES_JSON;
    else process.env.VAULT_XDR_DENY_RULES_JSON = saved;
  }
});

test('28 fixture alerts replay through the notes API: 10 blocked, 6 ambiguous allowed, 12 normal allowed', async () => {
  const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/brute-force.json', import.meta.url)));
  const decisions = [];
  for (const a of fixture.alerts) decisions.push({ alertId: a.id, ...await decide(a) });
  // Explicit fictional identity assignments for replay, not production user bindings.
  const bindings = fixture.alerts.map((a, i) => ({ alertId: a.id,
    userId: `00000000-0000-4000-8000-${String(i + 1).padStart(12, '0')}` }));
  const document = createVaultDenyRules(decisions, bindings, now);
  const counts = { blocked: 0, ambiguousAllowed: 0, normalAllowed: 0 };
  for (let i = 0; i < decisions.length; i++) {
    const handler = createNotesHandler({ verify: async () => ({ userId: bindings[i].userId }),
      deny: identity => matchVaultDeny(identity, document, now),
      settings: () => ({ key: 'fixture-placeholder', url: new URL('https://fixture.invalid') }),
      fetcher: async () => Response.json([]) });
    const res = response(); await handler({ method: 'GET', headers: {}, query: {} }, res);
    assert.equal(res.code, decisions[i].action === 'block' ? 403 : 200);
    counts[res.code === 403 ? 'blocked' : decisions[i].action === 'alert' ? 'ambiguousAllowed' : 'normalAllowed']++;
  }
  assert.deepEqual(counts, { blocked: 10, ambiguousAllowed: 6, normalAllowed: 12 });
  assert.equal(document.rules.length, 10);
});
