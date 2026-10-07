import assert from 'node:assert/strict';
import { test } from 'node:test';
import { matchBoundDeny } from '../src/xdr-policy.mjs';
import { decide, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { mkdtemp, mkdir, copyFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';

const now = Date.parse('2026-10-07T00:00:00Z');
const request = fixtureRequests().normal;
const rule = { action: 'block', confidence: 0.95, pattern: 'rapid-login-failures', alertId: 'test-alert',
  issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 900000).toISOString(),
  ...Object.fromEntries(['classId', 'projectId', 'subjectId', 'deviceId'].map(k => [k, request[k]])) };
const document = rules => ({ schema: 'aleph.xdr.bound-deny.v1', rules });

test('bound block requires every verified identity dimension and honors expiry', () => {
  assert.equal(matchBoundDeny(request, document([rule]), now), rule);
  for (const field of ['classId', 'projectId', 'subjectId', 'deviceId']) {
    assert.equal(matchBoundDeny({ ...request, [field]: 'different' }, document([rule]), now), null);
    assert.equal(matchBoundDeny(request, document([{ ...rule, [field]: undefined }]), now), null);
  }
  assert.equal(matchBoundDeny(request, document([rule]), now - 1), null);
  assert.equal(matchBoundDeny(request, document([rule]), now + 900000), null);
});
test('alert/record, ungrounded or malformed candidates never become active blocks', () => {
  for (const changed of [{ action: 'alert' }, { action: 'record' }, { confidence: 0.84 },
    { confidence: NaN }, { pattern: 'unknown' }, { alertId: '' }, { expiresAt: 'invalid' },
    { expiresAt: new Date(now + 900001).toISOString() }]) {
    assert.equal(matchBoundDeny(request, document([{ ...rule, ...changed }]), now), null);
  }
});
test('existing decide contract and baseline remain intact with empty active rules', async () => {
  const result = await decide(request);
  assert.equal(result.decision, 'deny');
  assert.equal(result.reasonCode, 'starter_not_ready');
  assert.deepEqual(Object.keys(result).sort(), ['decision', 'reasonCode', 'requestId', 'ruleIds', 'schema']);
  assert.deepEqual(result.ruleIds, ['starter.deny']);
  assert(RULE_IDS.includes('xdr.brute-force.deny'));
});

test('existing decide actually reads and applies the bound rules file', async () => {
  const folder = await mkdtemp(join(tmpdir(), 'aleph-xdr-policy-'));
  try {
    await mkdir(join(folder, 'src'));
    await mkdir(join(folder, 'xdr', 'brute-force'), { recursive: true });
    for (const name of ['decider.mjs', 'xdr-policy.mjs']) {
      await copyFile(new URL(`../src/${name}`, import.meta.url), join(folder, 'src', name));
    }
    const start = Date.now() - 1000;
    const active = { ...rule, issuedAt: new Date(start).toISOString(), expiresAt: new Date(start + 900000).toISOString() };
    await writeFile(join(folder, 'xdr', 'brute-force', 'active-rules.json'), JSON.stringify(document([active])));
    const loaded = await import(pathToFileURL(join(folder, 'src', 'decider.mjs')).href);
    assert.deepEqual((await loaded.decide(request)).ruleIds, ['starter.deny', 'xdr.brute-force.deny']);
    assert.deepEqual((await loaded.decide({ ...request, subjectId: 'other' })).ruleIds, ['starter.deny']);
  } finally {
    const target = resolve(folder), base = resolve(tmpdir());
    assert(target.startsWith(base + sep) && target.slice(base.length + 1).startsWith('aleph-xdr-policy-'));
    await rm(target, { recursive: true, force: true });
  }
});
