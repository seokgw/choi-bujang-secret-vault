import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { decide } from './decide.mjs';
import { extractAlert } from './read-alerts.mjs';
import { configureJev } from './jev.mjs';

const patterns = JSON.parse(await readFile(new URL('./patterns.json', import.meta.url)));
const variants = patterns.find(p => p.name === 'rapid-login-failures').condition.vendorRules;
configureJev(async () => { throw Error('unavailable'); });
try {
  for (const v of variants) {
    const alert = { timestamp: '2026-10-08T00:00:00Z', decoder: { name: 'sshd' },
      rule: { id: v.id, level: 10, description: v.description,
        groups: ['authentication_failures'], mitre: { id: ['T1110'] } },
      data: { srcip: '192.0.2.1', srcuser: 'user01' } };
    const result = await decide(alert);
    assert.equal(result.action, 'block');
    assert.equal(result.reason, 'rapid-login-failures');
    assert.deepEqual(await decide(extractAlert(alert)), result);
    const changes = [
      { rule: { ...alert.rule, level: 5 } },
      { rule: { ...alert.rule, id: '5716' } },
      { rule: { ...alert.rule, groups: ['authentication_success'] } },
      { rule: { ...alert.rule, mitre: { id: ['T1078'] } } },
      { rule: { ...alert.rule, description: 'sshd: authentication success.' } },
      { decoder: { name: 'unrelated' } },
      { data: { srcip: 'invalid' } },
      { timestamp: 'invalid' },
    ];
    for (const change of changes) assert.notEqual((await decide({ ...alert, ...change })).action, 'block');
    const contaminated = { ...alert, data: { ...alert.data, token: 'DO_NOT_OUTPUT' } };
    assert(!JSON.stringify(extractAlert(contaminated)).includes('DO_NOT_OUTPUT'));
  }
  const aggregate = { timestamp: '2026-10-08T00:00:00Z',
    rule: { level: 12, description: 'unrecognized event' },
    data: { srcip: '192.0.2.1', event_type: 'login_failure',
      failure_count: 50, window_seconds: 120, same_source: true } };
  for (const level of [0, 5, 9, 12]) {
    assert.equal((await decide({ ...aggregate, rule: { ...aggregate.rule, level } })).action, 'block');
  }
  for (const changes of [{ failure_count: 3 }, { window_seconds: 600 },
    { same_source: false }, { event_type: 'login_success' }]) {
    assert.equal((await decide({ ...aggregate, data: { ...aggregate.data, ...changes } })).action, 'alert');
  }
  assert.equal((await decide({ ...aggregate, data: { srcip: '192.0.2.1' } })).action, 'alert');
} finally { configureJev(undefined); }
console.log('PASS: 2 official Wazuh correlation signatures block; 16 missing/conflicting evidence cases do not block; raw/extracted parity and secret exclusion verified.');
