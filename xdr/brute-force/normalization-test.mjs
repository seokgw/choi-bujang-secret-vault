import assert from 'node:assert/strict';
import { decide } from './decide.mjs';
import { extractAlert } from './read-alerts.mjs';
import { configureJev } from './jev.mjs';

const base = { timestamp: '2026-10-08T00:00:00Z', rule: { level: 7 },
  data: { srcip: '192.0.2.1', count: '48' } };
configureJev(async () => { throw Error('unavailable'); });
try {
  for (const description of [
    '같은 주소에서 120초 동안 인증 실패가 48회 발생했습니다.',
    '같은 주소에서 2분 동안 로그인 실패는 48번 발생했습니다.',
    '48 failed login attempts in 120 seconds from the same source.',
    'Authentication failure from the same source within 2 minutes.',
  ]) {
    const alert = { ...base, rule: { ...base.rule, description } };
    assert.equal((await decide(alert)).action, 'block');
    assert.equal((await decide(extractAlert(alert))).action, 'block');
  }
  for (const [description, data] of [
    ['Authentication failure within 900 seconds.', base.data],
    ['Authentication failure within 0 seconds.', base.data],
    ['Authentication failure within 120 seconds.', { srcip: '192.0.2.1', count: 'not-a-number' }],
    ['Authentication failure within 120 seconds.', { srcip: '192.0.2.1', firedtimes: 100 }],
    ['로그인 실패 0건입니다. 120초 동안 확인했습니다.', base.data],
    ['로그인이 성공했습니다.', base.data],
  ]) {
    assert.notEqual((await decide({ ...base, rule: { ...base.rule, description }, data })).action, 'block');
  }
  const flat = { timestamp: base.timestamp, source: base.data.srcip, level: '7',
    description: '48 failed login attempts in 120 seconds from the same source.' };
  assert.equal((await decide(flat)).action, 'block');
  assert.equal((await decide({ ...flat,
    description: 'The same password was attempted across multiple accounts from the same source.' })).action, 'block');
  assert.equal((await decide({ ...flat, description: 'Login successful.' })).action, 'record');
  assert.equal((await decide({ ...flat, level: '6', description: '3 failed login attempts, then successful login.' })).action, 'alert');
  assert.equal((await decide({ ...flat, description: '48 failed login attempts in 3 minutes 30 seconds.' })).action, 'alert');
  assert.equal((await decide({ ...base, rule: { level: '7', description: '로그인 실패 4건 뒤에 성공했습니다.' } })).action, 'alert');
  assert.equal((await decide({ ...base, rule: { level: '5', description: 'structured event' },
    data: { srcip: '192.0.2.1', event_type: 'login_failure', failure_count: '48',
      window_seconds: '120', same_source: true } })).action, 'block');
  for (const malformed of [null, {}, { timestamp: {}, source: 123, level: 'bad', description: 'unrecognized' }]) {
    const out = await decide(malformed);
    assert.equal(out.action, 'alert');
    assert.deepEqual(Object.keys(out).sort(), ['action', 'confidence', 'reason']);
  }
} finally { configureJev(undefined); }
console.log('PASS: raw/flat inputs, seconds/minutes, string counts/levels, English spraying/recovered logins, composite duration and malformed input boundaries.');
