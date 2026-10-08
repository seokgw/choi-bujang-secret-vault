import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { runInNewContext } from 'node:vm';
import { isIP } from 'node:net';
import { decide } from './decide.mjs';

const source = await readFile(new URL('./decide.mjs', import.meta.url), 'utf8');
const patterns = JSON.parse(await readFile(new URL('./patterns.json', import.meta.url)));
const snapshot = source.match(/const fallbackPatterns = ([\s\S]*?);\s+const patterns/);
assert(snapshot);
assert.deepEqual(JSON.parse(snapshot[1]), patterns.map(({ name, condition }) => ({ name, condition })));
// No process, fetch, filesystem, module loader, helpers or timers are provided.
const isolated = runInNewContext('(' + decide.toString() + ')', {}, { timeout: 1000 });
const fixture = JSON.parse(await readFile(new URL('../fixtures/brute-force.json', import.meta.url)));
for (const alert of fixture.alerts) {
  assert.deepEqual(JSON.parse(JSON.stringify(await isolated(alert))), await decide(alert));
}
const uncertain = { timestamp: '2026-10-08T00:00:00Z', source: '192.0.2.1',
  level: 5, description: '로그인 실패 2건입니다.' };
assert.equal((await isolated(uncertain)).action, 'alert');
for (const address of ['192.0.2.1', '2001:db8::1', '::1', '::ffff:192.0.2.1',
  '2001:db8:0:0:0:0:0:1', '999.0.0.1', '01.2.3.4', '2001:::1', '1:2:3', '192.0.2.1/24']) {
  const out = await isolated({ ...uncertain, source: address, description: 'rapid-login-failures' });
  assert.equal(out.action, isIP(address) ? 'block' : 'alert');
}
console.log('PASS: function-only isolated JavaScript matches all 28 decisions without Node globals or imports; IP boundaries, missing-AI fallback and pattern snapshot verified.');
