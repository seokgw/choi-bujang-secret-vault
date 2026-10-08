import assert from 'node:assert/strict';
import { mkdtemp, cp, readFile, rm } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { decide } from './decide.mjs';

const fixture = JSON.parse(await readFile(new URL('../fixtures/brute-force.json', import.meta.url)));
const expected = [];
for (const alert of fixture.alerts) expected.push(await decide(alert));
const dir = await mkdtemp(join(tmpdir(), 'xdr-standalone-'));
try {
  await cp(new URL('./decide.mjs', import.meta.url), join(dir, 'decide.mjs'));
  const script = `
    import assert from 'node:assert/strict';
    import {readFileSync} from 'node:fs';
    const module = await import(${JSON.stringify(pathToFileURL(join(dir, 'decide.mjs')).href)});
    assert.deepEqual(Object.keys(module), ['decide']);
    const input = JSON.parse(readFileSync(0, 'utf8'));
    const output = [];
    for (const alert of input) output.push(await module.decide(alert));
    const uncertain = {timestamp:'2026-10-08T00:00:00Z',
      rule:{level:5,description:'로그인 실패 2건입니다.'},data:{srcip:'192.0.2.1'}};
    assert.equal((await module.decide(uncertain)).action, 'alert');
    process.env.TYPESAFE_API_KEY = 'fixture-only';
    globalThis.fetch = async (_url, options) => {
      assert(!options.body.includes('192.0.2.1'));
      return Response.json({answers:{brute_force:{type:'noul',noul:0.9}}});
    };
    assert.equal((await module.decide(uncertain)).action, 'block');
    globalThis.fetch = async () => {throw Error('offline');};
    assert.equal((await module.decide(uncertain)).action, 'alert');
    console.log(JSON.stringify(output));
  `;
  const env = { ...process.env };
  delete env.TYPESAFE_API_KEY;
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
    cwd: dir, input: JSON.stringify(fixture.alerts), encoding: 'utf8', env,
    timeout: 15000, windowsHide: true,
  });
  assert.equal(child.status, 0, child.stderr);
  assert.deepEqual(JSON.parse(child.stdout), expected);
  console.log('PASS: decide.mjs alone, no sibling files or dependencies; all 28 decisions match; Jev success/error and missing-key fallback verified.');
} finally {
  assert.equal(resolve(dirname(dir)), resolve(tmpdir()));
  assert(dir.includes('xdr-standalone-'));
  await rm(dir, { recursive: true, force: true });
}
