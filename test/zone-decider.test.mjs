import assert from 'node:assert/strict';
import { test } from 'node:test';
import vm from 'node:vm';
import { decide } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

test('module and isolated decider reject unknown paths without blanket resource denial', async () => {
  for (const run of [decide, vm.runInNewContext(`(${decide.toString()})`)]) {
    const { normal, suspicious } = fixtureRequests();
    assert.equal((await run(normal)).decision, 'allow');
    assert.equal((await run(suspicious)).decision, 'step_up');
    for (const id of ['demo', '00000000-0000-4000-8000-000000000001', 'memo_1']) {
      const result = await run({ ...normal, path: `/notes/${id}`, route: 'GET /notes/:id' });
      assert.equal(result.decision, 'allow');
    }
    for (const path of ['/admin', '/api/notes/export', '/api/notes/1/export',
      '/api/notes/%31', '/api/notes/../notices', '/api/notes/1?export=1', '/api/notes-other',
      '/notes/Export', '/notes/search', '/notes/demo/export']) {
      const result = await run({ ...normal, path, route: 'GET /api/notes/:id' });
      assert.equal(result.decision, 'deny');
      assert.ok(result.ruleIds.includes('zone_known_resource'));
    }
    for (const subjectId of ['a_fixture', 'b_fixture']) {
      const input = { ...normal, subjectId, path: '/api/notes/1', route: 'GET /api/notes/:id' };
      const result = await run(input);
      assert.equal(result.decision, 'allow');
    }
    for (const method of ['PUT', 'PATCH']) {
      const result = await run({ ...normal, method, path: '/api/notices/1', route: `${method} /api/notices/:id` });
      assert.equal(result.decision, 'allow');
    }
    for (const change of [{ route: 'GET /api/notices' }, { method: 'POST' },
      { queryLength: 1 }, { service: 'other' }, { subjectId: '' }, { deviceId: 'client' }]) {
      assert.equal((await run({ ...normal, ...change })).decision, 'deny');
    }
    const unregistered = await run({ ...normal, path: '/unknown', deviceRegistered: false });
    assert.equal(unregistered.reasonCode, 'device_not_registered');
  }
});
