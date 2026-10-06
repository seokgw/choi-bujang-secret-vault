import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createNotesHandler } from '../api/notes.js';
const a = '00000000-0000-4000-8000-00000000000a';
const b = '00000000-0000-4000-8000-00000000000b';
function response() {
  return { setHeader() {}, status(v) { this.code = v; return this; }, json(v) { this.body = v; } };
}
function fixture(detailRoute = false) {
  let nextId = 3;
  const rows = [{ id: 1, title: 'A test', content: 'fictional A', owner_id: a },
    { id: 2, title: 'B test', content: 'fictional B', owner_id: b }];
  const handler = createNotesHandler({ detailRoute, verify: async req => ({ userId: req.testIdentity }),
    settings: () => ({ key: 'test-only-placeholder', url: new URL('https://test.supabase.co') }),
    fetcher: async (url, init) => {
      const owner = url.searchParams.get('owner_id');
      assert.ok([`eq.${a}`, `eq.${b}`].includes(owner));
      const id = url.searchParams.get('id');
      const matches = rows.filter(row => `eq.${row.owner_id}` === owner && (!id || `eq.${row.id}` === id));
      if (init.method === 'POST') {
        const note = { id: nextId++, ...JSON.parse(init.body) }; rows.push(note); return Response.json([note]);
      }
      if (init.method === 'PATCH') for (const row of matches) Object.assign(row, JSON.parse(init.body));
      if (init.method === 'DELETE') for (const row of matches) rows.splice(rows.indexOf(row), 1);
      return Response.json(matches);
    } });
  const run = async (who, method, id, body, extraQuery = {}) => {
    const res = response(); await handler({ method, testIdentity: who,
      headers: { authorization: 'test-only-header' }, query: { ...extraQuery, ...(id === undefined ? {} : { id: String(id) }) }, body }, res);
    return res;
  };
  return { rows, run };
}
test('A/B list isolation ignores browser owner, role and userId', async () => {
  const { run } = fixture();
  for (const [who, other, ownId] of [[a, b, 1], [b, a, 2]]) {
    const res = await run(who, 'GET', undefined, { owner_id: other, role: 'admin' }, { owner_id: other, userId: other });
    assert.equal(res.code, 200); assert.deepEqual(res.body.notes.map(row => row.id), [ownId]);
    assert.ok(!JSON.stringify(res.body).includes(other));
  }
});
test('A/B foreign detail read, PUT, PATCH and DELETE match missing ID denial and preserve rows', async () => {
  const { run, rows } = fixture(true);
  const before = structuredClone(rows);
  for (const [who, ownId, otherId] of [[a, 1, 2], [b, 2, 1]]) {
    const own = await run(who, 'GET', ownId);
    assert.equal(own.code, 200); assert.equal(own.body.id, ownId);
    assert.deepEqual(Object.keys(own.body).sort(), ['content', 'id', 'title']);
    for (const method of ['GET', 'PUT', 'PATCH', 'DELETE']) {
      const body = { title: 'spoof', content: 'spoof', owner_id: who };
      const foreign = await run(who, method, otherId, body);
      const missing = await run(who, method, 999, body);
      assert.equal(foreign.code, 404); assert.deepEqual(foreign.body, { error: 'not_found' });
      assert.deepEqual(foreign.body, missing.body);
    }
  }
  assert.deepEqual(rows, before);
});
test('A/B own creation, update, deletion work; spoofed owner never transfers ownership', async () => {
  const { run, rows } = fixture();
  for (const [who, other] of [[a, b], [b, a]]) {
    const made = await run(who, 'POST', undefined, { title: 'new test', content: 'fictional', owner_id: other, userId: other, id: 999 });
    assert.equal(made.code, 201);
    const id = made.body.notes[0].id;
    assert.equal(rows.find(r => r.id === id).owner_id, who);
    for (const method of ['PUT', 'PATCH']) {
      const changed = await run(who, method, id, { title: 'updated', content: 'fictional updated', owner_id: other });
      assert.equal(changed.code, 200); assert.equal(rows.find(r => r.id === id).owner_id, who);
    }
    assert.equal((await run(who, 'DELETE', id)).code, 200);
    assert.ok(!rows.some(r => r.id === id));
  }
});
test('server fails closed if upstream returns a foreign owner despite filter', async () => {
  const handler = createNotesHandler({ verify: async () => ({ userId: a }),
    settings: () => ({ key: 'test-only-placeholder', url: new URL('https://test.supabase.co') }),
    fetcher: async () => Response.json([{ id: 2, title: 'private test', content: 'must be hidden', owner_id: b }]) });
  const res = response(); await handler({ method: 'GET', headers: {} }, res);
  assert.equal(res.code, 503); assert.deepEqual(res.body, { error: 'service_unavailable' });
});
