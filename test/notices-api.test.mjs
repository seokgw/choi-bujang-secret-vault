import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createNoticesHandler } from '../api/notices.js';
import { createNotesHandler } from '../api/notes.js';

const student = '00000000-0000-4000-8000-000000000001';
const instructor = '00000000-0000-4000-8000-000000000002';
function response() {
  return { headers: {}, setHeader(k, v) { this.headers[k] = v; },
    status(code) { this.code = code; return this; }, json(body) { this.body = body; } };
}
test('direct notice edits use server verified identity and stored role, never client role', async () => {
  let notice = { id: 1, title: 'fictional notice', content: 'fictional content' };
  let rpcCalls = 0;
  const handler = createNoticesHandler({ detailRoute: true,
    verify: async req => req.identity, deny: async () => null,
    settings: () => ({ key: 'test-placeholder', url: new URL('https://fixture.invalid') }),
    fetcher: async (url, init) => {
      assert.equal(url.pathname, '/rest/v1/rpc/update_training_notice');
      const body = JSON.parse(init.body);
      assert.equal(body.role, undefined);
      assert.equal(body.userId, undefined);
      rpcCalls++;
      if (body.p_user_id !== instructor) return Response.json({ error: 'instructor_required' });
      notice = { id: body.p_id, title: body.p_title, content: body.p_content };
      return Response.json({ notice });
    } });
  const run = async (who, query = { id: '1' }) => {
    const res = response();
    await handler({ method: 'PATCH', query, headers: { authorization: 'fixture', role: 'instructor' },
      identity: who && { kind: 'student', userId: who },
      body: { title: 'updated', content: 'fictional update', role: 'instructor', userId: instructor } }, res);
    return res;
  };
  const before = structuredClone(notice);
  const denied = await run(student);
  assert.equal(denied.code, 403);
  assert.equal(denied.headers['X-Aleph-Denial-Reason'], 'instructor_required');
  assert.deepEqual(denied.body, { error: 'forbidden' });
  assert.deepEqual(notice, before);
  const allowed = await run(instructor);
  assert.equal(allowed.code, 200);
  assert.equal(allowed.headers['X-Aleph-Resource-Id'], 'notices:1');
  assert.equal(allowed.body.title, 'updated');
  assert.equal((await run(null)).code, 401);
  assert.equal((await run(instructor, { id: '1', action: 'export' })).code, 400);
  assert.equal((await run(instructor, { id: 'export' })).code, 400);
  assert.equal(rpcCalls, 2);
});

test('role lookup failures never permit a notice edit', async () => {
  const handler = createNoticesHandler({ detailRoute: true,
    verify: async () => ({ kind: 'student', userId: instructor }), deny: async () => null,
    settings: () => ({ key: 'test-placeholder', url: new URL('https://fixture.invalid') }),
    fetcher: async () => Response.json({ error: 'unavailable' }, { status: 503 }) });
  const res = response();
  await handler({ method: 'PATCH', query: { id: '1' }, headers: { authorization: 'fixture' },
    body: { title: 'test', content: 'fictional' } }, res);
  assert.equal(res.code, 503);
  assert.equal(res.headers['X-Aleph-Denial-Reason'], 'permission_check_unavailable');
});

test('stored owner mismatch refuses all note data and leaves a short reason', async () => {
  const handler = createNotesHandler({ verify: async () => ({ userId: student }), deny: async () => null,
    settings: () => ({ key: 'test-placeholder', url: new URL('https://fixture.invalid') }),
    fetcher: async () => Response.json([{ id: 1, title: 'hidden', content: 'hidden', owner_id: instructor }]) });
  const res = response();
  await handler({ method: 'GET', query: {}, headers: { role: 'instructor' } }, res);
  assert.equal(res.code, 503);
  assert.equal(res.headers['X-Aleph-Denial-Reason'], 'ownership_check_failed');
  assert.deepEqual(res.body, { error: 'service_unavailable' });
});
