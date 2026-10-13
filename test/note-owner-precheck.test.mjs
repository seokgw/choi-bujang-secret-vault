import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createNotesHandler } from '../api/notes.js';

const a = '00000000-0000-4000-8000-000000000001';
const b = '00000000-0000-4000-8000-000000000002';
test('direct detail reads compare the stored owner before requesting any content', async () => {
  for (const who of [a, b]) {
    const selections = [];
    const handler = createNotesHandler({ detailRoute: true,
      verify: async () => ({ userId: who }), deny: async () => null,
      settings: () => ({ key: 'fixture-placeholder', url: new URL('https://fixture.invalid') }),
      fetcher: async url => {
        const selection = url.searchParams.get('select');
        selections.push(selection);
        if (selection === 'id,owner_id') {
          assert.equal(url.searchParams.get('owner_id'), null);
          return Response.json([{ id: 1, owner_id: a }]);
        }
        assert.equal(url.searchParams.get('owner_id'), `eq.${who}`);
        return Response.json([{ id: 1, owner_id: a, title: 'fixture', content: 'fixture' }]);
      } });
    const response = { headers: {}, setHeader(k, v) { this.headers[k] = v; },
      status(code) { this.code = code; return this; }, json(body) { this.body = body; } };
    await handler({ method: 'GET', query: { id: '1' }, headers: { role: 'instructor' },
      body: { owner_id: a, role: 'instructor' } }, response);
    assert.equal(response.code, who === a ? 200 : 404);
    assert.equal(selections[0], 'id,owner_id');
    assert.equal(selections.length, who === a ? 2 : 1);
    if (who === b) assert.deepEqual(response.body, { error: 'not_found' });
  }
});
