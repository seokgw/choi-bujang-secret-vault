import assert from 'node:assert/strict';
import { test } from 'node:test';
import { RESOURCE_IDS, resourceIdForPath } from '../src/resources.mjs';
import { createNotesHandler } from '../api/notes.js';

test('note and notice resources are distinct even for identical record numbers', () => {
  assert.notEqual(RESOURCE_IDS.notes, RESOURCE_IDS.notices);
  for (const name of ['notes', 'notices']) {
    assert.equal(resourceIdForPath(`/api/${name}`), name);
    assert.equal(resourceIdForPath(`/api/${name}/1`), `${name}:1`);
  }
  for (const path of ['/api/notes-other', '/api/notes/../notices', '/api/notices/0',
    '/api/notes/2147483648', '/api/notes/1/edit', undefined]) {
    assert.equal(resourceIdForPath(path), null);
  }
});

test('existing note handlers identify the resource independently of spoofed client fields', async () => {
  const handler = createNotesHandler({ verify: async () => null });
  for (const [id, expected] of [[undefined, 'notes'], ['1', 'notes:1']]) {
    const response = { headers: {}, setHeader(key, value) { this.headers[key] = value; },
      status(code) { this.code = code; return this; }, json(body) { this.body = body; } };
    await handler({ method: 'GET', query: { id, resourceId: 'notices' },
      headers: { 'x-aleph-resource-id': 'notices' }, body: { resourceId: 'notices' } }, response);
    assert.equal(response.headers['X-Aleph-Resource-Id'], expected);
    assert.equal(response.code, 401);
    assert.deepEqual(response.body, { error: 'unauthorized' });
  }
});
