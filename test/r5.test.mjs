import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';
import notesHandler from '../api/notes.js';
import { readFile } from 'node:fs/promises';
import { runInNewContext } from 'node:vm';

const config = {
  step: 1,
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  sampleMarker: 'SAMPLE_NOTE_1',
  publicAppUrl: 'https://student-defense.vercel.app',
};
const env = {
  VERCEL_GIT_PROVIDER: 'github',
  VERCEL_GIT_REPO_OWNER: 'Student-A',
  VERCEL_GIT_REPO_SLUG: 'aleph-defense',
  VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
  VERCEL_URL: 'student-defense-123.vercel.app',
};

test('build identity uses Vercel Git and deployment metadata', () => {
  assert.equal(deploymentIdentity(env, { ...config, step: 2 }).step, 2);
  assert.deepEqual(deploymentIdentity(env, config), {
    schema: 'aleph.defense.deployment.v1',
    step: 1,
    repoUrl: 'https://github.com/student-a/aleph-defense',
    commit: 'a'.repeat(40),
    publicAppUrl: 'https://student-defense-123.vercel.app',
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
  });
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_PROVIDER: undefined }, config));
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_COMMIT_SHA: 'short' }, config));
});

test('notes API limits fields and hides missing configuration/upstream errors', async () => {
  const oldFetch = globalThis.fetch;
  const oldUrl = process.env.SUPABASE_URL;
  const oldKey = process.env.SUPABASE_SECRET_KEY;
  let status, body;
  const response = { setHeader() {}, status(value) {
    status = value; return { json(value) { body = value; } };
  } };
  try {
    delete process.env.SUPABASE_SECRET_KEY;
    await notesHandler({ method: 'GET' }, response);
    assert.equal(status, 503);
    assert.deepEqual(body, { error: 'NOTES_UNAVAILABLE' });
    process.env.SUPABASE_URL = 'https://unit-test.invalid';
    process.env.SUPABASE_SECRET_KEY = 'unit-test-placeholder';
    globalThis.fetch = async (url, init) => {
      assert.equal(url.searchParams.get('select'), 'title,content');
      assert.equal(init.headers.apikey, 'unit-test-placeholder');
      assert.equal(init.headers['Accept-Profile'], 'vault_api');
      return Response.json([{ title: 'test title', content: 'test content', owner_id: 'hidden' }]);
    };
    await notesHandler({ method: 'GET' }, response);
    assert.equal(status, 200);
    assert.deepEqual(body, { notes: [{ title: 'test title', content: 'test content' }] });
    globalThis.fetch = async () => { throw new Error('private upstream details'); };
    await notesHandler({ method: 'GET' }, response);
    assert.equal(status, 503);
    assert.deepEqual(body, { error: 'NOTES_UNAVAILABLE' });
    await notesHandler({ method: 'POST' }, response);
    assert.equal(status, 405);
  } finally {
    globalThis.fetch = oldFetch;
    if (oldUrl === undefined) delete process.env.SUPABASE_URL; else process.env.SUPABASE_URL = oldUrl;
    if (oldKey === undefined) delete process.env.SUPABASE_SECRET_KEY; else process.env.SUPABASE_SECRET_KEY = oldKey;
  }
});

test('first attack check reads public data.json without credentials', async () => {
  const originalFetch = globalThis.fetch;
  let requestUrl;
  let options;
  try {
    globalThis.fetch = async (url, init) => {
      requestUrl = String(url);
      options = init;
      return new Response(JSON.stringify({ sampleMarker: 'SAMPLE_NOTE_1', notes: [{ title: '가상' }] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };
    const [result] = await runAttackChecks(config);
    assert.equal(requestUrl, 'https://student-defense.vercel.app/data.json');
    assert.equal(options.redirect, 'error');
    assert.match(result.observed, /확인 표시가 보임/u);
    globalThis.fetch = async () => new Response('<html>not the data</html>', { status: 200 });
    const [failed] = await runAttackChecks(config);
    assert.match(failed.observed, /보이지 않음/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('stage 2 self-check records public API and data removal without note bodies', async () => {
  const oldFetch = globalThis.fetch;
  try {
    globalThis.fetch = async url => {
      const path = new URL(url).pathname;
      if (path === '/data.json') return new Response('', { status: 404 });
      if (path === '/api/notes') return Response.json({ notes: Array(4).fill({ content: 'not recorded' }) });
      if (path === '/aleph.json') return Response.json({ schema: 'aleph.defense.deployment.v1', step: 2 });
      return new Response('', { headers: { 'x-content-type-options': 'nosniff' } });
    };
    const results = await runAttackChecks({ ...config, step: 2 });
    assert.equal(results.length, 4);
    assert.match(results[0].observed, /404/u);
    assert.match(results[1].observed, /건수 4/u);
    assert.doesNotMatch(JSON.stringify(results), /not recorded/u);
  } finally { globalThis.fetch = oldFetch; }
});

test('client renders all four API cards as text and hides internal error details', async () => {
  const html = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
  const script = html.match(/<script type="module">([\s\S]*?)<\/script>/u)[1];
  let children;
  const document = {
    querySelector: () => ({ replaceChildren: (...items) => { children = items; } }),
    createElement: tag => ({ tag, append(...items) { this.children = items; } }),
  };
  const execute = fetch => runInNewContext(`(async () => {${script}\n})()`, { document, fetch });
  await execute(async url => {
    assert.equal(url, '/api/notes');
    return Response.json({ notes: Array.from({ length: 4 }, (_, i) => ({ title: `<b>${i}</b>`, content: 'test' })) });
  });
  assert.equal(children.length, 4);
  assert.equal(children[0].children[0].textContent, '<b>0</b>');
  await execute(async () => { throw new Error('internal detail'); });
  assert.equal(children.length, 1);
  assert.doesNotMatch(children[0].textContent, /internal detail/u);
});
