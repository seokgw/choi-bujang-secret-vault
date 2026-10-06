import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';
import '../test/stage3.test.mjs';
import '../test/stage4.test.mjs';

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
  const stage5 = { ...config, step: 5,
    originalApiUrl: 'https://student-project.supabase.co/rest/v1/training_notes' };
  assert.equal(deploymentIdentity(env, stage5).originalApiUrl, stage5.originalApiUrl);
  assert.throws(() => deploymentIdentity(env, { ...stage5, originalApiUrl: null }));
  assert.throws(() => deploymentIdentity(env, { ...stage5,
    originalApiUrl: `${stage5.originalApiUrl}?select=*` }));
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
