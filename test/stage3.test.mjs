import assert from 'node:assert/strict';
import { test } from 'node:test';
import { generateKeyPair, SignJWT } from 'jose';
import { readFile } from 'node:fs/promises';
import { runInNewContext } from 'node:vm';
import config from '../aleph.config.json' with { type: 'json' };
import notesHandler, { createNotesHandler } from '../api/notes.js';
import { createSessionHandler } from '../api/session.js';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';
import { COOKIE, sessionToken } from '../src/vault-server.mjs';
const userId = '00000000-0000-4000-8000-00000000000a';
const origin = new URL(config.publicAppUrl).origin;
const settings = () => ({ key: 'test-only-placeholder', url: new URL('https://test.supabase.co') });
function response() {
  return { headers: {}, setHeader(k, v) { this.headers[k.toLowerCase()] = v; },
    status(v) { this.code = v; return this; }, json(v) { this.body = v; return this; } };
}
test('anonymous requests reject before any DB access with JSON only', async () => {
  const handler = createNotesHandler({ verify: async () => null,
    settings: () => { assert.fail('must not read configuration'); } });
  for (const method of ['GET', 'POST', 'PATCH', 'DELETE']) {
    const res = response(); await handler({ method, headers: {} }, res);
    assert.equal(res.code, 401); assert.deepEqual(res.body, { error: 'unauthorized' });
    assert.match(res.headers['content-type'], /application\/json/u);
  }
});
test('deployed handler rejects missing or malformed authorization without configuration', async () => {
  for (const headers of [{}, { authorization: 'Bearer malformed' }]) {
    const res = response(); await notesHandler({ method: 'GET', headers }, res);
    assert.equal(res.code, 401); assert.deepEqual(res.body, { error: 'unauthorized' });
  }
});
test('CRUD assigns verified owner and exposes only allowed fields', async () => {
  const row = { id: 5, title: '<b>test</b>', content: 'fictional test', owner_id: 'hidden' };
  const calls = [];
  const handler = createNotesHandler({ verify: async () => ({ userId }), settings,
    fetcher: async (url, init) => { calls.push({ url, init }); return Response.json([row]); } });
  for (const method of ['GET', 'POST', 'PATCH', 'DELETE']) {
    const res = response();
    await handler({ method, headers: { origin }, query: { id: '5' },
      body: { title: row.title, content: row.content, owner_id: 'spoofed', userId: 'spoofed', role: 'admin' } }, res);
    assert.equal(res.code, method === 'POST' ? 201 : 200);
    assert.deepEqual(res.body, method === 'DELETE' ? { deleted: true }
      : { notes: [{ id: 5, title: row.title, content: row.content }] });
  }
  assert.deepEqual(JSON.parse(calls[1].init.body), { title: row.title, content: row.content, owner_id: userId });
  assert.deepEqual(JSON.parse(calls[2].init.body), { title: row.title, content: row.content });
  assert.equal(calls[2].url.searchParams.get('id'), 'eq.5');
  assert.equal(calls[0].init.headers['Accept-Profile'], 'vault_api');
});
test('reject unsafe origin, invalid id/body, and hide upstream details', async () => {
  const handler = createNotesHandler({ verify: async () => ({ userId }), settings,
    fetcher: async () => { throw new Error('private upstream detail'); } });
  for (const [req, code] of [
    [{ method: 'POST', headers: { origin: 'https://other.example' } }, 403],
    [{ method: 'PATCH', headers: { origin }, query: { id: '1&owner_id=all' } }, 400],
    [{ method: 'POST', headers: { origin }, body: { title: '', content: 'test' } }, 400],
    [{ method: 'GET', headers: {} }, 503],
  ]) { const res = response(); await handler(req, res); assert.equal(res.code, code);
    assert.doesNotMatch(JSON.stringify(res.body), /private|stack|test-only/u); }
});
test('login uses verified token in HttpOnly cookie, not response; logout clears it', async () => {
  const { privateKey } = await generateKeyPair('ES256');
  const token = await new SignJWT({}).setProtectedHeader({ alg: 'ES256' }).sign(privateKey);
  const handler = createSessionHandler({ settings, verify: async req =>
    req.headers?.authorization === `Bearer ${token}` ? { userId } : null,
  fetcher: async () => Response.json({ access_token: token, expires_in: 3600 }) });
  const res = response(); await handler({ method: 'POST', headers: { origin },
    body: { email: 'fictional@example.invalid', password: 'test-only-placeholder' } }, res);
  assert.equal(res.code, 200); assert.deepEqual(res.body, { authenticated: true });
  assert.match(res.headers['set-cookie'], /Secure; HttpOnly; SameSite=Strict/u);
  assert.equal(sessionToken({ headers: { cookie: `${COOKIE}=${token}` } }), token);
  const out = response(); await handler({ method: 'DELETE', headers: { origin } }, out);
  assert.match(out.headers['set-cookie'], /Max-Age=0/u);
  assert.deepEqual(out.body, { authenticated: false });
  const invalid = response(); await handler({ method: 'POST', headers: { origin }, body: {} }, invalid);
  assert.equal(invalid.code, 400);
});
test('existing login verifier verifies judge signatures and student claims, rejects invalid identities', async () => {
  const { privateKey, publicKey } = await generateKeyPair('ES256');
  const verify = createLoginVerifier({ config, judgeKeySet: async () => publicKey,
    supabaseClient: { auth: { getClaims: async () => ({ data: { claims: {
      iss: config.identityProvider.issuer, aud: 'authenticated', role: 'authenticated',
      sub: userId, exp: Math.floor(Date.now() / 1000) + 60,
    } } }) } } });
  const base = { aleph_role: 'judge', aleph_identity: 'a', aleph_run: userId };
  const token = await new SignJWT(base).setProtectedHeader({ alg: 'ES256' }).setIssuer(config.judgeIssuer)
    .setAudience(new URL(config.publicAppUrl).hostname).setSubject(userId).setIssuedAt().setExpirationTime('5m').sign(privateKey);
  assert.equal((await verify(`Bearer ${token}`)).userId, userId);
  assert.equal(await verify(undefined), null);
  assert.equal(await verify('Bearer malformed'), null);
  const wrong = await new SignJWT(base).setProtectedHeader({ alg: 'ES256' }).setIssuer('https://other.example')
    .setSubject(userId).sign(privateKey);
  assert.equal(await verify(`Bearer ${wrong}`), null);
  const expired = await new SignJWT(base).setProtectedHeader({ alg: 'ES256' }).setIssuer(config.judgeIssuer)
    .setAudience(new URL(config.publicAppUrl).hostname).setSubject(userId)
    .setIssuedAt(Math.floor(Date.now() / 1000) - 120).setExpirationTime(Math.floor(Date.now() / 1000) - 60).sign(privateKey);
  assert.equal(await verify(`Bearer ${expired}`), null);
  const student = await new SignJWT({}).setProtectedHeader({ alg: 'ES256' })
    .setIssuer(config.identityProvider.issuer).sign(privateKey);
  assert.equal((await verify(`Bearer ${student}`)).kind, 'student');
});
test('stage3 self-check requires denial JSON and stage3 identity', async () => {
  const old = globalThis.fetch;
  try {
    globalThis.fetch = async url => {
      const path = new URL(url).pathname;
      if (path === '/api/notes') return Response.json({ error: 'unauthorized' }, { status: 401 });
      if (path === '/data.json') return new Response('', { status: 404 });
      if (path === '/aleph.json') return Response.json({ schema: 'aleph.defense.deployment.v1', step: 3 });
      return new Response('', { headers: { 'x-content-type-options': 'nosniff' } });
    };
    const result = await runAttackChecks(config);
    assert.match(result[1].observed, /HTTP 401; JSON 오류 확인/u);
    globalThis.fetch = async () => new Response('<html>login</html>', { status: 200 });
    assert.match((await runAttackChecks(config))[1].observed, /미확인/u);
  } finally { globalThis.fetch = old; }
});
test('static UI keeps credentials and hidden notes out of storage and markup', async () => {
  const html = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
  const app = await readFile(new URL('../public/app.js', import.meta.url), 'utf8');
  assert.match(html, /id="workspace" hidden/u);
  assert.match(app, /title\.textContent = note\.title/u);
  assert.doesNotMatch(app + html, /SUPABASE_SECRET_KEY|localStorage|sessionStorage|innerHTML/u);
});
test('client hides anonymous data, renders four cards after login, creates and logs out', async () => {
  const script = await readFile(new URL('../public/app.js', import.meta.url), 'utf8');
  function element() {
    return { hidden: false, value: '', events: {}, children: [],
      addEventListener(name, fn) { this.events[name] = fn; },
      replaceChildren(...items) { this.children = items; }, append(...items) { this.children.push(...items); },
      focus() {}, querySelector() { return this.button ??= element(); },
      reset() { for (const field of Object.values(this.elements ?? {})) field.value = ''; } };
  }
  const nodes = Object.fromEntries(['login', 'workspace', 'editor', 'notes', 'status', 'logout', 'cancel', 'editor-heading']
    .map(id => [`#${id}`, element()]));
  nodes['#login'].elements = { email: element(), password: element() };
  nodes['#editor'].elements = { title: element(), content: element() };
  let authenticated = false;
  let created;
  const rows = Array.from({ length: 4 }, (_, i) => ({ id: i + 1, title: `<b>${i}</b>`, content: 'fictional' }));
  const fetcher = async (url, init) => {
    if (url === '/api/session') {
      if (init.method === 'POST') authenticated = true;
      if (init.method === 'DELETE') authenticated = false;
      return authenticated || init.method === 'DELETE' ? Response.json({ authenticated })
        : Response.json({ error: 'unauthorized' }, { status: 401 });
    }
    assert.equal(authenticated, true);
    if (init.method === 'POST') { created = JSON.parse(init.body); rows.push({ id: 5, ...created }); }
    return Response.json({ notes: rows });
  };
  await runInNewContext(`(async () => {${script}\n})()`, {
    document: { querySelector: id => nodes[id], createElement: element }, fetch: fetcher, confirm: () => true,
  });
  assert.equal(nodes['#workspace'].hidden, true); assert.equal(nodes['#notes'].children.length, 0);
  nodes['#login'].elements.email.value = 'fictional@example.invalid';
  nodes['#login'].elements.password.value = 'test-only-placeholder';
  await nodes['#login'].events.submit({ preventDefault() {} });
  assert.equal(nodes['#workspace'].hidden, false); assert.equal(nodes['#notes'].children.length, 4);
  assert.equal(nodes['#notes'].children[0].children[0].textContent, '<b>0</b>');
  assert.equal(nodes['#login'].elements.password.value, '');
  nodes['#editor'].elements.title.value = 'test'; nodes['#editor'].elements.content.value = 'fictional';
  await nodes['#editor'].events.submit({ preventDefault() {} });
  assert.deepEqual(created, { title: 'test', content: 'fictional' });
  assert.equal(nodes['#notes'].children.length, 5);
  await nodes['#logout'].events.click();
  assert.equal(nodes['#workspace'].hidden, true); assert.equal(nodes['#notes'].children.length, 0);
});
