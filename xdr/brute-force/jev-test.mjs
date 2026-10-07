import assert from 'node:assert/strict';
import { createTypeSafeProvider, ENDPOINT } from './typesafe-jev.mjs';
const summary = { description: 'ambiguous-failures', level: 6, source: 'DO_NOT_SEND', account: 'DO_NOT_SEND', password: 'DO_NOT_SEND' };
let calls = 0;
const provider = createTypeSafeProvider({ apiKey: 'fixture-only', fetchImpl: async (url, options) => {
  calls++;
  assert.equal(url, ENDPOINT);
  assert.equal(options.redirect, 'error');
  assert(!options.body.includes('DO_NOT_SEND'));
  assert(!options.body.includes('fixture-only'));
  const request = JSON.parse(options.body);
  assert.equal(request.questions.brute_force.type, 'noul');
  return Response.json({ answers: { brute_force: { type: 'noul', noul: 0.6 } } });
} });
assert.equal(await provider(summary), 0.6);
assert.equal(calls, 1);
for (const response of [Response.json({}, { status: 401 }), Response.json({}, { status: 429 }),
  Response.json({ answers: { brute_force: { type: 'noul', noul: 2 } } }),
  Response.json({ answers: { brute_force: { type: 'choice', confidence: 0.9 } } })]) {
  await assert.rejects(createTypeSafeProvider({ apiKey: 'fixture-only', fetchImpl: async () => response })(summary));
}
await assert.rejects(createTypeSafeProvider({ apiKey: 'fixture-only', fetchImpl: async () => { throw Error('offline'); } })(summary));
await assert.rejects(createTypeSafeProvider({ fetchImpl: async () => { throw Error('must not call'); } })(summary));
console.log('PASS: official request/response, privacy whitelist, missing key, HTTP errors, malformed answer, network failure (mock transport).');
