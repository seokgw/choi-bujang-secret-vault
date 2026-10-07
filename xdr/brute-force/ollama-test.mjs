import assert from 'node:assert/strict';
import { createOllamaProvider } from './ollama.mjs';
let calls = 0;
const summary = { description: 'ambiguous-failures', level: 6, source: 'DO_NOT_SEND', account: 'DO_NOT_SEND' };
const provider = createOllamaProvider({ model: 'fixture-model', fetchImpl: async (url, options) => {
  calls++;
  assert.equal(url, 'http://127.0.0.1:11434/api/generate');
  assert(!options.body.includes('DO_NOT_SEND'));
  const body = JSON.parse(options.body);
  assert.equal(body.stream, false);
  assert.equal(body.format.required[0], 'score');
  return Response.json({ done: true, response: '{"score":0.2}' });
} });
assert.equal(await provider(summary), 0.2);
assert.equal(await provider(summary), 0.2);
assert.equal(calls, 1);
for (const response of [Response.json({}, { status: 500 }), Response.json({ done: false }),
  Response.json({ done: true, response: '{"score":2}' }), Response.json({ done: true, response: 'invalid' })]) {
  await assert.rejects(createOllamaProvider({ model: 'fixture-model', fetchImpl: async () => response })(summary));
}
console.log('PASS: local-only request, privacy whitelist, caching, HTTP failure, incomplete/malformed/out-of-range score.');
