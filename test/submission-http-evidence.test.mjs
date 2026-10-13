import { test } from 'node:test';
import assert from 'node:assert/strict';
import { observePublicChecks } from '../src/http-checks.mjs';

test('uncorrelated public checks are not submitted as executed attacks',async()=>{
  const config={publicAppUrl:'https://example.invalid/',step:12};
  const headers={'content-type':'application/json'};
  const responses={
    '/data.json':new Response('',{status:404}),
    '/api/notes':new Response(JSON.stringify({error:'unauthorized'}),{status:401,headers}),
    '/aleph.json':new Response(JSON.stringify({schema:'aleph.defense.deployment.v1',step:12,commit:'a'.repeat(40)}),{status:200,headers})
  };
  let index=0;
  const results=await observePublicChecks(config,{
    fetcher:async url=>responses[new URL(url).pathname].clone(),
    makeId:()=>['11111111-1111-4111-8111-111111111111','22222222-2222-4222-8222-222222222222','33333333-3333-4333-8333-333333333333'][index++],
    now:()=> '2026-10-13T09:00:00.000Z'
  });
  assert.deepEqual(results.map(r=>r.attackId),['static_note_removal','anonymous_note_rejection','deployment_identity']);
  assert.ok(results.every(r=>r.observed==='not_run'));
  assert.equal(results.every(r=>Object.keys(r).sort().join(',')==='attackId,expected,observed'),true);
});
test('unexpected API response does not become a submitted attack result',async()=>{
 const results=await observePublicChecks({publicAppUrl:'https://example.invalid/',step:12},{
   fetcher:async()=>new Response('wrong',{status:200}),
   makeId:()=> '44444444-4444-4444-8444-444444444444',
   now:()=> '2026-10-13T09:00:00.000Z'
 });
 assert.equal(results.every(r=>r.observed==='not_run'),true);
});
