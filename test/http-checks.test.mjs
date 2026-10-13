import assert from 'node:assert/strict';
import { test } from 'node:test';
import { observePublicChecks } from '../src/http-checks.mjs';
const config={publicAppUrl:'https://fixture.invalid',step:12};
test('records actual normal allowance and prohibited denial without verdict text or bodies',async()=>{
  const rows=await observePublicChecks(config,{fetcher:async url=>
    url.pathname==='/data.json'?new Response(null,{status:404}):
    url.pathname==='/api/notes'?Response.json({error:'unauthorized'},{status:401}):
    Response.json({schema:'aleph.defense.deployment.v1',step:12,commit:'a'.repeat(40)}),
    makeId:()=> 'req-fixture',now:()=> '2026-10-13T00:00:00.000Z'});
  assert.ok(rows.every(x=>x.observed==='not_run'));
  assert.equal(JSON.stringify(rows).includes('unauthorized'),false);
});
test('network failure stays not_run and an HTTP 200 login page is not valid evidence',async()=>{
  const absent=await observePublicChecks(config,{fetcher:async()=>{throw Error('offline');}});
  assert.ok(absent.every(x=>x.observed==='not_run'));
  const wrong=await observePublicChecks(config,{fetcher:async()=>new Response('<html>ok</html>',{status:200})});
  assert.ok(wrong.every(x=>x.observed==='not_run'));
});
