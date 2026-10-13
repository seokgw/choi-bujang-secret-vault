import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseLogs, reconcile } from '../scripts/auto-compare-vercel.mjs';
test('CLI records are redacted and restricted to the target production host',()=>{
 const raw=[
 {id:'v1',environment:'production',domain:'site.example',timestamp:1791875616933,
  requestMethod:'GET',requestPath:'/api/notes',responseStatusCode:401,cookie:'private'},
 {id:'v2',environment:'preview',domain:'site.example',timestamp:1791875616934,
  requestMethod:'GET',requestPath:'/api/notes',responseStatusCode:401}
 ].map(JSON.stringify).join('\n');
 const events=parseLogs(raw,'site.example');
 assert.equal(events.length,1);assert.equal(events[0].id,'v1');
 assert.equal(JSON.stringify(events).includes('private'),false);
});
test('same path and HTTP status do not prove matching request ID',()=>{
 const logs=[{id:'vercel-id',path:'/api/notes',method:'GET',status:401,at:'2026-10-13T07:00:00.000Z'}];
 const probes=[{attackId:'anonymous_note_rejection',path:'/api/notes',expected:[401,403],
   httpStatus:401,vercelId:'client-other-id',observedAt:'2026-10-13T07:00:00.000Z'}];
 const result=reconcile(probes,logs);
 assert.equal(result.verifiedMatches,0);
 assert.equal(result.records[0].evidence,'http_unverified');
 assert.equal(result.records[0].judgeVerified,false);
});
test('an exact matching Vercel ID still is not ALEPH judge pass',()=>{
 const logs=[{id:'v1',path:'/api/notes',method:'GET',status:401,at:'2026-10-13T07:00:00.000Z'}];
 const probes=[{attackId:'anonymous_note_rejection',path:'/api/notes',expected:[401,403],
   httpStatus:401,vercelId:'v1',observedAt:'2026-10-13T07:00:00.000Z'}];
 const result=reconcile(probes,logs);
 assert.equal(result.verifiedMatches,1);
 assert.equal(result.matchedJudgeAttacks,null);
 assert.equal(result.records[0].judgeVerified,false);
});
