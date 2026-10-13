import { test } from 'node:test';
import assert from 'node:assert/strict';
import { compareEvidence } from '../scripts/compare-vercel-evidence.mjs';

test('matching Vercel log ID and HTTP status is correlated, but not ALEPH verified', () => {
  const log=JSON.stringify({id:'vercel-log-1',timestamp:1791875616933,environment:'production',
    requestMethod:'GET',requestPath:'/api/notes',responseStatusCode:401,
    message:'do not expose',authorization:'secret'});
  const result=compareEvidence(log,{http:{records:[{attackId:'anonymous_note_rejection',
    requestId:'vercel-log-1',httpStatus:401}]}});
  assert.equal(result.matched,1);
  assert.equal(result.records[0].judgeVerified,false);
  assert.equal(JSON.stringify(result).includes('secret'),false);
});
test('similar time/path without exact Vercel request ID stays not_run',()=>{
  const log=JSON.stringify({id:'real-vercel-id',timestamp:1791875616933,environment:'production',
    requestMethod:'GET',requestPath:'/api/notes',responseStatusCode:401});
  const result=compareEvidence(log,{http:{records:[{attackId:'anonymous_note_rejection',
    requestId:'client-generated-uuid',httpStatus:401}]}});
  assert.equal(result.matched,0);
  assert.equal(result.records[0].correlation,'not_run');
  assert.equal(result.records[0].vercelRequestId,null);
});
