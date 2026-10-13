import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createOperationsHandler } from '../api/operations.js';

function reply() { return {
  headers: {}, setHeader(k,v){ this.headers[k]=v; },
  status(n){ this.statusCode=n; return this; }, json(x){this.payload=x;return this;}
}; }
test('server summary redacts user and never invents evidence', async () => {
  const handler=createOperationsHandler({verify:async()=>({userId:'fixture-private-id'}),evidenceSource:async()=>[]});
  const res=reply();await handler({method:'GET'},res);
  assert.equal(res.statusCode,200);
  assert.equal(res.payload.policy.status,'code_inventory');
  assert.equal(res.payload.policy.count,'not_run');
  assert.equal(res.payload.policy.verifiedCount,'not_run');
  assert.ok(res.payload.policy.rules.length > 0);
  assert.equal(res.payload.detection.status,'not_run');
  assert.equal(res.payload.detection.count,'not_run');
  assert.equal(res.payload.revocation.count,'not_run');
  assert.equal(res.payload.recovery.version,'not_run');
  assert.equal(res.payload.assault.defended,'not_run');
  assert.equal(res.payload.device.approved,false);
  assert.equal(JSON.stringify(res.payload).includes('fixture-private-id'),false);
});
test('unauthenticated access rejected', async () => {
  const res=reply();await createOperationsHandler({verify:async()=>null})({method:'GET'},res);
  assert.equal(res.statusCode,401);
});

test('dashboard HTTP totals equal the exact redacted evidence rows', async () => {
  const evidenceSource=async()=>[
    {attackId:'static_note_removal',requestId:'req-1',checkedAt:'2026-10-13T00:00:00.000Z',httpStatus:404,source:'direct_http',judgeCorrelated:false},
    {attackId:'anonymous_note_rejection',requestId:'req-2',checkedAt:'2026-10-13T00:00:01.000Z',httpStatus:401,source:'direct_http',judgeCorrelated:false}
  ];
  const handler=createOperationsHandler({verify:async()=>({userId:'fixture-private-id'}),evidenceSource});
  const response=reply();await handler({method:'GET'},response);
  assert.equal(response.statusCode,200);
  assert.equal(response.payload.http.observed,2);
  assert.equal(response.payload.http.records.length,3);
  assert.deepEqual(response.payload.http.records.map(x=>x.httpStatus),[404,401,'not_run']);
  assert.equal(response.payload.http.records[2].status,'not_run');
  assert.equal(response.payload.http.records.every(x=>x.judgeCorrelated===false),true);
  assert.equal(JSON.stringify(response.payload).includes('fixture-private-id'),false);
});
