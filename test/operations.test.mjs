import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createOperationsHandler } from '../api/operations.js';

function reply() { return {
  headers: {}, setHeader(k,v){ this.headers[k]=v; },
  status(n){ this.statusCode=n; return this; }, json(x){this.payload=x;return this;}
}; }
test('server summary redacts user and never invents evidence', async () => {
  const handler=createOperationsHandler({verify:async()=>({userId:'fixture-private-id'}),deviceCheck:async()=>false});
  const res=reply();await handler({method:'GET'},res);
  assert.equal(res.statusCode,200);
  assert.equal(res.payload.policy.status,'code_inventory');
  assert.equal(res.payload.policy.count,null);
  assert.equal(res.payload.policy.verifiedCount,null);
  assert.ok(res.payload.policy.rules.length > 0);
  assert.equal(res.payload.detection.status,'not_run');
  assert.equal(res.payload.detection.count,null);
  assert.equal(res.payload.revocation.count,null);
  assert.equal(res.payload.recovery.version,null);
  assert.equal(res.payload.assault.defended,null);
  assert.equal(res.payload.device.approved,false);
  assert.equal(JSON.stringify(res.payload).includes('fixture-private-id'),false);
});
test('unauthenticated access rejected', async () => {
  const res=reply();await createOperationsHandler({verify:async()=>null})({method:'GET'},res);
  assert.equal(res.statusCode,401);
});
