import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createDeviceApprovalHandler } from '../api/device-approval.js';
import { createNotesHandler } from '../api/notes.js';
function res(){return {headers:{},setHeader(k,v){this.headers[k]=v;},status(n){this.code=n;return this;},json(x){this.body=x;return this;}};}
test('request does not grant approval; GET remains unverified', async()=>{
  const handler=createDeviceApprovalHandler({verify:async()=>({userId:'test-user'}),origin:()=>true});
  const r=res();await handler({method:'POST'},r);
  assert.equal(r.code,202);assert.equal(r.body.trusted,false);
  const g=res();await handler({method:'GET'},g);
  assert.equal(g.code,200);assert.equal(g.body.trusted,false);
});
test('non-approved request cannot fetch note or reach data fetch',async()=>{
  let fetched=false;
  const handler=createNotesHandler({verify:async()=>({userId:'test-user'}),deny:async()=>false,
    deviceApproved:async()=>false,fetcher:async()=>{fetched=true;throw Error('must not run');}});
  const r=res();await handler({method:'GET',query:{id:'1'},headers:{}},r);
  assert.equal(r.code,403);assert.equal(fetched,false);
});
test('approved device can progress to previous note protections',async()=>{
  const handler=createNotesHandler({verify:async()=>({userId:'test-user'}),deny:async()=>true,
    deviceApproved:async()=>true});
  const r=res();await handler({method:'GET',query:{id:'1'},headers:{}},r);
  assert.equal(r.code,403);assert.equal(r.headers['X-Aleph-Denial-Reason'],'xdr_denied');
});
test('unauthenticated enrollment is denied',async()=>{
  const handler=createDeviceApprovalHandler({verify:async()=>null,origin:()=>true});
  const r=res();await handler({method:'POST'},r);assert.equal(r.code,401);
});
