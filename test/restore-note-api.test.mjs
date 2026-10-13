import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
import { createNoteRestoreHandler } from '../api/restore-note.js';

const sha = s => createHash('sha256').update(s).digest('hex');
const B = '00000000-0000-4000-8000-00000000000b';
const A = '00000000-0000-4000-8000-00000000000a';
const before = () => [
  { id: 1, ownerId: A, title: 'A', content: 'A original' },
  { id: 2, ownerId: B, title: 'B', content: 'B modified' },
  { id: 3, ownerId: B, title: 'B other', content: 'untouched' },
];
const response = () => ({ headers:{}, setHeader(k,v){this.headers[k]=v;},
  status(n){this.code=n;return this;},json(v){this.body=v;return this;} });
function harness({ tamperHash = false, identity = 'b' } = {}) {
  const notes = before();
  const audit = [{ action:'original', id:2 }];
  const safe = 'B restored';
  const handler = createNoteRestoreHandler({
    verify: async () => ({ kind:'judge', identity, userId:B, runId:'run_fixture' }),
    origin: () => true,
    loadVerifiedBackup: async () => ({ verified:true, id:2, ownerId:B, title:'B',content:safe,
      contentSha256:tamperHash?sha('wrong'):sha(safe) }),
    trialStore: { async restoreOne({id,ownerId,title,content,expectedContentSha256}) {
      const found=notes.filter(row=>row.id===id&&row.ownerId===ownerId);
      if(found.length!==1)return null;
      Object.assign(found[0],{title,content});
      return {id,ownerId,contentSha256:sha(found[0].content)};
    }},
  });
  const send = async (id=2,method='POST') => {
    const res=response();
    await handler({ method,query:{},body:{id},headers:{} },res);
    return res;
  };
  return { notes,audit,send };
}
test('B restores exactly one verified record while A and other B note and audit survive',async()=>{
  const h=harness();
  const beforeAudit=structuredClone(h.audit);
  const res=await h.send();
  assert.equal(res.code,200);
  assert.deepEqual(res.body,{restored:true,id:2,owner:'b',contentSha256:sha('B restored')});
  assert.equal(h.notes[1].content,'B restored');
  assert.equal(h.notes[0].content,'A original');
  assert.equal(h.notes[2].content,'untouched');
  assert.deepEqual(h.audit,beforeAudit);
});
test('invalid snapshot hash and wrong identity do not modify a note',async()=>{
  for(const options of [{tamperHash:true},{identity:'a'}]){
    const h=harness(options);const prior=structuredClone(h.notes);
    const res=await h.send();
    assert.notEqual(res.code,200);assert.deepEqual(h.notes,prior);
  }
});
test('without verified backup and trial store POST fails closed',async()=>{
  const handler=createNoteRestoreHandler({
    verify:async()=>({kind:'judge',identity:'b',userId:B,runId:'run_fixture'}),
    origin:()=>true
  });
  const res=response();await handler({method:'POST',query:{},body:{id:2},headers:{}},res);
  assert.equal(res.code,503);
  assert.equal(res.body.error,'verified_backup_unavailable');
});
