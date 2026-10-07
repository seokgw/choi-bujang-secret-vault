import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { deploymentIdentity } from './deployment-identity.mjs';

const root = resolve(import.meta.dirname, '..');
const output = resolve(root, 'public', 'data.json');
const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));
if (![2, 3, 4, 5].includes(config.step)) throw new Error('현재 빌드는 2·3·4·5단계 설정이 필요합니다.');
if (config.step >= 5) {
  const original = new URL(config.originalApiUrl);
  const issuer = new URL(config.identityProvider.issuer);
  if (original.protocol !== 'https:' || original.origin !== issuer.origin
      || original.pathname !== '/rest/v1/training_notes' || original.search
      || original.hash || original.username || original.password) {
    throw new Error('원본 API 주소는 실제 프로젝트의 쿼리 없는 메모 HTTPS 경로여야 합니다.');
  }
}
await mkdir(resolve(root, 'public'), { recursive: true });
await rm(output, { force: true });
console.log('공개 data.json을 생성하지 않습니다.');
const xdr = JSON.parse(await readFile(resolve(root, 'xdr/brute-force/result.json'), 'utf8'));
const counts = {};
for (const action of ['block', 'alert', 'record']) {
  if (!Number.isSafeInteger(xdr.counts?.[action]) || xdr.counts[action] < 0) throw new Error('XDR 집계 형식 오류');
  counts[action] = xdr.counts[action];
}
if (!Number.isSafeInteger(xdr.validation?.normalBlocked) || xdr.validation.normalBlocked < 0) throw new Error('XDR 오탐 집계 형식 오류');
await mkdir(resolve(root, 'public/xdr/brute-force'), { recursive: true });
await writeFile(resolve(root, 'public/xdr/brute-force/result.json'), `${JSON.stringify({
  schema: 'aleph.xdr.public.v1', moduleKey: 'brute-force', counts,
  normalBlocked: xdr.validation.normalBlocked,
  productionConnected: xdr.validation.productionConnected === true,
  scope: '가상 경보 로컬 검증. 운영 ZTNA 차단은 연결되지 않았습니다.',
}, null, 2)}\n`, 'utf8');
if (!process.argv.includes('--local')) {
  const identity = deploymentIdentity(process.env, config);
  await writeFile(resolve(root, 'public', 'aleph.json'),
    `${JSON.stringify(identity, null, 2)}\n`, 'utf8');
  console.log('배포 저장소·커밋·주소를 public/aleph.json에 기록했습니다.');
}
