import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { pathToFileURL } from 'node:url';

// Read-only inspection. Never expose arbitrary account names or raw event fields.
function safeDescription(value) {
  if (typeof value !== 'string') return null;
  if (/password|passwd|pwd|token|secret|api[ _-]?key|private[ _-]?key|cookie|authorization|bearer|credential|비밀번호|패스워드|토큰|인증정보|비밀|개인키|-----BEGIN|(?:sk-|ghp_|github_pat_)\S+|eyJ[\w-]+\.[\w-]+\.[\w-]+|[A-Za-z0-9+/_=-]{32,}/i.test(value)) {
    return '[REDACTED]';
  }
  return value.replace(/[\r\n\u2028\u2029\u0000-\u001f\u007f]+/g, ' ');
}

export function extractAlert(alert) {
  const time = typeof alert?.timestamp === 'string' ? Date.parse(alert.timestamp) : NaN;
  const source = alert?.data?.srcip;
  const account = alert?.data?.srcuser;
  const rawLevel = alert?.rule?.level;
  const level = typeof rawLevel === 'string' && /^\d{1,3}$/.test(rawLevel)
    ? Number(rawLevel) : rawLevel;
  return {
    timestamp: Number.isFinite(time) ? new Date(time).toISOString() : null,
    source: typeof source === 'string' && isIP(source) ? source : null,
    account: typeof account === 'string' && /^(?:user\d{2}|admin\d{2}|svc-lab)$/.test(account) ? account : null,
    level: Number.isSafeInteger(level) && level >= 0 ? level : null,
    description: safeDescription(alert?.rule?.description),
  };
}

export async function readAlerts(path = new URL('../fixtures/privilege.json', import.meta.url)) {
  const fixture = JSON.parse(await readFile(path, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || fixture.moduleKey !== 'privilege'
      || !Array.isArray(fixture.alerts)) throw new Error('경보 배열 형식이 아닙니다.');
  return fixture.alerts.map(extractAlert);
}

// This inspection helper is independent of privilege/decide.mjs.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    for (const alert of await readAlerts()) process.stdout.write(JSON.stringify(alert) + '\n');
  } catch {
    console.error('경보 읽기에 실패했습니다. 입력 형식을 확인하세요.');
    process.exitCode = 1;
  }
}
