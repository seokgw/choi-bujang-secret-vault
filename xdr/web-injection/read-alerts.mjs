import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { pathToFileURL } from 'node:url';

// Discard the entire description if it might contain credentials. Never echo
// request URLs, headers, bodies or other unrequested Wazuh fields.
function safeDescription(value) {
  if (typeof value !== 'string') return null;
  if (/password|passwd|pwd|token|secret|api[ _-]?key|private[ _-]?key|cookie|authorization|bearer|credential|비밀번호|패스워드|토큰|인증|비밀|개인키/i.test(value)
      || /-----BEGIN|(?:sk-|ghp_|jv_live_)\S+|eyJ[\w-]+\.[\w-]+\.[\w-]+|[A-Za-z0-9+/_=-]{32,}/.test(value)) return '[REDACTED]';
  return value.replace(/[\r\n\u2028\u2029]+/g, ' ');
}

export function extractAlert(alert) {
  const timestamp = typeof alert?.timestamp === 'string' ? Date.parse(alert.timestamp) : NaN;
  const source = alert?.data?.srcip;
  const account = alert?.data?.srcuser;
  const rawLevel = alert?.rule?.level;
  const level = typeof rawLevel === 'string' && /^\d{1,3}$/.test(rawLevel) ? Number(rawLevel) : rawLevel;
  return {
    timestamp: Number.isFinite(timestamp) ? new Date(timestamp).toISOString() : null,
    source: typeof source === 'string' && isIP(source) ? source : null,
    // This training repository contains virtual accounts only.
    account: typeof account === 'string' && /^user\d{2}$/.test(account) ? account : null,
    level: Number.isSafeInteger(level) && level >= 0 ? level : null,
    description: safeDescription(alert?.rule?.description),
  };
}

export async function readAlerts(path = new URL('../fixtures/web-injection.json', import.meta.url)) {
  const fixture = JSON.parse(await readFile(path, 'utf8'));
  if (!Array.isArray(fixture.alerts)) throw new Error('경보 배열이 없습니다.');
  return fixture.alerts.map(extractAlert);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    for (const alert of await readAlerts()) process.stdout.write(`${JSON.stringify(alert)}\n`);
  } catch {
    console.error('경보 읽기에 실패했습니다. 입력 파일 형식을 확인하세요.');
    process.exitCode = 1;
  }
}
