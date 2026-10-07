import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';

// Free-form descriptions are never echoed: only recognized evidence summaries survive.
export function extractAlert(alert) {
  const raw = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  let description = 'unknown';
  const failures = raw.match(/(?:로그인 )?실패(?:가)?\s*(\d+)건/);
  const minutes = raw.match(/(\d+)분/);
  const count = failures ? Number(failures[1]) : 0;
  if (/같은 비밀번호/.test(raw) && /여러 계정|서로 다른 계정/.test(raw)) description = 'password-spraying';
  else if (count >= 30 && minutes && Number(minutes[1]) <= 3) description = 'rapid-login-failures';
  else if (/실패/.test(raw)) description = 'ambiguous-failures';
  else if (/성공|로그아웃|세션 유지|로그인 상태|자료실 화면/.test(raw)) description = 'normal-event';
  if (count === 1 && /뒤에 성공/.test(raw)) description = 'normal-event';
  const time = Date.parse(alert?.timestamp);
  return {
    timestamp: Number.isFinite(time) ? new Date(time).toISOString() : null,
    source: isIP(alert?.data?.srcip ?? '') ? alert.data.srcip : null,
    account: /^user\d{2}$/.test(alert?.data?.srcuser ?? '') ? alert.data.srcuser : null,
    level: Number.isInteger(alert?.rule?.level) ? alert.rule.level : null,
    description,
  };
}

export async function readAlerts(path = new URL('../fixtures/brute-force.json', import.meta.url)) {
  const fixture = JSON.parse(await readFile(path, 'utf8'));
  if (!Array.isArray(fixture.alerts)) throw new Error('경보 배열이 없습니다.');
  return fixture.alerts.map(extractAlert);
}
