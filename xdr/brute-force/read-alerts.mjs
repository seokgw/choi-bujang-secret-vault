import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';

// Free-form descriptions are never echoed: only recognized evidence summaries survive.
export function extractAlert(alert) {
  const raw = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  let description = 'unknown';
  const failures = raw.match(/(?:로그인 )?실패(?:가)?\s*(\d+)건/);
  const minutes = raw.match(/(\d+)분/);
  const count = failures ? Number(failures[1]) : 0;
  const accounts = raw.match(/같은 주소가 계정\s*(\d+)개에 같은 간격으로 로그인 실패/);
  const repeated = /한 글자씩 바꿔|로그인 실패.*이어졌|로그인 실패.*성공은 없습니다/.test(raw);
  const strongRepeated = alert?.rule?.level >= 10 && (
    (count >= 30 && !minutes && repeated)
    || (accounts && Number(accounts[1]) >= 10)
  );
  if (/같은 비밀번호/.test(raw) && /여러 계정|서로 다른 계정/.test(raw)) description = 'password-spraying';
  else if ((count >= 30 && minutes && Number(minutes[1]) <= 3) || strongRepeated) description = 'rapid-login-failures';
  else if (/실패/.test(raw)) description = 'ambiguous-failures';
  else if (/성공|로그아웃|세션 유지|로그인 상태|자료실 화면/.test(raw)) description = 'normal-event';
  // A small corrected login is recorded, rather than escalated as an attack.
  // Success alone never overrides high-volume or spraying evidence.
  if (description === 'ambiguous-failures' && count >= 1 && count <= 6
      && Number.isInteger(alert?.rule?.level) && alert.rule.level <= 7
      && /뒤(?:에)?\s*성공/.test(raw)
      && !/여러 계정|서로 다른 계정|계정 이름을 바꿔|같은 비밀번호/.test(raw)) description = 'normal-event';
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
