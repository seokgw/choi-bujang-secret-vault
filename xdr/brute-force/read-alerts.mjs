import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';

const patterns = JSON.parse(await readFile(new URL('./patterns.json', import.meta.url), 'utf8'));
function vendorSignal(alert, raw) {
  // A trusted Wazuh correlation alert contains evidence aggregated upstream.
  // firedtimes is an alert counter, not a login failure count; never infer from it.
  if (!Number.isInteger(alert?.rule?.level) || alert.rule.level < 10
      || !Array.isArray(alert?.rule?.groups) || !Array.isArray(alert?.rule?.mitre?.id)) return null;
  return patterns.find(p => p.condition.vendorRules?.some(v =>
    String(alert.rule.id) === v.id && alert?.decoder?.name === v.decoder
    && alert.rule.groups.includes(v.group) && alert.rule.mitre.id.includes(v.mitre)
    && raw === v.description))?.condition.description ?? null;
}

// Free-form descriptions are never echoed: only recognized evidence summaries survive.
export function extractAlert(alert) {
  const raw = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  let description = 'unknown';
  const failures = raw.match(/(?:로그인 )?실패(?:가)?\s*(\d+)건/);
  const minutes = raw.match(/(\d+)분/);
  const count = failures ? Number(failures[1]) : 0;
  const accounts = raw.match(/같은 주소가 계정\s*(\d+)개에 같은 간격으로 로그인 실패/);
  const repeated = /한 글자씩 바꿔|로그인 실패.*이어졌|로그인 실패.*성공은 없습니다/.test(raw);
  const strongRepeated = (
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
  const vendor = vendorSignal(alert, raw);
  if (vendor) description = vendor;
  // Structured failure aggregates do not require a MITRE tag or exact wording.
  const failuresTotal = alert?.data?.failure_count;
  const windowSeconds = alert?.data?.window_seconds;
  if (['login_failure', 'authentication_failed'].includes(alert?.data?.event_type)
      && Number.isInteger(failuresTotal) && failuresTotal >= 30
      && Number.isInteger(windowSeconds) && windowSeconds > 0 && windowSeconds <= 180
      && alert?.data?.same_source === true) description = 'rapid-login-failures';
  // Explicitly requested stricter policy for low-volume unresolved failures.
  // This is an operational threshold, not proof that the event is an attack.
  const unresolvedCount = count * (/두 계정.*건씩/.test(raw) ? 2 : 1);
  if (description === 'ambiguous-failures' && Number.isInteger(alert?.rule?.level)
      && alert.rule.level >= 5 && alert.rule.level <= 8
      && unresolvedCount >= 3 && unresolvedCount <= 8
      && (!minutes || Number(minutes[1]) <= 10) && !/성공/.test(raw)) {
    description = 'repeated-login-failures-policy';
  }
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
