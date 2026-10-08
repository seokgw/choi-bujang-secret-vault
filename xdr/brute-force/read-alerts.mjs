import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';

const patterns = JSON.parse(await readFile(new URL('./patterns.json', import.meta.url), 'utf8'));
function integer(value) {
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return value;
  return typeof value === 'string' && /^\d{1,7}$/.test(value) ? Number(value) : null;
}
function vendorSignal(alert, raw) {
  // A trusted Wazuh correlation alert contains evidence aggregated upstream.
  // firedtimes is an alert counter, not a login failure count; never infer from it.
  if (integer(alert?.rule?.level) === null || integer(alert.rule.level) < 10
      || !Array.isArray(alert?.rule?.groups) || !Array.isArray(alert?.rule?.mitre?.id)) return null;
  return patterns.find(p => p.condition.vendorRules?.some(v =>
    String(alert.rule.id) === v.id && alert?.decoder?.name === v.decoder
    && alert.rule.groups.includes(v.group) && alert.rule.mitre.id.includes(v.mitre)
    && raw === v.description))?.condition.description ?? null;
}

// Free-form descriptions are never echoed: only recognized evidence summaries survive.
export function extractAlert(alert) {
  const raw = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const level = integer(alert?.rule?.level);
  let description = 'unknown';
  const failureSignal = /실패|failed\s+(?:login|logon|password|authentication)|(?:login|logon|authentication)\s+fail(?:ure|ed)/i.test(raw);
  const failures = raw.match(/실패(?:가|는)?\s*(\d+)\s*(?:건|회|번)/)
    ?? raw.match(/(\d+)\s+failed\s+(?:login|logon|authentication)\s+attempts?/i);
  const minutes = raw.match(/(?<![\d.\-])(\d+)\s*(?:분|minutes?\b|mins?\b)/i);
  const seconds = raw.match(/(?<![\d.\-])(\d+)\s*(?:초|seconds?\b|secs?\b)/i);
  const duration = minutes || seconds ? (minutes ? Number(minutes[1]) * 60 : 0)
    + (seconds ? Number(seconds[1]) : 0) : null;
  // Wazuh count is commonly a decimal string. Read it only for an explicit
  // authentication failure, never from firedtimes or unrelated event counters.
  const aggregateCount = integer(alert?.data?.count) ?? 0;
  const count = failures ? Number(failures[1]) : failureSignal ? aggregateCount : 0;
  const accounts = raw.match(/같은 주소가 계정\s*(\d+)개에 같은 간격으로 로그인 실패/);
  const repeated = /한 글자씩 바꿔|로그인 실패.*이어졌|로그인 실패.*성공은 없습니다/.test(raw);
  const strongRepeated = (
    (count >= 30 && duration === null && repeated)
    || (accounts && Number(accounts[1]) >= 10)
  );
  const spraying = (/같은 비밀번호/.test(raw) && /여러 계정|서로 다른 계정/.test(raw))
    || (/\b(?:same|single) password\b/i.test(raw) && /\b(?:multiple|different|many) (?:user )?accounts\b/i.test(raw));
  if (spraying) description = 'password-spraying';
  else if ((failureSignal && count >= 30 && duration > 0 && duration <= 180) || strongRepeated) description = 'rapid-login-failures';
  else if (failureSignal) description = 'ambiguous-failures';
  else if (/성공|로그아웃|세션 유지|로그인 상태|자료실 화면|\b(?:login|logon|authentication) (?:succeeded|successful|success)\b|\blogged out\b|\bsession (?:active|maintained)\b/i.test(raw)) description = 'normal-event';
  // A small corrected login is recorded, rather than escalated as an attack.
  // Success alone never overrides high-volume or spraying evidence.
  if (description === 'ambiguous-failures' && count >= 1 && count <= 6
      && level !== null && level <= 7
      && /뒤(?:에)?\s*성공|\b(?:then|followed by)\s+(?:a\s+)?(?:successful (?:login|logon)|success)\b/i.test(raw)
      && !spraying && !/여러 계정|서로 다른 계정|계정 이름을 바꿔|\b(?:multiple|different|many) (?:user )?accounts\b/i.test(raw)) description = 'normal-event';
  const vendor = vendorSignal(alert, raw);
  if (vendor) description = vendor;
  // Structured failure aggregates do not require a MITRE tag or exact wording.
  const failuresTotal = integer(alert?.data?.failure_count);
  const windowSeconds = integer(alert?.data?.window_seconds);
  if (['login_failure', 'authentication_failed'].includes(alert?.data?.event_type)
      && Number.isInteger(failuresTotal) && failuresTotal >= 30
      && Number.isInteger(windowSeconds) && windowSeconds > 0 && windowSeconds <= 180
      && alert?.data?.same_source === true) description = 'rapid-login-failures';
  // Explicitly requested stricter policy for low-volume unresolved failures.
  // This is an operational threshold, not proof that the event is an attack.
  const unresolvedCount = count * (/두 계정.*건씩/.test(raw) ? 2 : 1);
  if (description === 'ambiguous-failures' && level !== null
      && level >= 5 && level <= 8
      && unresolvedCount >= 3 && unresolvedCount <= 8
      && (duration === null || (duration > 0 && duration <= 600)) && !/성공|success/i.test(raw)) {
    description = 'repeated-login-failures-policy';
  }
  const time = typeof alert?.timestamp === 'string' ? Date.parse(alert.timestamp) : NaN;
  return {
    timestamp: Number.isFinite(time) ? new Date(time).toISOString() : null,
    source: isIP(alert?.data?.srcip ?? '') ? alert.data.srcip : null,
    account: /^user\d{2}$/.test(alert?.data?.srcuser ?? '') ? alert.data.srcuser : null,
    level,
    description,
  };
}

export async function readAlerts(path = new URL('../fixtures/brute-force.json', import.meta.url)) {
  const fixture = JSON.parse(await readFile(path, 'utf8'));
  if (!Array.isArray(fixture.alerts)) throw new Error('경보 배열이 없습니다.');
  return fixture.alerts.map(extractAlert);
}
