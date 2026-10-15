// Self-contained copies of xdr/known-cve/patterns.json; no imports or I/O.
const PATTERNS = Object.freeze([
  {
    name: 'log4shell-jndi-header',
    condition: {
      signal: 'HTTP 요청 머리글의 JNDI 원격 조회 구문',
      scope: 'Wazuh data.useragent 등 요청 머리글',
      match: '머리글에서 완전한 JNDI 외부 참조 구문 확인',
      exclude: '단순 jndi·CVE·중괄호 단어만으로 확정하지 않음'
    },
    evidence: 'CVE-2021-44228; MITRE ATT&CK T1190'
  },
  {
    name: 'log4shell-jndi-query',
    condition: {
      signal: 'HTTP 요청 인자의 JNDI 원격 조회 구문',
      scope: 'Wazuh data.url의 쿼리 인자',
      match: '인자에서 완전한 JNDI 외부 참조 구문 확인',
      exclude: 'CVE 이름 검색이나 jndi 수업 단어는 공격 확정에서 제외'
    },
    evidence: 'CVE-2021-44228; MITRE ATT&CK T1190'
  },
  {
    name: 'known-cve-probe-indicator',
    condition: {
      signal: '알려진 취약점 점검·탐색 흔적',
      scope: 'Wazuh rule.description 및 data.url',
      match: 'CVE 점검 흔적 또는 불완전한 원격 조회 정황',
      exclude: '문서 열람·수업 도구 유사 이름·일반 단어만으로 차단 금지'
    },
    evidence: 'known-cve fixture kc-05, kc-11, kc-13; MITRE ATT&CK T1190'
  }
]);

const LOOKUP = new RegExp('\\$\\{jndi:(?:ldap|ldaps|rmi|dns|iiop|http|https):\\/\\/[^\\s{}]+\\}', 'i');
const CVE = /CVE-2021-44228/i;
const PROBE = /점검 흔적|점검 도구|취약점|CVE-2021-44228|원격 조회|조회 형태|jndi|lookup|중괄호|라이브러리 이름/i;
const NEGATIVE = /구문은 없습니다|악용 구문은 없습니다|완전한 구문은 아닙니다/i;

export function decide(alert) {
  const data = alert && typeof alert === 'object' ? alert.data : null;
  const rule = alert && typeof alert === 'object' ? alert.rule : null;
  const description = typeof rule?.description === 'string' ? rule.description : '';
  const header = typeof data?.useragent === 'string' ? data.useragent : '';
  const url = typeof data?.url === 'string' ? data.url : '';
  const query = url.includes('?') ? url.slice(url.indexOf('?') + 1) : '';
  const mitre = Array.isArray(rule?.mitre) ? rule.mitre.includes('T1190')
    : Array.isArray(rule?.mitre?.id) && rule.mitre.id.includes('T1190');
  const level = Number(rule?.level);
  // Raw syntax is stronger evidence than a free-form Wazuh description.
  // Restrict header and query reads to documented fixture fields.
  const headerMatch = LOOKUP.test(header);
  const queryMatch = LOOKUP.test(query);
  if (headerMatch || queryMatch) {
    const pattern = PATTERNS[headerMatch ? 0 : 1];
    const confidence = mitre && Number.isFinite(level) && level >= 10 ? 0.98 : 0.9;
    return { action: 'block', confidence, reason: pattern.name };
  }
  // Without the raw lookup string, descriptions alone must not cause a block.
  // These weak T1190-related signals merit review, never automatic denial.
  // A document, a class tool name, or a library reference alone is ambiguous;
  // ordinary access with no vulnerability signal stays record.
  const suspiciousText = PROBE.test(description) || CVE.test(query);
  if (suspiciousText && mitre && Number.isFinite(level) && level >= 5) {
    const confidence = NEGATIVE.test(description) ? 0.55 : 0.65;
    return { action: 'alert', confidence, reason: PATTERNS[2].name };
  }
  return { action: 'record', confidence: 0.05, reason: 'no-matching-pattern' };
}
