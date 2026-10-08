// Portable decision function: no required imports, filesystem or module-level state.
export async function decide(alert) {

  // Standalone snapshot of patterns.json. Keep this fallback in sync when rules change.
  const fallbackPatterns = [
    {
      "name": "rapid-login-failures",
      "condition": {
        "description": "rapid-login-failures",
        "minimumLevel": 0,
        "confidence": 0.95,
        "vendorRules": [
          {
            "id": "5712",
            "decoder": "sshd",
            "group": "authentication_failures",
            "mitre": "T1110",
            "description": "sshd: brute force trying to get access to the system. Non existent user."
          },
          {
            "id": "5720",
            "decoder": "sshd",
            "group": "authentication_failures",
            "mitre": "T1110",
            "description": "sshd: Multiple authentication failures."
          }
        ]
      }
    },
    {
      "name": "password-spraying",
      "condition": {
        "description": "password-spraying",
        "minimumLevel": 0,
        "confidence": 0.95
      }
    }
  ];
  const patterns = fallbackPatterns;


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
  function extractAlert(alert) {
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
    // A single corrected failure is ordinary; repeated failures remain ambiguous.
    if (description === 'ambiguous-failures' && count === 1 && level !== null && level <= 7
        && /뒤(?:에)?\s*성공|\b(?:then|followed by)\s+(?:a\s+)?(?:successful (?:login|logon)|success)\b/i.test(raw)
        && !/여러 계정|서로 다른 계정|계정 이름을 바꿔|\b(?:multiple|different|many) (?:user )?accounts\b/i.test(raw)) description = 'normal-event';
    const vendor = vendorSignal(alert, raw);
    if (vendor) description = vendor;
    // Structured failure aggregates do not require a MITRE tag or exact wording.
    const failuresTotal = integer(alert?.data?.failure_count);
    const windowSeconds = integer(alert?.data?.window_seconds);
    if (['login_failure', 'authentication_failed'].includes(alert?.data?.event_type)
        && Number.isInteger(failuresTotal) && failuresTotal >= 30
        && Number.isInteger(windowSeconds) && windowSeconds > 0 && windowSeconds <= 180
        && alert?.data?.same_source === true) description = 'rapid-login-failures';
    const time = typeof alert?.timestamp === 'string' ? Date.parse(alert.timestamp) : NaN;
    return {
      timestamp: Number.isFinite(time) ? new Date(time).toISOString() : null,
      source: isIP(alert?.data?.srcip ?? '') ? alert.data.srcip : null,
      account: /^user\d{2}$/.test(alert?.data?.srcuser ?? '') ? alert.data.srcuser : null,
      level,
      description,
    };
  }


  // Contract: https://docs.typesafe.ai/api (TypeSafe's first-party endpoint).
  const ENDPOINT = 'https://api.typesafe.ai/v1/systemone';

  function createTypeSafeProvider({ apiKey, fetchImpl = fetch } = {}) {
    return async summary => {
      if (!apiKey) throw new Error('Jev not configured');
      const res = await fetchImpl(ENDPOINT, {
        method: 'POST', redirect: 'error', signal: AbortSignal.timeout(900),
        headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: 'jev-latest',
          state: {
            signal: ['ambiguous-failures', 'unknown'].includes(summary.description) ? summary.description : 'unknown',
            ruleLevel: Number.isInteger(summary.level) ? summary.level : null,
            context: 'Local attack patterns were inconclusive. Missing evidence must not be assumed. No credentials or event text provided.',
          },
          questions: {
            brute_force: {
              type: 'noul',
              instructions: 'Does the provided evidence establish a brute-force login attack?',
              criteria: {
                true: 'Evidence explicitly establishes rapid repeated login failures or the same password attempted across multiple accounts.',
                false: 'Ordinary activity, insufficient evidence, or ambiguous failures. Rule severity alone does not establish an attack.',
              },
            },
          },
        }),
      });
      if (!res.ok) throw new Error(`Jev HTTP ${res.status}`);
      const answer = (await res.json())?.answers?.brute_force;
      if (answer?.type !== 'noul' || !Number.isFinite(answer.noul) || answer.noul < 0 || answer.noul > 1) {
        throw new Error('Jev invalid answer');
      }
      // Noul is P(attack), not the separate Choice/Score confidence property.
      return answer.noul;
    };
  }

  let optionalJev;
  async function askJev(summary) {
    optionalJev ??= (typeof process !== 'undefined' && process.versions?.node
      ? import('./jev.mjs') : Promise.resolve(null)).catch(error => {
      return null;
    });
    const connected = await optionalJev;
    if (connected) return connected.askJev(summary);
    // In a single-file deployment, use the same official API contract directly.
    const apiKey = typeof process !== 'undefined' ? process.env?.TYPESAFE_API_KEY : undefined;
    if (!apiKey) throw new Error('Jev unavailable');
    let timer;
    try {
      return await Promise.race([createTypeSafeProvider({ apiKey })(summary),
        new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Jev timeout')), 1000); })]);
    } finally { clearTimeout(timer); }
  }

  const signals = new Set(['rapid-login-failures', 'password-spraying', 'normal-event', 'ambiguous-failures']);
  function summaryOf(alert) {
    if (alert?.rule) return extractAlert(alert);
    if (!signals.has(alert?.description)) {
      return extractAlert({ timestamp: alert?.timestamp,
        rule: { level: alert?.level, description: alert?.description },
        data: { srcip: alert?.source, srcuser: alert?.account } });
    }
    // Accept the five-field output of readAlerts without re-extracting it as Wazuh.
    // Only known signal labels survive; free text and additional fields are discarded.
    const time = typeof alert?.timestamp === 'string' ? Date.parse(alert.timestamp) : NaN;
    return {
      timestamp: Number.isFinite(time) ? new Date(time).toISOString() : null,
      source: typeof alert?.source === 'string' && isIP(alert.source) ? alert.source : null,
      account: typeof alert?.account === 'string' && /^user\d{2}$/.test(alert.account) ? alert.account : null,
      level: Number.isInteger(alert?.level) ? alert.level : null,
      description: signals.has(alert?.description) ? alert.description : 'unknown',
    };
  }
  function response(confidence, reason) {
    return { action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record', confidence, reason };
  }

  function isIP(value) {
    if (typeof value !== 'string') return 0;
    const ipv4 = text => {
      const parts = text.split('.');
      return parts.length === 4 && parts.every(p => /^(?:0|[1-9]\d{0,2})$/.test(p) && Number(p) <= 255);
    };
    if (ipv4(value)) return 4;
    let v = value;
    if (v.includes('.')) {
      const last = v.lastIndexOf(':');
      if (last < 0 || !ipv4(v.slice(last + 1))) return 0;
      v = v.slice(0, last + 1) + '0:0';
    }
    if (!/^[0-9a-f:]+$/i.test(v)) return 0;
    const valid = groups => groups.every(p => /^[0-9a-f]{1,4}$/i.test(p));
    if (v.includes('::')) {
      const sides = v.split('::');
      if (sides.length !== 2) return 0;
      const left = sides[0] ? sides[0].split(':') : [];
      const right = sides[1] ? sides[1].split(':') : [];
      return valid(left) && valid(right) && left.length + right.length < 8 ? 6 : 0;
    }
    const parts = v.split(':');
    return parts.length === 8 && valid(parts) ? 6 : 0;
  }
  const summary = summaryOf(alert);
    if (summary.description === 'normal-event') return response(0.1, 'normal-event');
    const matched = patterns.find(p => summary.source && summary.timestamp
      && (summary.description === p.condition.description || p.condition.alternativeDescriptions?.includes(summary.description))
      && (p.condition.minimumLevel === 0 || (Number.isInteger(summary.level) && summary.level >= p.condition.minimumLevel)));
    if (matched) return response(summary.description === matched.condition.description
      ? matched.condition.confidence : matched.condition.alternativeConfidence, matched.name);
    try {
      const confidence = await askJev(summary);
      if (!Number.isFinite(confidence) || confidence < 0 || confidence > 1) throw new Error('Invalid confidence');
      return response(confidence, 'ambiguous-failures');
    } catch {
      return response(0.5, 'ambiguous-failures');
    }

}
