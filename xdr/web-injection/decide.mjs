// Standalone counterpart of the three patterns in patterns.json.
// No request URL, account, address, description or credential is sent to Jev.
export async function decide(alert) {
  const respond = (confidence, reason) => ({
    action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
    confidence, reason,
  });
  const raw = alert?.rule?.description ?? alert?.description;
  const text = typeof raw === 'string' ? raw : '';
  const numeric = value => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
    ? value : typeof value === 'string' && /^\d{1,7}$/.test(value) ? Number(value) : null;
  const level = numeric(alert?.rule?.level ?? alert?.level);
  const countMatch = text.match(/(\d+)\s*(?:번|회|건)/);
  const count = countMatch ? Number(countMatch[1]) : numeric(alert?.data?.count);
  const repeated = count !== null && count >= 2
    && !/반복(?:은)?\s*없|반복되지|반복하지/.test(text);
  // Match the documented request signals, not individual SQL words or severity.
  const patterns = [
    { name: 'sql-injection', signal: /SQL\s*(?:구문|표식)|데이터베이스 조회를 이어 붙|\bunion\s+(?:all\s+)?select\b|\bor\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i },
    { name: 'script-tag-injection', signal: /<\s*script\b|스크립트\s*(?:삽입 표기|표식)/i },
    { name: 'repeated-path-traversal', signal: /\.\.\/|경로.*거슬러 올라|경로 이탈 표기/i },
  ];
  const matched = patterns.find(pattern => pattern.signal.test(text));
  if (matched && repeated) return respond(0.95, matched.name);
  // Explicit ordinary activity only. A suspicious attempt followed by a normal
  // request remains ambiguous; low severity alone is not normal evidence.
  const suspicious = /SQL|select|스크립트|script|주입|따옴표|구분 문자|구분자|경로|이상한|공격|평소보다|\.\.\//i.test(text);
  if (text && text !== '[REDACTED]' && !suspicious
      && /조회했습니다|화면이 열렸습니다|새로고침했습니다/.test(text)) {
    return respond(0.1, 'normal-event');
  }
  const reason = matched?.name ?? 'unmatched-web-injection';
  try {
    const apiKey = typeof process !== 'undefined' ? process.env?.TYPESAFE_API_KEY : undefined;
    if (!apiKey) throw new Error('Jev unavailable');
    const response = await fetch('https://api.typesafe.ai/v1/systemone', {
      method: 'POST', redirect: 'error', signal: AbortSignal.timeout(900),
      headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'jev-latest',
        state: { pattern: matched?.name ?? null, repeated, count, ruleLevel: level,
          context: 'Web injection evidence is inconclusive. No event text or request contents provided. Missing evidence must not be assumed.' },
        questions: { web_injection: {
          type: 'noul', instructions: 'Does the supplied evidence establish a malicious web injection attempt?',
          criteria: { true: 'Established SQL injection, script tag injection or repeated directory traversal.',
            false: 'Ordinary words, insufficient evidence or ambiguous request syntax. Severity alone does not establish an attack.' },
        } },
      }),
    });
    if (!response.ok) throw new Error('Jev request failed');
    const answer = (await response.json())?.answers?.web_injection;
    if (answer?.type !== 'noul' || !Number.isFinite(answer.noul) || answer.noul < 0 || answer.noul > 1) {
      throw new Error('Invalid Jev confidence');
    }
    return respond(answer.noul, reason);
  } catch {
    return respond(0.5, reason);
  }
}
