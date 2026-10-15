// Self-contained pattern definitions from xdr/exfiltration/patterns.json.
const PATTERNS = Object.freeze([
  {
    "name": "unfamiliar-destination-bulk-transfer",
    "condition": {
      "signal": "처음 보는 목적지로 큰 파일 또는 다수 자료 전송",
      "scope": "rule.description, rule.mitre, data.dstip, data.bytes",
      "match": "T1041 또는 T1048 표시와 낯선 목적지, 대량·반복 전송 정황이 함께 있음",
      "exclude": "승인된 목적지의 정상 동기화나 단순 조회, 실패 전송은 제외"
    },
    "evidence": "MITRE ATT&CK T1041/T1048: https://attack.mitre.org/techniques/T1041/ ; https://attack.mitre.org/techniques/T1048/"
  },
  {
    "name": "off-hours-compressed-transfer",
    "condition": {
      "signal": "업무 시간 외 압축 파일 외부 전송",
      "scope": "rule.description, rule.mitre, data.bytes",
      "match": "T1048 표시와 비업무 시간 또는 연속된 압축 파일 전송, 낯선 주소 신호가 결합됨",
      "exclude": "압축 파일 생성만 한 경우와 승인된 백업은 제외"
    },
    "evidence": "MITRE ATT&CK T1048: https://attack.mitre.org/techniques/T1048/"
  },
  {
    "name": "repeated-command-channel-transfer",
    "condition": {
      "signal": "명령 통로를 통한 반복·대용량 전송",
      "scope": "rule.description, rule.mitre, data.count, data.bytes",
      "match": "T1041 표시와 큰 파일 반복 전송 또는 자료실 전체 외부 복사 정황이 있음",
      "exclude": "작은 자료 이름만 보이거나 읽기·정상 업무 이벤트는 제외"
    },
    "evidence": "MITRE ATT&CK T1041: https://attack.mitre.org/techniques/T1041/"
  }
]);

export function decide(alert) {
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const mitre = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  const level = Number(alert?.rule?.level);
  const bytes = Number(alert?.data?.bytes);
  const transferred = Number.isFinite(bytes) && bytes > 0;
  const volume = transferred && bytes >= 50_000_000;
  const t1041 = mitre.includes('T1041');
  const t1048 = mitre.includes('T1048');
  const knownTechnique = t1041 || t1048;
  const unusualDestination = /처음 보는|평소에 쓰지 않던 포트|외부 주소|두 곳/.test(description);
  const bulkOrRepeated = /자료 200건|대용량 전송이 8번|연속 전송|메모 묶음|15번|자료실 전체|반복 전송|같은 압축 파일/.test(description);
  const commandChannel = t1041 && /명령 통로로 큰 파일|대용량 전송이 8번|자료실 전체/.test(description);
  const compressed = t1048 && /압축 파일/.test(description) && /나갔|올라갔/.test(description);
  const outsideHours = /수업 시간 밖|업무 시간 밖/.test(description);
  const strong = knownTechnique && level >= 10 && volume && (
    (unusualDestination && (bulkOrRepeated || compressed || outsideHours)) ||
    (commandChannel && (bulkOrRepeated || unusualDestination)) ||
    (outsideHours && /전송이 15번/.test(description))
  );
  if (strong) {
    const pattern = commandChannel ? PATTERNS[2] : compressed && (outsideHours || /연속|두 곳/.test(description))
      ? PATTERNS[1] : PATTERNS[0];
    return { action: 'block', confidence: 0.95, reason: pattern.name };
  }
  // A suspicious signal alone must never block legitimate traffic.
  if (knownTechnique && Number.isFinite(level) && level >= 5) {
    const pattern = t1041 && /명령 통로/.test(description) ? PATTERNS[2]
      : t1048 && /압축 파일/.test(description) ? PATTERNS[1] : PATTERNS[0];
    return { action: 'alert', confidence: 0.65, reason: pattern.name };
  }
  return { action: 'record', confidence: 0.1, reason: 'no-matching-pattern' };
}
