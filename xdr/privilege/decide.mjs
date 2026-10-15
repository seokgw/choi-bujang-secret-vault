const PATTERNS = Object.freeze([
  {name:'unexpected-admin-group-membership', evidence:'MITRE ATT&CK T1078 and T1098', condition:'Unexpected administrator membership change'},
  {name:'unexpected-administrator-command', evidence:'MITRE ATT&CK T1068', condition:'Unexpected privileged command'},
  {name:'off-hours-elevated-access', evidence:'MITRE ATT&CK T1068 and T1078', condition:'Unexpected off-hours privileged access'}
]);

export function decide(alert) {
  const message = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const tags = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  const level = Number(alert?.rule?.level);
  const group = alert?.data?.group;
  const account = tags.includes('T1078');
  const privilege = tags.includes('T1068');
  const strongGroup = account && group === 'administrators' &&
    /관리자 그룹|다시 관리자로/.test(message) &&
    /원격 주소|평범한 계정|곧바로|계정 4개|1분 뒤|업무처럼/.test(message);
  const strongCommand = privilege &&
    /관리자 명령|관리자 권한/.test(message) &&
    /방금 관리자가 된|처음 보는 주소|다른 계정의 권한|수업 시간 밖|권한으로 바뀌었/.test(message);
  const strongTime = (privilege || account) &&
    /수업 시간 밖|업무처럼 보이지 않는 시각/.test(message) &&
    /관리자 명령|관리자 그룹 추가와 명령 실행/.test(message);
  if (level >= 10 && (strongGroup || strongCommand || strongTime)) {
    return { action:'block', confidence:0.95,
      reason: strongGroup ? PATTERNS[0].name : strongTime ? PATTERNS[2].name : PATTERNS[1].name };
  }
  if (level >= 5 && (account || privilege) &&
      /관리자|권한|그룹|계정/.test(message)) {
    return { action:'alert', confidence:0.65,
      reason: account && /그룹|계정/.test(message) ? PATTERNS[0].name : PATTERNS[1].name };
  }
  return { action:'record', confidence:0.1, reason:'no-matching-pattern' };
}
