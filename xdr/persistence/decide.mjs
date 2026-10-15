const PATTERNS = Object.freeze([
  {name:'unsigned-new-service', mitre:'T1543'},
  {name:'unfamiliar-scheduled-task', mitre:'T1053'},
  {name:'unfamiliar-startup-folder', mitre:'T1547.001'}
]);

export function decide(alert) {
  const text = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const tags = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  const level = alert?.rule?.level;
  const path = typeof alert?.data?.path === 'string' ? alert.data.path : '';
  const service = tags.includes('T1543');
  const task = tags.includes('T1053');
  const temp = /[\\/]Temp[\\/]/i.test(path);
  const startup = /[\\/]Startup[\\/]/i.test(path);
  const strongService = service && (
    (/서명 없는 새 서비스/.test(text) && temp) ||
    /서명 없는 서비스 등록이 연속/.test(text) ||
    (/서비스 실행 파일이 바뀌었고 서명이 없습니다/.test(text) && temp) ||
    (/목록에 없는 서비스가 다시 켜도/.test(text) && temp)
  );
  const strongTask = task && temp && (
    /처음 보는 예약 작업|예약 작업 이름이 임의 문자열|시작 프로그램과 예약 작업이 같은 임시 파일/.test(text)
  );
  const strongStartup = service && (
    (startup && /시작 폴더에 평소 목록에 없는 프로그램/.test(text)) ||
    (task && temp && /시작 프로그램과 예약 작업이 같은 임시 파일/.test(text))
  );
  if (level >= 10 && (strongService || strongTask || strongStartup)) {
    return { action:'block', confidence:0.95,
      reason: strongService ? PATTERNS[0].name : strongTask ? PATTERNS[1].name : PATTERNS[2].name };
  }
  const normal = /평소 시각에 그대로|기존 수업 도구 서비스가 서명된|목록을 읽기만|정의 업데이트가 평소|기존 예약 작업이 수업 자료|로그인했습니다|로그아웃했습니다|자료실 화면이 열렸습니다/.test(text);
  if (!normal && level >= 5 && (service || task || /시작 폴더|시작 항목|예약 작업|서비스|임시 폴더/.test(text))) {
    return { action:'alert', confidence:0.65,
      reason: task ? PATTERNS[1].name : /시작 폴더|시작 항목/.test(text) ? PATTERNS[2].name : PATTERNS[0].name };
  }
  return { action:'record', confidence:0.1, reason:'no-matching-pattern' };
}
