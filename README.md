# BYTE BACK 자료실 · 5단계 저장점

## 보너스 xdr-01 저장점

2026-10-08 최종 저장점: 임시 경로의 공식 npm 도구로 `npm run xdr:run -- brute-force`를 다시 실행해 result.json을 갱신했다. counts는 block 10 / alert 6 / record 12이며 정상 XDR block은 0건이다. 실제 Jev 키는 미설정이므로 애매한 6건은 오류 대체 alert이며 실제 AI 추론 성공으로 표시하지 않는다. `decide`는 원본 경보와 readAlerts의 추출 결과를 모두 처리한다. 정상 이벤트는 record, 명확한 공격은 block이 기대 결과다. 공개 화면에서는 집계 JSON 확인을 누른다. 기존 판정기·원본 경보·설정은 이번 단계에서 변경하지 않았다.

현재 보조 판단은 실제 TypeSafe Jev API 연동이다. 서버 환경의 `TYPESAFE_API_KEY`만 사용하며 키를 코드·브라우저·로그에 넣지 않는다. 키 미설정·타임아웃·오류·잘못된 확신도는 alert다. 실제 추론 성공은 키 설정 후 별도 확인해야 하며 미설정 실행을 AI 성공으로 보고하지 않는다.

2026-10-08 자료실 API 차단 연결: `api/notes.js`는 인증으로 검증한 identity에 대해 `src/vault-xdr.mjs`를 호출한다. 목록·상세의 모든 메서드에서 유효한 사용자 연결 block 규칙은 DB 접근 전에 403으로 거부하며 기존 인증·Origin·소유권 검사는 유지한다. 서버 전용 `VAULT_XDR_DENY_RULES_JSON` 설정을 읽고 없거나 잘못되면 기존 정책으로 처리한다. 규칙에는 발급 시각, 최대 15분 만료, 근거 alertId, 패턴, confidence, 발급자와 검증된 사용자 ID의 SHA-256 가명 연결이 필수다. 요청 본문·IP·가상 계정 이름으로 사용자 연결을 추정하지 않는다. `createVaultDenyRules(decisions, bindings)`는 서버에서 확인한 일대일 경보-사용자 연결을 받아 block 후보만 생성한다. 실제 사용자 ID·연결 자료는 Git/로그/공개 화면에 넣지 않고 운영자가 공식 서버 설정 화면에서 규칙을 등록한다. 실제 연결 정보가 없어 운영 대상 등록은 보류하며 활성 차단 성공으로 표시하지 않는다.

실행: `node --test test/vault-xdr.test.mjs test/r5.test.mjs test/package-starter.test.mjs test/xdr-policy.test.mjs`. 27건 통과. 실제 notes 핸들러의 가상 인증·DB를 사용해 28경보를 재생한 결과 차단 후보 10건 403, 애매한 6건과 정상 12건 200이며 만료·다른 사용자·동일 IP·본문 위조·누락된 연결도 검증했다. 이는 배포에서 실제 사용자로 실행한 시험과 구분한다. 자료실 화면에서 정상 로그인 후 자기 자료 목록을 열면 기존 동작이 유지되어야 하며, 운영자가 유효한 차단 규칙을 등록한 대상의 API 요청은 403이어야 한다. 별도 `src/decider.mjs`의 기본 거부는 이 자료실 경로와 분리돼 있다.

2026-10-08 최종 판정 수정: `decide(alert)`는 먼저 로컬 패턴을 비교하고 애매한 경보만 `jev.mjs`를 통해 실제 TypeSafe Jev에 질의한다. 유효한 확신도는 그대로 반환하며 0.85 이상 block, 0.5 이상 alert, 그 아래 record다. 오류·미응답·범위 밖 응답은 confidence 0.5의 alert다. reason은 한 줄 패턴 이름이다. 재실행 명령은 `node scripts/xdr-run.mjs brute-force`이며 공개 화면에서 집계 JSON 확인을 누른다. 명확한 공격 10건 block, 애매한 6건 alert, 정상 12건 record가 로컬 기대 결과다. 실제 서비스 AI 호출·심판 통과·운영 ZTNA 연동을 의미하지 않는다.

최신 X01 수정 저장점: block 10 / alert 6 / record 12, 정상 XDR block 0건. 이전 로컬 판단 정책 실행 당시 근거가 명확한 공격은 로컬에서 block, 남은 애매한 6건은 근거 부족으로 alert임을 확인했다. XDR 경계 시험·기존 인증/패키징·주체 연결 규칙 시험 23건·로컬 빌드가 통과했다. 아래 6/10/12와 AI 호출 기록은 이전 점검 기록이다. 심판 재통과 및 운영 ZTNA 정상 통과는 아직 확인되지 않았다.

2026-10-08 X01_CLEAR_NOT_BLOCKED 수정: 반복 실패 정규화가 시간 명시만 요구해 bf-05·07·08·10을 놓쳤다. 기존 반복 실패 패턴에서 수준 10 이상·대량 반복의 명시적 근거(비밀번호 변형/연속 실패/성공 없음) 또는 같은 주소의 일정 간격 다중 계정 실패를 인식하도록 보완했다. 시간/동일 비밀번호/사용자 연결을 추정하지 않는다. 장시간·낮은 수준·임계 미만 경계와 정상 경보는 차단하지 않는 로컬 시험을 추가했다. 이 수정은 운영 ZTNA 기본 규칙이나 원본 경보를 바꾸지 않는다. 심판 재통과 여부는 재제출 후 확인해야 한다.

2026-10-08 alert 재검토: bf-11·12·17은 낮은 경보 수준(7 이하), 로그인 실패 6건 이하 뒤 성공, 다중 계정/스프레이 근거 없음 조건으로 record에 옮긴다. 성공만으로 대량 실패·스프레이를 정상 처리하지 않는다. 나머지 근거 부족 경보는 alert로 유지한다. 예상 집계는 block 6 / alert 10 / record 12이며 아래의 6/13/9는 이전 실행 기록이다. 이는 보수적인 기록 정책으로 실제 계정의 정상 여부를 증명하는 것은 아니다.

### 기존 판정기에 XDR 규칙 추가

`src/decider.mjs`의 기존 decide(request)가 `src/xdr-policy.mjs`를 통해 서버 전용 `xdr/brute-force/active-rules.json`을 읽는다. 기존 starter.deny와 응답 5항목·이유 코드를 보존하며, 유효한 차단 후보가 일치하면 ruleIds에 xdr.brute-force.deny를 추가한다. 운영 등록부를 확인하지 못해 새 reasonCode는 도입하지 않았다. RULE_IDS의 새 항목은 실제 구현한 후보 검사 분기다.

규칙은 action=block, confidence 0.85~1, 두 로컬 패턴 중 하나, 근거 alertId, issuedAt/expiresAt(최대 15분), 운영 엔진이 검증한 classId/projectId/subjectId/deviceId를 요구한다. 네 식별 값 모두 현재 요청과 일치해야 적용된다. 같은 IP라는 이유로 다른 사용자를 차단하지 않는다. 신원 연결 정보가 없는 가상 경보를 자동 활성화하지 않으며 active-rules는 현재 빈 배열이다. 이 파일에 실제 개인정보나 자격증명을 넣거나 공개 정적 빌드에 복사하지 않는다.

실행: `node --test test/xdr-policy.test.mjs`. 등록부 형식·만료·다른 주체·alert/record 제외·기존 decide의 실제 파일 읽기를 격리된 가상 규칙으로 검증한다. 공개 화면에서는 집계 JSON 확인을 눌러 XDR 정상 오탐 0을 확인한다. 정상 기본 정책은 기존 deny이며 운영 정상 통과나 실접속 차단 완료를 의미하지 않는다. 실제 활성화에는 운영 엔진의 검증된 주체 연결 및 판정기 등록이 여전히 필요하다.

### TypeSafe Jev 연결 시험

공식 API `https://api.typesafe.ai/v1/systemone`에 연결하는 서버용 어댑터를 추가했다. 계약 출처는 https://docs.typesafe.ai/api 이다. 현재 `jev.mjs`는 `TYPESAFE_API_KEY`가 서버에 설정된 경우 TypeSafe 어댑터를 사용하며, 키가 없으면 alert로 처리한다. 로컬 점수 대체는 제거했다. TypeSafe 공식 콘솔 https://console.typesafe.ai 에서 발급한 키는 실행 환경의 비밀 환경변수 입력란에만 설정하고 채팅·명령 문자열·Git에 넣지 않는다. 브라우저에서는 호출하지 않는다.

외부 전송은 정규화된 신호·규칙 수준만 포함한다. 출발 주소·계정·경보 원문·인증값은 제외한다. `noul`의 0~1 값은 공격일 확률이며 Choice/Score의 별도 confidence와 다르다. 현재 decide는 유효한 보조 판단 점수를 변경하지 않고 0.85 이상 block, 0.5 이상 alert, 그 아래 record로 반환한다. 900ms HTTP 시간 제한·잘못된 응답·인증 오류는 alert로 처리한다. 모델은 공식 별칭 jev-latest를 사용하며 실제 검증한 고정 버전은 없다.

실행: `node xdr/brute-force/jev-test.mjs`로 모의 HTTP 계약/오류/비노출을 검증하고 `npm run xdr:run -- brute-force`로 실제 환경을 재실행한다. 2026-10-07 공식 endpoint에 비밀값 없는 가상 요청을 직접 전송한 결과 HTTP 403 및 인증 오류 표시를 확인했다. 현재 키는 미설정이며 실제 Jev 추론 성공은 미확인이다. 모의 계약 시험과 기존 분류/오류/만료 시험은 통과했다. 이번 연결 변경은 아직 커밋·배포하지 않았다.

공개 결과 화면 경로는 `/xdr/brute-force/`다. 빌드는 최신 result.json에서 counts와 정상 XDR 오탐 수만 골라 공개 JSON을 생성한다. 원본 경보·주소·계정·로그는 정적 배포에 복사하지 않는다. 기존 로그인 자료실은 `/`에서 유지한다. 이번 배포는 결과 공개이며 운영 ZTNA 연결 완료를 의미하지 않는다.

`npm run xdr:run -- brute-force`로 원본 가상 Wazuh 경보 28건을 재실행하고 `xdr/brute-force/result.json`을 확인한다. `node xdr/brute-force/verify.mjs`는 추출 건수·패턴 근거·분류·Jev 오류/시간 초과·거부 후보 만료를 검증한다. 경보 설명은 알려진 신호 요약으로 정규화하며 원문/인증정보를 출력하지 않는다. `xdr/alerts.log`는 block/alert를 JSON 한 줄씩 append한다.

MITRE T1110.001·T1110.003의 두 신호만 사용한다. 이 fixture에서는 시간 범위나 동일 비밀번호 근거가 부족한 bf-05·07·08·10을 보수적으로 alert로 처리한다. 결과는 block 6 / alert 13 / record 9이며 정상 XDR block은 0이다. Jev 공식 연결은 미설정이고 애매한 경보는 alert로 떨어진다. 신뢰된 호스트는 `jev.mjs`의 configureJev로 확신도 제공 함수를 연결할 수 있다. Jev만으로 애매한 경보를 block으로 승격하지 않는다.

기존 `src/decider.mjs`와 RULE_IDS는 보존했다. 별도 `ztna.mjs`는 block 후보만 경보 시각부터 15분 만료·경보 ID를 갖는 거부 규칙으로 만들고, 검증된 출발 주소를 받는 경우 기존 판정기 앞에서 비교한다. fixture 재생은 과거 경보 시각으로 검증하며 현재 접속을 차단하지 않는다. 운영 계약에 출발 IP 연결이 없어 실제 엔진 연동은 미완료다. 기존 starter.deny가 모든 요청을 거부하므로 정상 ZTNA 요청 통과는 실패이며 제출 가능으로 표시할 수 없다. 배포 화면에 XDR 결과를 게시하지 않았다.

설정 대조: step 5·기존 배포 주소·Auth issuer/audience/JWKS·메모/세션 허용 경로·originalApiUrl은 기존 5단계 구현을 유지한다. judgeIssuer를 변경하지 않았다. 화면에서는 공개 저장소의 `xdr/brute-force/result.json`을 눌러 counts를 확인한다. 정상 경보는 record, 두 신호가 명확한 공격은 block이어야 한다. 이는 로컬 가상 경보 검증이며 운영 심판 판정이 아니다.

2026-10-07 직접 검증: 원본/기존 판정기/설정 diff 0, 추출 28/28, 두 패턴 근거 존재, 정상 XDR 오탐 0, 후보 6건의 만료/경보 ID 존재, 로그 줄별 JSON 파싱 성공. 전체 계약 형식의 가상 요청으로 기존 판정기 함수를 직접 호출했으며 정상 9건도 starter.deny로 거부됐다. 운영 요청 차단 성공을 의미하지 않는다. Jev 미설정/오류/잘못된 확신도/시간 초과 검증과 기존 인증·패키징 시험 19건이 통과했다. 현재 실행 셸에 npm이 없어 npm 명령 자체는 실패했고 같은 실행기를 `node scripts/xdr-run.mjs brute-force`로 실행했다. 최신 추적 파일과 이번 추가 파일의 비밀값 패턴 및 기존 메모 본문 검색은 0건이며 Git 과거 이력의 완전한 비밀값 부재를 증명하지 않는다. 공개 배포 루트는 HTTP 200, XDR 결과 경로는 404다. GitHub 저장소는 PUBLIC이며 이번 저장점의 원격 반영은 아직 하지 않았다. 제출 상태는 제출 전 수정 필요다.

현재 구조: **브라우저 → Vercel 인증 API 서버 함수 → Supabase Auth / vault_api.training_notes**.
기존 가상 메모는 4건이며 사용자가 지정한 A 대상은 ID 1·2·3이다. ID 4는 삭제하거나 소유자를 바꾸지 않는다. 어두운 화면 디자인과 텍스트 카드 렌더링을 유지하면서 이메일/비밀번호 로그인, 로그아웃, 메모 추가·수정·삭제를 구현했다. 비로그인 화면에는 메모가 없고 메모 API는 401 JSON 오류를 반환한다. 기존 정책·탐지 연습과 미구현 서버 뼈대는 유지한다.

## 다시 실행

Node.js 22 이상과 npm을 사용한다. 새 체크아웃에서는 `npm ci`로 의존성을 설치한다.

- `npm run test:r5`: 인증, CRUD, 안전한 오류, 배포 식별 정보와 자기 점검 시험.
- `npm run test:package`: 기존 서버 뼈대와 패키징 안내 시험.
- `npm run build -- --local`: 정적 파일 준비. 서버 함수 실행은 아니다.
- `npm run build`: Vercel 시스템 환경변수를 검증하고 public/aleph.json 생성. 배포 정보가 없으면 실패한다.
- `npm run bundle`: 저장점 커밋 후 artifacts/submission.json 생성. bundle-notes.json에 작업 설명을 작성하며 두 파일은 Git에서 제외된다.

배포 화면에서 이메일/비밀번호를 직접 입력하고 **로그인**을 누른다. A/B 소유자 연결 SQL 적용 후 A 계정이면 선택한 기존 카드 3개와 A가 새로 만든 메모가 보이며 **저장**, 카드의 **수정/삭제**, **로그아웃**을 시험할 수 있다. 삭제 시험은 새로 만든 가상 시험 메모만 대상으로 한다. 시크릿 창에서는 로그인 폼만 보이고 GET /api/notes는 401 JSON이어야 한다. 실제 계정 비밀번호를 코드·명령·채팅에 적지 않는다. 이 화면은 계정 가입 기능을 제공하지 않는다. 계정이 없으면 사용자가 Supabase Auth 공식 화면에서 직접 생성한다.

## 로그인과 서버 API 계약

POST /api/session은 이메일/비밀번호를 Supabase Auth 이메일 로그인에 전달하고, 받은 토큰을 **기존 src/verify-login.mjs**로 검증한다. 검증된 토큰은 Secure·HttpOnly·SameSite=Strict의 __Host-vault-session 쿠키에 저장한다. 토큰을 응답 JSON이나 클라이언트 저장소에 넣지 않는다. GET /api/session은 로그인 상태만 반환한다. DELETE /api/session은 쿠키를 지우고 Supabase 로컬 세션 로그아웃을 요청한다. 이미 발급된 액세스 토큰의 즉시 무효화까지 보장하는 것은 아니다. 자동 갱신은 구현하지 않았으므로 세션 만료 시 다시 로그인한다.

메모 API는 쿠키 또는 Authorization Bearer를 기존 검증기로 확인한다. Supabase 학생 토큰은 getClaims로 확인하고 심판 토큰은 기존 운영 발급자의 ES256 서명 검증을 유지한다. 브라우저의 userId·role·owner_id는 신뢰하지 않는다.

- GET /api/notes: owner_id가 검증된 사용자 ID인 행만 조회하고 id,title,content만 반환.
- GET /api/notes/:id: 본인 행이면 {id,title,content}, 타인/없는 행이면 동일한 404 JSON. GET /api/notes?id=숫자는 기존 notes 배열 응답을 유지.
- POST /api/notes: title/content만 받고 owner_id는 **검증한 사용자 ID**로 서버가 지정. 성공 201.
- PUT/PATCH /api/notes/:id: 제목·content 수정. DELETE 같은 주소: 삭제. 기존 PUT/PATCH/DELETE /api/notes?id=숫자도 제공한다. PUT은 기존 전체 제목/본문 입력 계약을 Supabase PATCH로 전달한다.
- 수정·삭제는 ID와 owner_id를 함께 DB 조건에 넣는 원자적 요청이다. 기존 행은 본인 소유여야 하고 수정 입력에 owner_id를 복사하지 않으므로 새 행의 소유자도 유지된다. 반환 행의 owner_id도 서버에서 다시 검사한다. 소유권 이전 기능은 없다.
- 비로그인 자료 요청: 401, application/json, `{ "error": "unauthorized" }`. HTML·자료·JWT·키·스택을 반환하지 않음.
- 쿠키를 쓰는 변경 요청은 배포 주소의 Origin을 확인한다. 잘못된 입력은 400, 거부는 403, 없는 대상은 404, 내부 실패는 일반 503 JSON.

aleph.config.json은 step 5이며 identityProvider는 aleph-plan-do-see의 Auth 발급자, audience authenticated, 해당 JWKS 주소다. allowedRoutes는 /api/notes의 GET·POST·PUT·PATCH·DELETE, /api/notes/:id의 GET·PUT·PATCH·DELETE, /api/session의 GET·POST·DELETE를 메서드와 함께 기록한다. root 수정·삭제에는 id 쿼리가 필요하다. judgeIssuer와 기존 RULE_IDS는 변경하지 않는다.

## DB와 서버 설정

기존 이전 SQL artifacts/supabase-stage2.sql과 원문 검색 패턴은 사용자 선택에 따라 Git·정적 배포·제출 JSON에서 제외한다. 별도 보관한다. 이미 만들어진 DB에 초기 SQL을 반복 실행하지 않는다. 가상 메모 owner_id uuid에는 auth.users 외래키가 없다. RLS와 owner_id 정책을 유지한다. 4단계 적용 상태에서 anon/PUBLIC 권한은 없고 authenticated에는 네 CRUD 권한이 있다. 5단계 권한 회수 SQL은 이후 사용자 실행 요청으로 실제 적용했다. 적용 후 PUBLIC·anon·authenticated의 직접 테이블 권한은 없으며 service_role CRUD는 유지된다.

3단계 추가 SQL artifacts/supabase-stage3.sql은 기존 4건을 보존하면서 자료실 ID 자동 생성 시퀀스를 만들고 service_role에 이 테이블의 INSERT·UPDATE·DELETE 및 시퀀스 권한을 준다. 다른 기존 테이블은 변경하지 않는다. 실행 결과는 최종 보고와 캡처로 구분해 기록하며 SQL 작성 자체를 DB 실행 성공으로 취급하지 않는다.

Vercel Production의 SUPABASE_URL과 SUPABASE_SECRET_KEY를 서버 환경변수에서만 읽는다. 기존 Secret 설정을 유지하며 키를 브라우저 파일·응답·로그·Git에 넣지 않는다. 자료 조회/편집은 Accept-Profile 및 Content-Profile: vault_api를 사용한다. 서버 API 응답에는 owner_id와 내부 정보를 넣지 않는다.

공유 프로젝트의 Data API는 기존 사용자 승인으로 활성화했고 authenticator의 pgrst.db_schemas=vault_api override로 자료실 스키마만 노출한다. **Reset override를 누르거나 public을 추가하지 않는다.** 기존 다른 테이블 데이터·권한·RLS는 변경하지 않는다. 서버 키는 프로젝트 수준 권한을 가지므로 별도 프로젝트만큼 격리된 것은 아니다.

## 4단계 소유권 SQL과 적용 상태

학습 SQL은 기존 사용자 선택에 따라 artifacts에만 보관하고 Git·정적 배포·제출 JSON에서 제외한다. 실제 비밀번호/JWT/키를 입력하지 않는다. A/B 이메일도 Git이나 출력에 기록하지 않고 SQL Editor의 입력란에만 직접 넣는다.

1. artifacts/supabase-stage4-owners.sql: 이메일로 auth.users의 A/B UUID를 각각 조회한다. ID 1·2·3의 owner_id만 A로 연결하고 B 가상 시험 메모 1건을 추가한다. 기존 4번째 메모와 제목/본문/ID는 보존한다. 계정 누락·동일 계정·잘못된 대상·중복 B 시험 메모면 트랜잭션을 중단한다. 총 예상 메모는 기존 4건+신규 B 1건=5건이다.
2. artifacts/supabase-stage4-owners-check.sql: A/B 조회 일치 여부와 A 대상 3건, B 시험 1건을 확인한다. UUID/이메일/본문을 결과에 출력하지 않는다.
3. artifacts/supabase-stage4-before.sql: role_table_grants와 has_table_privilege의 역할별 SELECT/INSERT/UPDATE/DELETE 및 기존 정책을 조회한다.
4. artifacts/supabase-stage4-rls.sql: 자료실 테이블 권한을 PUBLIC·anon·authenticated에서 회수하고 authenticated에 네 CRUD 권한만 부여한다. RLS를 활성화하며 SELECT/DELETE는 USING(auth.uid()=owner_id), INSERT는 WITH CHECK, UPDATE는 USING과 WITH CHECK를 모두 둔다. 기존 정책이 있으면 무작정 DROP하지 않고 검토를 요구하며 중단한다. 다른 테이블은 변경하지 않는다. custom schema USAGE와 해당 정수 ID 시퀀스 USAGE는 삽입에 필요한 최소 보조 권한이다.
5. artifacts/supabase-stage4-after.sql / supabase-stage4-policies.sql: 같은 두 방법으로 적용 후 권한과 USING/WITH CHECK를 확인한다. anon 네 권한은 false, authenticated는 네 권한만 true여야 한다.

2026-10-06 읽기 전용 실제 조회에서 기존 메모 4건의 ID 1·2·3·4 및 초기 원본 일치를 확인했다. 기존 정책은 0개, role_table_grants의 PUBLIC/anon/authenticated 명시적 권한은 없었고 has_table_privilege에서도 anon/authenticated의 네 권한이 모두 false였다. 이후 사용자 명시적 SQL 실행 요청에 따라 RLS/최소 권한 SQL 실행이 성공했다. 적용 후 has_table_privilege에서 anon 네 권한 false, authenticated 네 권한 true를 확인했고 role_table_grants에서는 authenticated에 DELETE/INSERT/SELECT/UPDATE 네 권한만 나타났다. 네 정책의 auth.uid()=owner_id 조건 및 UPDATE의 USING/WITH CHECK를 실제 재조회했다. 다른 테이블은 변경하지 않았다.

**2026-10-06 사용자 B 계정 생성 후 소유자 연결 SQL 실행이 성공했다.** 기존 계정을 A, 새 계정을 B로 식별하고 이메일로 auth.users를 조회했다. 재조회 결과 서로 다른 계정임을 확인했고 ID 1·2·3의 A 소유자 일치 3건, B 시험 메모 1건을 확인했다. 전체 메모는 5건이며 ID 4의 원본 내용과 가상 소유자도 보존됐다. 실제 이메일·UUID·비밀번호를 파일·Git·제출 묶음에 기록하지 않았다. 이 기록 당시 실제 A/B 시험은 미확인이었다. 이후 화면 CRUD 결과는 아래 후속 기록을 따른다. 상세 API 및 타인 ID 직접 요청 시험은 미확인이다.

## 현재 보안 한계

API가 이제 로그인 여부와 서버에서 검증한 ID에 따른 owner_id를 함께 검사한다. URL/쿼리/본문의 owner_id·userId·role은 권한에 사용하지 않는다. POST 소유자는 서버 지정이며 PUT/PATCH 소유자 변경 입력은 무시하고 DELETE도 자기 행만 대상으로 한다. A/B가 자기 자료만 접근하도록 코드가 바뀌었으며 실제 화면 목록 분리·CRUD는 아래 후속 기록에서 확인했고, 타인 ID 직접 API 요청은 아직 미확인이다.

서버 전용 service_role은 RLS를 우회하므로 API의 소유자 검사도 반드시 유지해야 한다. DB 정책은 authenticated 직접 요청에 같은 규칙을 적용한다. [Supabase RLS 공식 설명](https://supabase.com/docs/guides/database/postgres/row-level-security)을 참고한다. 실제 DB 역할별 동작과 외부 A/B 요청 검증을 로컬 모의 시험으로 대신하지 않는다. 서버 키의 프로젝트 수준 권한, 토큰 즉시 무효화·자동 갱신 미구현, 과거 노출 이력의 한계는 남아 있다.

루트/public의 data.json을 제거한 2단계 구조를 유지한다. 빌드는 오래된 public/data.json도 제거하고 다시 생성하지 않는다. /data.json의 의도한 결과는 404다. Vercel build/output 설정과 첫 화면 X-Content-Type-Options: nosniff를 유지한다. 배포 식별 정보 검증을 유지하며 5단계 public/aleph.json도 자동 생성한다.

## 가상 메모 노출 검색 절차

**A. 현재 최신 상태:** GitHub 최신 파일, 현재 Vercel 정적 배포 파일, 현재 /data.json을 각각 확인한다. 로그인 API 응답은 정적 검색과 별도로 기록한다.

원문을 README에 복사하지 않는다. 로컬 artifacts/note-search-patterns.json에 기존 제목과 본문 8개를 보관하며 Git·제출 JSON에서 제외한다. 새 체크아웃에서는 초기 커밋에서만 패턴을 추출한다:

```powershell
$oldData = git show ff9b6cb607aa610fe892b5d685c479129f3c5c75:data.json | ConvertFrom-Json
$patterns = @($oldData.notes | ForEach-Object { $_.title; $_.content })
foreach ($file in (git ls-files)) {
  if (Test-Path -LiteralPath $file) {
    $text = Get-Content -LiteralPath $file -Raw
    if (@($patterns | Where-Object { $text.Contains($_) }).Count) { Write-Output $file }
  }
}
```

출력이 없으면 로컬 최신 추적 파일의 원문 검색 결과는 0건이다. GitHub 최신 파일은 push된 커밋 SHA를 대조하고 최신 저장소를 별도 다운로드/체크아웃하여 같은 검색을 실행한다. 로컬 검사를 GitHub 검사로 대신 쓰지 않는다. 로컬 SQL과 패턴은 원문이 있으므로 Git 또는 public에 옮기지 않는다.

현재 배포는 개발자 도구 Network를 열고 `/`를 새로고침한다. HTML·JS·CSS 등 정적 응답과 현재 public 배포 파일을 저장해 위 패턴으로 검색한다. 실제 /aleph.json의 커밋과 저장점을 대조한다. /api/notes 응답은 비로그인 거부와 로그인 조회 확인으로 따로 기록한다.

주소창에서 https://choi-bujang-secret-vault-vert.vercel.app/data.json 을 직접 열고 Network의 HTTP 404를 확인한다. 파일이 있으면 메모 0건이고 기존 제목·본문이 없어야 한다. /aleph.json 접근과 `/`의 nosniff 헤더도 확인한다. 비로그인 창에서 /api/notes를 직접 열고 요청 여부를 별도로 캡처한다. 키나 환경변수 값은 캡처하지 않는다.

기록 형식: `시각(KST) | 대상 URL/저장소 | 커밋 SHA/배포 ID | 최신/과거 | 검사 경로 | 검색 건수/HTTP 상태 | 통과/실패/미확인 | 캡처 경로`. 원문 대신 경로와 건수만 적는다.

**B. 과거 공개 이력:** 옛 공개 GitHub 커밋과 옛 Vercel 배포는 별개다. 초기 공개 커밋에는 메모가 남아 있다. 최신 파일에서 없어져도 과거 노출이 완전히 해소된 것이 아니다. 이번 작업은 Git 이력을 재작성하거나 옛 배포를 삭제하지 않는다. 옛 배포 URL·커밋을 따로 목록화하고 확인하지 않은 접근 차단·삭제를 완료로 적지 않는다.

## 이번 저장점 검증과 사용자 직접 확인

실행 명령은 위 다시 실행 절을 따른다. 로컬 A/B 시험은 모의 DB와 실행 중 생성한 시험 토큰을 사용하며 실제 계정 검증이 아니다. 실제 실행한 테스트/빌드·배포 결과는 최종 보고/제출 묶음에 기록한다. 기존 decider/detect 연습의 미구현 항목은 이번 단계에서 수정하지 않는다.

사용자는 다음을 직접 캡처한다:

- A 기존 ID 1·2·3의 owner_id가 이메일로 조회한 A UUID인지, B 시험 1건이 B UUID인지. ID 4 보존 여부.
- A와 B 각각 자기 목록·한 건 조회·추가·수정·삭제 가능 여부.
- A의 B 행 접근/수정/삭제 및 B의 A 행 접근/수정/삭제가 자료 없는 404로 거부되는지.
- POST/PUT/PATCH의 owner_id 변경 시도가 무시되며 자기 소유가 유지되는지.
- 5단계 SQL 적용 후 PUBLIC 직접 권한 없음, anon/authenticated 테이블 네 CRUD 권한 모두 false. 적용 전후 결과를 구분한다.
- 네 RLS 정책의 USING/WITH CHECK가 auth.uid()=owner_id 규칙인지 및 5단계 적용 후 일반 역할의 DB 직접 요청이 거부되는지.
- 비로그인 메모 요청 401 JSON, /data.json 404, /aleph.json의 5단계 저장점과 첫 화면 nosniff.
- 서버 키 비노출과 최신 GitHub/정적 배포의 기존 메모 본문 부재.

SQL 연결 확인과 실제 A/B 계정 요청 시험을 구분하며 심판 판정을 추측하지 않는다. 제목처럼 짧은 일반 단어 검색은 기존 XDR fixture 설명에서도 일치할 수 있으므로 전체 본문 일치와 구분하며 기존 연습 자료를 보존한다. [AGENTS.md](AGENTS.md)의 저장점 규칙을 따른다.

이번 저장점의 로컬 실행 결과는 최종 보고와 제출 묶음에 기록한다. 실제 A/B 화면 시험 및 5단계 권한 회수 SQL은 아래 후속 기록을 따른다.

## 5단계 서버 경로 집중과 권한 회수 제안

브라우저 메모 DB 직접 호출 점검 결과: **없음**. 이 점검 때문에 화면/API 파일을 수정하지 않았다. 모든 메모 요청은 /api/notes 또는 /api/notes/:id 서버 함수로 간다. 기존 Auth 역시 /api/session 서버 함수를 거치며 로그인·로그아웃·세션 확인 UI를 보존한다. 최신 과제 24항의 공개 키 제거 기준을 우선한다. 브라우저 공식 Supabase SDK 직접 Auth 방식으로 되돌리지 않는다. 화면에 Supabase URL/key 초기화 값, publishable/anon 키가 없다.

현재 구조: 브라우저 → Vercel 서버 함수/API → 서버 전용 Supabase 설정 → vault_api.training_notes. 기존 src/verify-login.mjs 검증과 owner_id 필터를 그대로 유지한다. 서버는 검증된 사용자 ID만 사용하고 브라우저 userId/role/owner_id를 신뢰하지 않는다. service_role 서버 접근은 일반 역할의 테이블 권한 회수와 별개이며 기존 CRUD 권한과 시퀀스 권한을 유지한다. 실제 A CRUD, B의 A 자료 접근 거부, 비로그인 거부는 사용자 캡처 확인 사항이다. B 자기 자료 CRUD는 허용되는 구조다.

**2026-10-06 사용자 후속 실행 요청으로 DB에 5단계 REVOKE를 적용했다.** 아래 SQL은 실제 사용한 적용 전/적용/적용 후 절차이며 기존 DB에 다시 적용할 필요는 없다. 파일은 기존 선택대로 Git·정적 배포·제출 JSON에서 제외한 artifacts에 보관한다.

1. artifacts/supabase-stage5-before.sql: role_table_grants로 PUBLIC/anon/authenticated의 모든 명시적 권한을 조회하고 has_table_privilege로 anon/authenticated의 네 CRUD 및 service_role의 네 CRUD를 각각 확인한다. PUBLIC은 ACL grantee=0으로 확인한다. 별도 열 권한, RLS 및 기존 정책도 조회한다.
2. artifacts/supabase-stage5-revoke.sql: 아래 한 테이블의 모든 직접 권한만 회수한다. 별도 열 권한이 있으면 먼저 중단한다. 데이터·RLS·owner_id 정책·service_role·다른 테이블은 변경하지 않는다.
3. artifacts/supabase-stage5-after.sql: 같은 조회를 반복한다. anon/authenticated 네 값 모두 false, PUBLIC 명시 권한 0행, role_table_grants 대상 세 역할 0행, 별도 열 권한 0행이 기대값이다. service_role 네 CRUD true 및 RLS/네 정책 유지도 확인한다. 상속 등으로 권한이 남으면 완료로 표시하지 말고 결과를 검토한다.

```sql
REVOKE ALL ON TABLE vault_api.training_notes FROM PUBLIC, anon, authenticated;
```

PUBLIC은 로그인 역할이 아니므로 has_table_privilege('PUBLIC', ...) 대신 ACL을 사용한다. [PostgreSQL 권한 조회 공식 문서](https://www.postgresql.org/docs/current/functions-info.html)를 참고한다. 4단계 authenticated CRUD 부여와 5단계 회수는 서로 다른 적용 상태이며 정책을 삭제하지 않는다.

originalApiUrl: **https://icvjlbkcyrqquoqhabdy.supabase.co/rest/v1/training_notes**. 실제 프로젝트와 확인된 테이블에 맞는 HTTPS 경로이며 query/fragment/자격증명이 없다. 커스텀 스키마는 Accept-Profile: vault_api 및 기존 pgrst.db_schemas=vault_api override를 사용한다. 원본 API의 공개 키 직접 요청 차단 시험은 실행하지 않았다. 사용자는 공식 도구의 비밀 입력란에서만 공개 키를 사용해 원본 GET을 요청하고 본문 없는 거부를 캡처한다. 키·JWT를 URL/채팅/로그에 적지 않는다.

실제 라우트와 allowedRoutes 대조(쿼리는 경로가 아닌 입력):

| 경로 | 실제 허용 메서드 = allowedRoutes |
| --- | --- |
| /api/notes | GET, POST, PUT, PATCH, DELETE |
| /api/notes/:id | GET, PUT, PATCH, DELETE |
| /api/session | GET, POST, DELETE |

/api/notes의 PUT/PATCH/DELETE에는 id 쿼리가 필요하다. 미구현 /api/ai 및 /api/threat-intel은 501 뼈대이므로 허용 목록에 넣지 않는다. 첫 화면 nosniff와 aleph.json 자동 생성 구조를 유지하며 5단계 설정을 빌드/자기 점검이 인식하게 했다.

사용자 직접 확인 기록: A 목록·한 건 조회/추가/수정/삭제, 기존 UI, 브라우저 Network의 메모 요청이 서버 API뿐인지, B의 A 자료 접근 거부, 무로그인 401 JSON, anon/authenticated SELECT 거부 및 INSERT/UPDATE/DELETE false, PUBLIC 권한 없음, 서버 CRUD/로그인/owner_id 검사, originalApiUrl 실제 경로 및 query 부재, 공개 키 원본 요청 차단, 서버 키의 브라우저/응답/로그 비노출을 각각 캡처한다. /aleph.json 저장점 및 첫 화면 nosniff도 확인한다. SQL 적용 후 권한은 실제 조회로 확인했다. 실제 배포의 A/B 계정 검증·공개 키 원본 요청·심판 판정은 아직 확인이 필요하며 로컬 모의 시험으로 대신하지 않는다.

이번 5단계 실제 로컬 실행: test:r5 16건 및 test:package 3건 통과. build -- --local과 모의 Vercel 시스템 메타데이터를 제공한 build 성공; 5단계 aleph.json 생성 및 data.json 부재 확인. 실제 배포 빌드 성공으로 기록하지 않는다. API가 반환한 Allow 메서드와 allowedRoutes 12개가 일치하고 원본 URL 구조 검증도 통과했다. 최신 추적 파일 48개/정적 파일의 기존 본문·비밀값 패턴 및 클라이언트 공개 키/서버 키 참조 검색 0건이다.

2026-10-06 5단계 적용 전 실제 읽기 전용 조회: vault_api.training_notes RLS true, 정책 4개; anon 네 CRUD false, authenticated 및 service_role 네 CRUD true. 이 기록은 적용 전 상태다. 아래 후속 적용 결과와 구분한다.

### 5단계 SQL 후속 실제 적용 결과

2026-10-06 사용자의 SQL 실행 요청으로 vault_api.training_notes의 REVOKE 트랜잭션이 성공했다. 적용 후 has_table_privilege 재조회에서 anon/authenticated의 SELECT·INSERT·UPDATE·DELETE 모두 false, service_role의 네 CRUD는 모두 true였다. information_schema.role_table_grants의 PUBLIC/anon/authenticated 명시적 권한 0건, PUBLIC ACL 0건, 해당 역할의 별도 열 권한 0건을 확인했다. RLS true, 정책 4개, 전체 자료 5건 유지도 재조회했다. 다른 테이블은 적용 SQL의 대상이 아니다.

SQL 적용 직후 배포 읽기 전용 확인에서는 /data.json 404, /api/notes 401, /aleph.json 200이며 아직 4단계 증명이다. HTML·app.js·aleph.json 기존 메모 패턴 일치 0건이다. 당시에는 5단계 커밋을 push/배포하지 않아 배포 완료로 기록하지 않았다. 실제 A/B 화면 CRUD는 아래 후속 기록에서 확인했다. 타인 ID 직접 API 요청과 공개 키를 사용한 원본 REST 요청은 아직 미확인이다.

### A/B 실제 화면 후속 검증

2026-10-06 사용자가 각각 A/B로 직접 로그인한 실제 배포 화면에서 확인했다. A는 기존 자기 카드 3개, B는 기존 자기 카드 1개를 조회했고 B 목록에 A 카드 3개가 없었다. 각각 새 가상 시험 메모를 생성하고 제목·본문 수정 후 그 시험 메모만 삭제했다. 종료 시 A 기존 3개/B 기존 1개는 보존됐다. A 로그아웃 후 자료가 숨겨지고 로그인 폼으로 전환됐다. 실제 계정 정보·키·토큰·메모 본문을 결과 파일이나 제출 JSON에 기록하지 않았다.

화면 목록 분리 확인은 타인 ID 직접 GET/PUT/PATCH/DELETE 거부 검증과 구분한다. 브라우저 도구가 직접 API 주소 열기를 차단해 실제 상세·타인 ID API 시험은 미확인이다. 로컬 타인 접근 거부 모의 시험 결과로 이를 대신하지 않는다. 당시 공개 키 원본 REST 요청과 5단계 배포 확인이 남아 있었다. 배포 후속 확인은 아래 기록을 따른다.

### 5단계 실제 배포 후속 확인

2026-10-06 사용자 배포 요청으로 GitHub main에 push했고 실제 Vercel /aleph.json에서 step 5 및 push한 저장점 커밋 일치를 확인했다. /data.json 404, 비로그인 /api/notes·/api/notes/1·/api/session 401 application/json 및 자료 없는 unauthorized 오류, 첫 화면 nosniff를 재확인했다. 배포 HTML·app.js·aleph.json에서 기존 메모 패턴 0건, app.js의 공개 키/서버 키 참조 0건을 확인했고 GitHub 최신 파일 48개에서도 기존 전체 메모 본문 0건이었다. 과거 공개 커밋/배포 제거를 의미하지 않는다. 타인 ID 직접 API 요청 및 공개 키 원본 REST 요청은 여전히 미확인이다. 실제 A/B 화면 CRUD는 앞 기록처럼 권한 회수 후 수행했으며 최종 배포 후 별도 재시험으로 가장하지 않는다.

5단계 배포 증명 보완: aleph.config.json의 originalApiUrl이 생성된 aleph.json에 빠져 심판 S05_ORIGINAL_URL_MISSING이 발생했다. 생성기에 5단계 원본 HTTPS 주소 출력을 추가하고 누락·query·자격증명 거부 시험 및 bundle의 실제 원본 주소 대조를 보완했다. 설정된 원본 경로에는 키가 없으며 메모/Auth/API 구현은 그대로 유지한다. test:r5 16건과 모의 Vercel 메타데이터 build가 통과했다. 심판 재검증 결과는 별도 확인 사항이다.
