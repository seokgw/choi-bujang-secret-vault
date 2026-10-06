# BYTE BACK 자료실 · 3단계 저장점

현재 구조: **브라우저 → Vercel 인증 API 서버 함수 → Supabase Auth / vault_api.training_notes**.
기존 가상 메모는 4건이다. 어두운 화면 디자인과 텍스트 카드 렌더링을 유지하면서 이메일/비밀번호 로그인, 로그아웃, 메모 추가·수정·삭제를 구현했다. 비로그인 화면에는 메모가 없고 메모 API는 401 JSON 오류를 반환한다. 기존 정책·탐지 연습과 미구현 서버 뼈대는 유지한다.

## 다시 실행

Node.js 22 이상과 npm을 사용한다. 새 체크아웃에서는 `npm ci`로 의존성을 설치한다.

- `npm run test:r5`: 인증, CRUD, 안전한 오류, 배포 식별 정보와 자기 점검 시험.
- `npm run test:package`: 기존 서버 뼈대와 패키징 안내 시험.
- `npm run build -- --local`: 정적 파일 준비. 서버 함수 실행은 아니다.
- `npm run build`: Vercel 시스템 환경변수를 검증하고 public/aleph.json 생성. 배포 정보가 없으면 실패한다.
- `npm run bundle`: 저장점 커밋 후 artifacts/submission.json 생성. bundle-notes.json에 작업 설명을 작성하며 두 파일은 Git에서 제외된다.

배포 화면에서 이메일/비밀번호를 직접 입력하고 **로그인**을 누른다. 정상 A 계정이면 기존 카드 4개가 보이며 **저장**, 카드의 **수정/삭제**, **로그아웃**을 시험할 수 있다. 삭제 시험은 새로 만든 가상 시험 메모만 대상으로 한다. 시크릿 창에서는 로그인 폼만 보이고 GET /api/notes는 401 JSON이어야 한다. 실제 계정 비밀번호를 코드·명령·채팅에 적지 않는다. 이 화면은 계정 가입 기능을 제공하지 않는다. 계정이 없으면 사용자가 Supabase Auth 공식 화면에서 직접 생성한다.

## 로그인과 서버 API 계약

POST /api/session은 이메일/비밀번호를 Supabase Auth 이메일 로그인에 전달하고, 받은 토큰을 **기존 src/verify-login.mjs**로 검증한다. 검증된 토큰은 Secure·HttpOnly·SameSite=Strict의 __Host-vault-session 쿠키에 저장한다. 토큰을 응답 JSON이나 클라이언트 저장소에 넣지 않는다. GET /api/session은 로그인 상태만 반환한다. DELETE /api/session은 쿠키를 지우고 Supabase 로컬 세션 로그아웃을 요청한다. 이미 발급된 액세스 토큰의 즉시 무효화까지 보장하는 것은 아니다. 자동 갱신은 구현하지 않았으므로 세션 만료 시 다시 로그인한다.

메모 API는 쿠키 또는 Authorization Bearer를 기존 검증기로 확인한다. Supabase 학생 토큰은 getClaims로 확인하고 심판 토큰은 기존 운영 발급자의 ES256 서명 검증을 유지한다. 브라우저의 userId·role·owner_id는 신뢰하지 않는다.

- GET /api/notes: 검증된 로그인 사용자에게 id,title,content만 반환.
- POST /api/notes: title/content만 받고 owner_id는 **검증한 사용자 ID**로 서버가 지정. 성공 201.
- PATCH /api/notes?id=숫자: 제목·본문 수정. DELETE 같은 주소: 삭제.
- 비로그인 자료 요청: 401, application/json, `{ "error": "unauthorized" }`. HTML·자료·JWT·키·스택을 반환하지 않음.
- 쿠키를 쓰는 변경 요청은 배포 주소의 Origin을 확인한다. 잘못된 입력은 400, 거부는 403, 없는 대상은 404, 내부 실패는 일반 503 JSON.

aleph.config.json은 step 3이며 identityProvider는 aleph-plan-do-see의 Auth 발급자, audience authenticated, 해당 JWKS 주소다. allowedRoutes는 실제 구현한 /api/notes와 /api/session이다. judgeIssuer와 기존 RULE_IDS는 변경하지 않는다.

## DB와 서버 설정

기존 이전 SQL artifacts/supabase-stage2.sql과 원문 검색 패턴은 사용자 선택에 따라 Git·정적 배포·제출 JSON에서 제외한다. 별도 보관한다. 이미 만들어진 DB에 초기 SQL을 반복 실행하지 않는다. 가상 메모 owner_id uuid에는 auth.users 외래키가 없다. RLS를 켜고 PUBLIC·anon·authenticated의 자료실 직접 읽기 권한을 회수한 구조를 유지한다.

3단계 추가 SQL artifacts/supabase-stage3.sql은 기존 4건을 보존하면서 자료실 ID 자동 생성 시퀀스를 만들고 service_role에 이 테이블의 INSERT·UPDATE·DELETE 및 시퀀스 권한을 준다. 다른 기존 테이블은 변경하지 않는다. 실행 결과는 최종 보고와 캡처로 구분해 기록하며 SQL 작성 자체를 DB 실행 성공으로 취급하지 않는다.

Vercel Production의 SUPABASE_URL과 SUPABASE_SECRET_KEY를 서버 환경변수에서만 읽는다. 기존 Secret 설정을 유지하며 키를 브라우저 파일·응답·로그·Git에 넣지 않는다. 자료 조회/편집은 Accept-Profile 및 Content-Profile: vault_api를 사용한다. 서버 API 응답에는 owner_id와 내부 정보를 넣지 않는다.

공유 프로젝트의 Data API는 기존 사용자 승인으로 활성화했고 authenticator의 pgrst.db_schemas=vault_api override로 자료실 스키마만 노출한다. **Reset override를 누르거나 public을 추가하지 않는다.** 기존 다른 테이블 데이터·권한·RLS는 변경하지 않는다. 서버 키는 프로젝트 수준 권한을 가지므로 별도 프로젝트만큼 격리된 것은 아니다.

## 현재 남은 보안 약점

Vercel API 주소 자체는 공개지만 비로그인 자료 요청은 거부하도록 변경했다. **로그인 사용자별 소유권 인가는 아직 구현하지 않았다.** 정상 로그인 사용자는 다른 사용자가 만든 메모도 조회·수정·삭제할 수 있다. RLS가 활성화되어도 서버 전용 역할을 통한 현재 API의 소유권 검사를 대신하지 않는다. 이 타인 메모 접근 약점은 다음 단계에서 해결할 항목이며 해결됐다고 쓰지 않는다. 실제 직접 요청 여부와 인가는 심판이 별도로 확인한다.

루트/public의 data.json을 제거한 2단계 구조를 유지한다. 빌드는 오래된 public/data.json도 제거하고 다시 생성하지 않는다. /data.json의 의도한 결과는 404다. Vercel build/output 설정과 첫 화면 X-Content-Type-Options: nosniff를 유지한다. 배포 식별 정보 검증을 유지하며 3단계 public/aleph.json도 자동 생성한다.

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

## 검증 범위와 점수 조건

로컬 인증/CRUD 시험은 모의 upstream 및 실행 중 생성한 시험 토큰을 사용하며 실제 A 계정 시험이 아니다. 실제 실행한 명령의 결과와 외부 확인은 최종 보고/제출 묶음에 기록한다. 미실행 항목은 미확인으로 남긴다. 기존 decider/detect 연습의 미구현 항목은 이번 단계에서 수정하지 않는다.

- 70점 기본: Auth 로그인/로그아웃, 화면 상태, 기존 토큰 검증, 비로그인 거부, 로그인 CRUD, 서버 owner_id 지정, 발급자/경로 일치, 키 비노출, 타인 메모 접근 한계 기록. 실제 A 로그인/CRUD 캡처 필요.
- 추가 10점: 비로그인 GET /api/notes가 401 또는 403 **JSON**이며 HTML과 자료가 없음. 실제 배포 확인 필요.
- 추가 10점: /aleph.json 자동 생성 구조 유지. 실제 배포 접근 캡처 필요.
- 추가 10점: 첫 화면 nosniff 유지. 실제 응답 헤더 캡처 필요.

사용자 직접 확인: 시크릿 창의 자료 비노출 및 JSON 거부, A 로그인 후 기존 4건 조회와 새 시험 메모 CRUD/로그아웃, 서버 키 비노출, /data.json 404, /aleph.json, 첫 화면 보안 헤더, 최신 GitHub/정적 배포의 기존 메모 문장 부재. 실제 계정 시험이나 심판 점수를 추측하지 않는다.

제목처럼 짧은 일반 단어 검색은 기존 XDR fixture 설명에서도 일치할 수 있다. 경로를 열어 전체 본문 일치와 구분하며 관계없는 연습 자료는 보존한다. [AGENTS.md](AGENTS.md)의 저장점 규칙을 따른다.

이번 저장점 로컬 실행: test:r5 12건, test:package 3건 통과. build -- --local 및 모의 Vercel 시스템 환경변수를 제공한 build 성공, 3단계 aleph.json 생성과 data.json 부재 확인. 최신 파일의 기존 메모 본문·비밀값 패턴 및 정적 파일의 메모/서버 키 참조 검색은 0건이었다. 실제 A 계정 로그인 시험은 아직 미확인이다.
