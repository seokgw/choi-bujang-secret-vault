# BYTE BACK 자료실 · 2단계 저장점

현재 구조: **브라우저 → Vercel 공개 API 서버 함수 → Supabase**.
1단계 data.json을 직접 확인한 결과 가상 메모는 4건이었다. 화면 디자인과 카드 렌더링을 유지하고 조회 경로만 `/api/notes`로 변경했다. 로그인·인가 기능은 아직 없다. 기존 정책·탐지 연습과 서버 뼈대를 유지했다.

## 다시 실행

Node.js 22 이상과 npm을 사용한다. 새 체크아웃에서는 `npm ci`로 기존 의존성을 설치한다.

- `npm run test:r5`: 배포 식별 정보, API 응답 필드와 안전한 오류, 자기 점검 시험.
- `npm run test:package`: 기존 서버 뼈대와 패키징 안내 시험.
- `npm run build -- --local`: 정적 파일 준비. Supabase나 Vercel 서버 함수 실행은 아니다.
- `npm run build`: Vercel 시스템 환경변수를 검증하고 public/aleph.json 생성. 배포 정보가 없으면 실패한다.
- `npm run bundle`: 저장점 커밋 후 artifacts/submission.json 생성. bundle-notes.json에 작업 설명을 먼저 작성한다. 두 파일은 Git에서 제외된다.

실제 배포 후 `/`를 열면 자동 조회한다. 정상 설정에서는 카드 4개가 표시되어야 한다. 설정 누락·Supabase 오류 시 일반 안내만 보여야 한다. POST `/api/notes`는 405로 거부되어야 한다. GET API는 현재 인증 없이 호출 가능하다.

## 사용자 실행: Supabase와 Vercel

이전 SQL은 로컬 `artifacts/supabase-stage2.sql`이다. 사용자 선택에 따라 원문이 든 SQL은 Git·정적 배포·제출 JSON에서 제외했다. 새 Git 체크아웃에는 없으므로 별도 보관하고 Supabase SQL Editor에서 직접 실행한다. 실제 키는 SQL에 적지 않는다.

최종 SQL은 트랜잭션으로 vault_api.training_notes를 만들고 기존 4건 전체를 삽입한다. owner_id uuid는 가상 소유자이며 auth.users 외래키가 없다. RLS를 활성화하고 PUBLIC·anon·authenticated 테이블 권한을 회수한다. 서버용 service_role에만 스키마 USAGE와 테이블 SELECT를 준다. 동명 스키마/테이블이 있으면 덮어쓰지 않고 실패한다. 이미 실행한 DB에는 초기 SQL을 반복 실행하지 않는다.

2026-10-06 사용자 승인으로 aleph-plan-do-see에 초기 SQL을 실행하고 자료실 테이블만 vault_api로 이동했다. 실제 SQL 조회에서 4건, owner_id uuid, RLS true, anon/authenticated SELECT false를 확인했다. 기존 테이블 데이터·권한·RLS는 변경하지 않았다. 사용자는 같은 항목을 캡처로 재확인할 수 있다.

Vercel Production 서버 환경변수 SUPABASE_URL과 SUPABASE_SECRET_KEY를 설정했다. 키는 Vercel Secret 유형으로 저장했으며 값 자체를 채팅·파일·Git·캡처에 넣지 않았다. SUPABASE_SECRET_KEY는 서버에서만 사용한다. 서버는 apikey 헤더와 Accept-Profile: vault_api로 title,content만 조회한다. owner_id·내부 오류·스택·환경변수·키는 응답하거나 로그로 출력하지 않는다. [Supabase 공식 키 사용법](https://supabase.com/docs/guides/getting-started/api-keys)을 따른다.

공유 프로젝트의 Data API가 꺼져 있었고, 활성화 화면은 기존 RLS 없는 테이블들의 공개 위험을 경고했다. 사용자 추가 승인으로 authenticator 역할의 pgrst.db_schemas를 vault_api로 제한한 뒤 Data API를 활성화했다. 관리 화면의 기본 노출 목록보다 이 override가 우선한다. **Reset override를 누르거나 public을 추가하지 않는다.** 기본 노출 목록만 보고 기존 테이블이 실제로 노출됐다고 판단하지 않는다. [Supabase 공식 override 설명](https://supabase.com/docs/guides/troubleshooting/pgrst106-the-schema-must-be-one-of-the-following-error-when-querying-an-exposed-schema)을 참고한다. 서버 키는 프로젝트 수준의 권한을 가지므로 별도 프로젝트만큼 격리된 것은 아니다.

## 현재 보안 약점과 배포 구조

정적 data.json에서 가상 메모를 제거하고 루트와 public의 파일을 삭제했다. 빌드는 복사하지 않고 오래된 public/data.json도 제거한다. 의도한 `/data.json` 배포 결과는 404다. 화면은 `/api/notes`만 호출한다.

하지만 Vercel 서버 함수 URL 자체는 공개 주소다. 인증/인가 없이 직접 API 주소를 요청할 수 있는 것이 현재 단계의 남은 약점이다. 해결되지 않았다. 서버 키를 숨기고 DB 직접 읽기를 막아도 공개 API를 통한 읽기는 가능하다. 공개 API 직접 요청 여부는 심판이 별도로 확인한다. 자기 점검은 심판 판정이 아니다.

vercel.json의 기존 build/output 설정을 유지하며 첫 화면과 정적 응답에 X-Content-Type-Options: nosniff를 설정했다. 배포 식별 정보 검증을 유지하고 2단계에서도 public/aleph.json을 생성한다. 실제 배포의 404·헤더·aleph 접근·카드 표시는 사용자 확인 필요다.

## 가상 메모 노출 검색 절차

**A. 현재 최신 상태:** GitHub 최신 파일, 현재 Vercel 정적 배포 파일, 현재 /data.json을 각각 확인한다. 자료를 반환하는 공개 API 응답은 정적 검색과 별도로 기록한다.

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

현재 배포는 개발자 도구 Network를 열고 `/`를 새로고침한다. HTML·JS·CSS 등 정적 응답과 현재 public 배포 파일을 저장해 위 패턴으로 검색한다. 실제 /aleph.json의 커밋과 저장점을 대조한다. /api/notes 응답은 공개 API 약점 확인으로 따로 기록한다.

주소창에서 https://choi-bujang-secret-vault-vert.vercel.app/data.json 을 직접 열고 Network의 HTTP 404를 확인한다. 파일이 있으면 메모 0건이고 기존 제목·본문이 없어야 한다. /aleph.json 접근과 `/`의 nosniff 헤더도 확인한다. 비로그인 창에서 /api/notes를 직접 열고 요청 여부를 별도로 캡처한다. 키나 환경변수 값은 캡처하지 않는다.

기록 형식: `시각(KST) | 대상 URL/저장소 | 커밋 SHA/배포 ID | 최신/과거 | 검사 경로 | 검색 건수/HTTP 상태 | 통과/실패/미확인 | 캡처 경로`. 원문 대신 경로와 건수만 적는다.

**B. 과거 공개 이력:** 옛 공개 GitHub 커밋과 옛 Vercel 배포는 별개다. 초기 공개 커밋에는 메모가 남아 있다. 최신 파일에서 없어져도 과거 노출이 완전히 해소된 것이 아니다. 이번 작업은 Git 이력을 재작성하거나 옛 배포를 삭제하지 않는다. 옛 배포 URL·커밋을 따로 목록화하고 확인하지 않은 접근 차단·삭제를 완료로 적지 않는다.

## 검증 범위와 점수 조건

Supabase의 실제 DB 상태와 Vercel Production 환경변수 저장을 확인했다. 배포 화면·404·aleph·헤더의 최신 결과는 artifacts/submission.json과 캡처로 별도 기록한다. 확인하지 않은 항목은 성공으로 쓰지 않는다. 제출 묶음은 실제 배포 주소에 요청한 HTTP/형식 결과만 기록하며 응답 실패는 사용자 확인 필요로 남긴다. 로컬 시험은 실제 심판 판정이 아니다.

- 70점 기본: SQL·owner_id uuid·RLS·직접 읽기 권한 회수, 서버 환경변수 API, 정적 원문 제거, 공개 API·과거 노출 한계 기록.
- 추가 10점: /data.json 404 구조. 실제 배포 확인 필요.
- 추가 10점: /aleph.json 생성 유지. 실제 배포 확인 필요.
- 추가 10점: 첫 화면 nosniff 설정. 실제 배포 확인 필요.

[AGENTS.md](AGENTS.md)의 저장점 규칙을 따른다. judgeIssuer와 기존 정책 RULE_IDS는 변경하지 않는다. 다음 단계의 로그인·인가가 현재 구현된 것으로 표현하지 않는다.

## 이번 저장점의 실제 로컬 확인

npm CLI로 test:r5 5건과 test:package 3건이 통과했다. 클라이언트 4개 카드 렌더링은 모의 API/DOM 시험이며 실제 배포 화면 확인은 아니다. build -- --local이 성공했고, 로컬에 모의 Vercel 시스템 환경변수를 제공한 build에서도 aleph.json 생성과 data.json 부재를 확인했다. 이것은 외부 배포 성공 증거가 아니다.

기존 decider:test는 6단계 규칙 미구현 오류를 보고했고 detect:test는 미구현 탐지 항목 2개를 확인 필요로 보고했다. 두 기능의 기존 소스는 수정하지 않았다. 비밀값 패턴 검사와 정적 파일 검사는 최종 보고에 기록한다.

제목처럼 짧은 일반 단어 검색은 다른 연습 자료의 설명에서도 일치할 수 있다. 경로를 열어 전체 본문 일치와 구분한다. 기존 XDR fixture 설명 2곳의 일반 단어 일치는 메모 노출이 아니므로 연습 자료를 보존했다. 기존 메모 본문 네 문장의 최신 파일 검색은 별도로 수행한다.
