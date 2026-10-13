# 8단계 API 자원 권한 검사 (로컬 작업 중)

메모 API는 검증된 로그인 사용자 ID를 DB 조회·수정 조건의 owner_id에 결합하고, 반환된 모든 행의 저장 소유자가 같은지 다시 확인한다. 타인 자료와 없는 번호는 같은 404 오류로 처리한다. 본문·헤더·쿼리의 role, owner_id, resourceId로 다른 구역 권한을 얻을 수 없다. 소유자 검사 실패 시 자료를 반환하지 않는다.

공지 API는 사용자 요청에 따라 새로 만들었다. `vault_api.resource_roles`의 app_origin·issuer·user_id·resource_id와 instructor 역할을 서버에서 대조한다. app_origin·issuer·user_id는 서버 설정과 검증된 로그인에서만 가져오고 클라이언트의 role을 쓰지 않는다. 수정 함수 `vault_api.update_training_notice`는 역할 행을 잠근 뒤 같은 트랜잭션에서 공지를 수정한다. 권한이 없으면 공지 존재 여부와 관계없이 403이다. 같은 깊이에 export 기능 경로를 만들지 않았고 공지 API 쿼리는 자료 id만 허용한다.

DB 적용: `db/stage8-resources.sql`을 기존 설정의 Supabase 프로젝트에 실제 실행했다. 새 `resource_roles`, `training_notices` 테이블만 추가하고 기존 training_notes·다른 테이블은 수정하지 않았다. 두 테이블의 RLS는 활성화됐으며 PUBLIC·anon·authenticated의 직접 접근은 회수했다. 수정 함수 호출은 service_role만 가능하고 security invoker를 사용한다. 일반 역할 허용 정책은 두지 않아 접근을 기본 거부한다. 보안 점검의 RLS 정책 없음 INFO는 이 서버 전용 설계에 해당한다.

검증: API 로컬 시험 28건 통과. 실제 DB의 롤백 시험에서 가상 학생 거부·다른 앱 거부·다른 발급자 거부·가상 강사 허용을 확인했다. 시험용 역할·공지 행은 모두 롤백했고 실제 강사 지정·공지는 0건, 기존 메모는 5건이다. 실제 계정 로그인 API 실측·배포는 아직 하지 않았다. 판정기의 추가 계약·구역 규칙도 아직 연결하지 않았다.

거부 사유는 개인정보 없이 `X-Aleph-Denial-Reason` 응답 헤더에 짧게 남긴다: login_required, resource_unavailable, ownership_check_failed, instructor_required, permission_check_unavailable. 토큰·사용자 ID·메모·공지 본문을 로그에 남기지 않는다.

강사 지정은 관리자가 Supabase 공식 Table Editor에서 `vault_api.resource_roles`에 해당 앱 주소·발급자·실제 사용자 UUID·resource_id=notices·role=instructor를 직접 등록한다. 서버 API에는 역할 변경 기능이 없으며 기본으로 누구도 강사로 지정하지 않는다. 계정·UUID를 Git·채팅·결과 파일에 복사하지 않는다. 공지도 관리자가 Table Editor에서 등록하며 이번 작업은 임의 공지 내용을 만들지 않았다.

재실행: `node --test test/notices-api.test.mjs test/r5.test.mjs test/resources.test.mjs`. 배포 후 기존 화면의 개발자 도구 Network에서 API 응답과 X-Aleph-Denial-Reason 헤더를 확인한다. 정상 자기 메모·저장된 강사 공지 수정은 허용, 타인 메모는 404, 일반 학생 공지 수정은 403/instructor_required여야 한다. 메뉴는 추가하지 않았다.
