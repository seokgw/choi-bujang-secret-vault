# 서버 자원 ID

| 기존/정의 경로 | 자원 ID |
|---|---|
| `/api/notes` | `notes` |
| `/api/notes/1` 또는 `/api/notes?id=1` | `notes:1` |
| `/api/notices` | `notices` |
| `/api/notices/1` | `notices:1` |

레코드의 기존 숫자 ID와 자료·주소는 바꾸지 않는다. 메모 API는 서버가 처리하는 경로와 검증한 숫자 ID에서 자원 ID를 결정해 `X-Aleph-Resource-Id` 응답 헤더로 표시한다. 클라이언트 헤더·본문·쿼리의 `resourceId`로 자원의 종류를 바꾸지 않는다.

처음에는 강사 공지 주소만 정의했으나, 후속 사용자 요청으로 공지 읽기·수정 API와 DB 권한 저장소를 추가했다. `/api/notices`는 로그인한 사용자의 GET만, `/api/notices/:id`는 GET·PUT·PATCH만 처리한다. 수정은 서버가 검증한 사용자와 DB의 강사 역할을 대조한다. 화면 메뉴는 변경하지 않았다. 자원 ID 표시는 권한 부여가 아니고 기존 메모의 로그인·소유권 검사는 유지한다. 판정기 v1 요청·응답 계약에 `resourceId` 항목을 추가하지 않는다.

확인 명령: `node --test test/resources.test.mjs`. 화면에서는 기존 자료실의 개발자 도구 Network에서 메모 요청을 선택하고 Response Headers의 `X-Aleph-Resource-Id`를 본다. 이번 로컬 변경은 아직 배포하지 않았으므로 배포 화면 확인은 배포 후 진행한다. 정상은 `notes` 또는 `notes:숫자`이며, 클라이언트가 `notices`를 보내도 메모 자원 ID가 바뀌지 않아야 한다. 비로그인 요청은 기존대로 401이다.
