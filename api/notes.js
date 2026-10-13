
import {
  serverSettings,
  verifyRequest,
  safeOrigin,
  bodyObject,
  jsonHeaders
} from '../src/vault-server.mjs';

import { activeVaultDeny } from '../src/vault-xdr.mjs';
import { isApprovedDevice } from './device-approval.js';
import { decide } from '../src/decider.mjs';
import { decisionInput } from '../src/decision-input.mjs';
import { resourceIdForPath } from '../src/resources.mjs';
import { rejectApi } from '../src/api-denial.mjs';

// 메모 ID 검증
function isValidNoteId(id) {
  return (
    typeof id === 'string' &&
    /^[1-9][0-9]{0,9}$/u.test(id) &&
    Number(id) <= 2147483647
  );
}

// 메모 API 핸들러
export function createNotesHandler({
  verify = verifyRequest,
  settings = serverSettings,
  fetcher = (...args) => fetch(...args),
  detailRoute = false,
  deny = activeVaultDeny,
  deviceApproved = isApprovedDevice
} = {}) {

  return async function handler(request, response) {

    jsonHeaders(response);

    const id = request.query?.id;
    const validId = isValidNoteId(id);

    // 서버에서 확인한 경로와 ID만 사용
    const resourcePath =
      detailRoute && validId
        ? `/api/notes/${id}`
        : '/api/notes';

    response.setHeader(
      'X-Aleph-Resource-Id',
      resourceIdForPath(resourcePath)
    );

    try {

      // 기존 정책 결정 전용 요청 유지
      // 메모 CRUD 권한을 부여하는 경로가 아님
      if (!detailRoute && request.method === 'POST') {

        const body = bodyObject(request);

        if (body?.schema === 'aleph.decision.v1') {

          if (!decisionInput(body)) {
            return response.status(400).json({
              error: 'invalid_request'
            });
          }

          return response.status(200).json(
            await decide(body)
          );
        }
      }

      // 1. 로그인 검증
      const identity = await verify(request);

      if (
        !identity ||
        typeof identity.userId !== 'string' ||
        !identity.userId
      ) {
        return rejectApi(
          response,
          401,
          'unauthorized',
          'login_required'
        );
      }

      // Never trust an installed PWA or client-declared device ID.
      // The existing decision-fixture POST above does not grant note access.
      if (await deviceApproved(request, identity) !== true) {
        return rejectApi(response, 403, 'forbidden', 'device_not_approved');
      }

      // 2. 기존 XDR 거부 규칙 유지
      if (await deny(identity)) {
        return rejectApi(
          response,
          403,
          'forbidden',
          'xdr_denied'
        );
      }

      // 3. 허용 HTTP 메서드
      // 전체 목록 GET은 허용하지 않음
      const methods = detailRoute
        ? ['GET', 'PUT', 'PATCH', 'DELETE']
        : ['POST', 'PUT', 'PATCH', 'DELETE'];

      if (!methods.includes(request.method)) {

        response.setHeader(
          'Allow',
          methods.join(', ')
        );

        return rejectApi(
          response,
          405,
          'method_not_allowed',
          'method_not_allowed'
        );
      }

      // 4. 허용된 쿼리 및 ID 검증
      if (
        Object.keys(request.query ?? {}).some(
          key => key !== 'id'
        ) ||
        (detailRoute && !validId) ||
        (id !== undefined && !validId)
      ) {
        return rejectApi(
          response,
          400,
          'invalid_request',
          'invalid_resource'
        );
      }

      // 5. 변경 요청 Origin 검사
      if (
        request.method !== 'GET' &&
        !safeOrigin(request)
      ) {
        return rejectApi(
          response,
          403,
          'forbidden',
          'origin_denied'
        );
      }

      // 6. 서버 전용 DB 설정
      const { key, url } = settings();

      const endpoint = new URL(
        '/rest/v1/training_notes',
        url
      );

      endpoint.searchParams.set(
        'select',
        'id,title,content,owner_id'
      );

      // 서버에서 검증한 사용자 ID로 소유권 제한
      endpoint.searchParams.set(
        'owner_id',
        `eq.${identity.userId}`
      );

      const headers = {
        apikey: key,
        'Accept-Profile': 'vault_api',
        'Content-Profile': 'vault_api',
        'Content-Type': 'application/json',
        Prefer: 'return=representation'
      };

      const init = {
        method:
          request.method === 'PUT'
            ? 'PATCH'
            : request.method,
        headers,
        redirect: 'error',
        signal: AbortSignal.timeout(10000)
      };

      // 7. 단건 요청 판단
      const hasId =
        detailRoute ||
        ['PUT', 'PATCH', 'DELETE'].includes(
          request.method
        );

      if (hasId) {

        if (!validId) {
          return rejectApi(
            response,
            400,
            'invalid_request',
            'invalid_resource'
          );
        }

        endpoint.searchParams.set(
          'id',
          `eq.${id}`
        );

      } else if (id !== undefined) {

        // 생성 요청에 임의의 ID를 지정하지 못하도록 차단
        return rejectApi(
          response,
          400,
          'invalid_request',
          'invalid_resource'
        );
      }

      // 8. 조회·수정·삭제 전 실제 DB 소유자 확인
      if (hasId) {

        const ownerEndpoint = new URL(endpoint);

        // 소유자 검증에는 본문을 조회하지 않음
        ownerEndpoint.searchParams.set(
          'select',
          'id,owner_id'
        );

        // 저장된 실제 소유자를 확인
        ownerEndpoint.searchParams.delete(
          'owner_id'
        );

        const ownerResponse = await fetcher(
          ownerEndpoint,
          {
            method: 'GET',
            headers,
            redirect: 'error',
            signal: AbortSignal.timeout(10000)
          }
        );

        if (!ownerResponse.ok) {
          throw new Error('owner_lookup_failed');
        }

        const stored = await ownerResponse.json();

        if (
          !Array.isArray(stored) ||
          stored.length > 1
        ) {
          throw new Error('invalid_owner_response');
        }

        // 존재하지 않거나 타인 소유인 메모 거부
        // 다른 사용자에게 메모 존재 여부를 노출하지 않음
        if (
          stored.length !== 1 ||
          stored[0]?.id !== Number(id) ||
          stored[0]?.owner_id !== identity.userId
        ) {
          return rejectApi(
            response,
            404,
            'not_found',
            'resource_unavailable'
          );
        }
      }

      // 9. 메모 생성·수정 데이터 검증
      if (
        ['POST', 'PUT', 'PATCH'].includes(
          request.method
        )
      ) {

        const body = bodyObject(request);

        if (
          !body ||
          typeof body.title !== 'string' ||
          !body.title.trim() ||
          body.title.length > 200 ||
          typeof body.content !== 'string' ||
          !body.content.trim() ||
          body.content.length > 10000
        ) {
          return rejectApi(
            response,
            400,
            'invalid_request',
            'invalid_body'
          );
        }

        // 클라이언트의 owner_id, role, userId 무시
        const note = {
          title: body.title.trim(),
          content: body.content.trim()
        };

        // 생성 시 소유자는 로그인 사용자로 강제
        if (request.method === 'POST') {
          note.owner_id = identity.userId;
        }

        init.body = JSON.stringify(note);
      }

      // 10. DB 요청
      // owner_id 필터를 유지해 타인 데이터 변경 방지
      const upstream = await fetcher(
        endpoint,
        init
      );

      if (!upstream.ok) {
        throw new Error('database_request_failed');
      }

      const rows = await upstream.json();

      // 11. DB 응답 검증
      if (
        !Array.isArray(rows) ||
        rows.some(row =>
          !Number.isInteger(row.id) ||
          typeof row.title !== 'string' ||
          typeof row.content !== 'string'
        )
      ) {
        throw new Error('invalid_database_response');
      }

      // 최종 소유자 검사
      if (
        rows.some(row =>
          row.owner_id !== identity.userId
        )
      ) {
        return rejectApi(
          response,
          503,
          'service_unavailable',
          'ownership_check_failed'
        );
      }

      // 단건 요청이 실제로 처리되지 않은 경우
      if (
        hasId &&
        rows.length === 0
      ) {
        return rejectApi(
          response,
          404,
          'not_found',
          'resource_unavailable'
        );
      }

      // 단건 응답은 정확히 한 개여야 함
      if (
        hasId &&
        (rows.length !== 1 ||
         rows[0].id !== Number(id))
      ) {
        throw new Error('invalid_record_count');
      }

      // 12. 삭제 응답
      if (request.method === 'DELETE') {
        return response.status(200).json({
          deleted: true
        });
      }

      // 응답에서 owner_id 제거
      const notes = rows.map(
        ({ id, title, content }) => ({
          id,
          title,
          content
        })
      );

      // 13. 단건 조회 응답
      if (
        detailRoute &&
        request.method === 'GET'
      ) {
        return response.status(200).json(
          notes[0]
        );
      }

      // 14. 생성 및 수정 응답
      return response.status(
        request.method === 'POST' ? 201 : 200
      ).json({
        notes
      });

    } catch {
      // DB 및 권한 검증 실패 시 기본 거부
      return rejectApi(
        response,
        503,
        'service_unavailable',
        'permission_check_unavailable'
      );
    }
  };
}

export default createNotesHandler();
