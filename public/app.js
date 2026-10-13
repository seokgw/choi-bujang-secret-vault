const login = document.querySelector('#login');
const workspace = document.querySelector('#workspace');
const editor = document.querySelector('#editor');
const list = document.querySelector('#notes');
const status = document.querySelector('#status');
const deviceApproval = document.querySelector('#device-approval');
const offlineNotice = document.querySelector('#offline-notice');
function updateConnectivity() {
  offlineNotice.hidden = navigator.onLine;
}
window.addEventListener('online', updateConnectivity);
window.addEventListener('offline', updateConnectivity);
updateConnectivity();
const approvalPanel = document.querySelector('#device-request-panel');
const approvalResult = document.querySelector('#device-request-result');
let approvedDevice = false;
function lockWorkspace() {
  approvedDevice = false;
  workspace.hidden = true;
  list.replaceChildren();
  resetEditor();
}
async function updateDeviceApproval() {
  const current = generation;
  lockWorkspace();
  deviceApproval.textContent = '서버 승인 상태 확인 중';
  try {
    const response = await fetch('/api/device-approval', {
      credentials: 'same-origin', cache: 'no-store',
      headers: { Accept: 'application/json' }
    });
    if (current !== generation) return;
    if (response.status === 401) {
      loggedOut();
      return;
    }
    if (!response.ok) throw new Error('status unavailable');
    const data = await response.json();
    if (current !== generation) return;
    approvedDevice = data.deviceApproval === 'approved' && data.trusted === true;
    deviceApproval.textContent = approvedDevice
      ? '서버에서 등록·승인된 기기' : '승인 대기 또는 미확인 · 보호 자료 차단';
    approvalPanel.hidden = approvedDevice;
    if (approvedDevice) {
      workspace.hidden = false;
      try { await loadNotes(); } catch (error) {
        lockWorkspace(); approvalPanel.hidden = false;
        status.textContent = '자료 접근을 재검증하지 못했습니다: ' + error.message;
      }
    }
  } catch {
    lockWorkspace();
    approvalPanel.hidden = false;
    deviceApproval.textContent = '서버 검증 불가 · 보호 자료 차단';
  }
}
let generation = 0;
let editingId = null;
function resetEditor() {
  editingId = null;
  editor.reset();
  document.querySelector('#editor-heading').textContent = '메모 추가';
}
function loggedOut() {
  deviceApproval.textContent = '로그인 필요 · 기기 승인되지 않음';
  generation++;
  lockWorkspace();
  approvalPanel.hidden = true;
  login.hidden = false;
}
async function request(path, options = {}) {
  const response = await fetch(path, { ...options, credentials: 'same-origin', cache: 'no-store',
    headers: { 'Content-Type': 'application/json' } });
  if (response.status === 401) {
    loggedOut();
    throw new Error('로그인이 필요합니다. 이메일과 비밀번호를 확인해 주세요.');
  }
  if (!response.ok) throw new Error('요청을 처리할 수 없습니다. 잠시 후 다시 시도해 주세요.');
  return response.json();
}
async function loadNotes() {
  if (!approvedDevice) return;
  const current = generation;
  const data = await request('/api/notes');
  if (current !== generation || !approvedDevice) return;
  if (!Array.isArray(data.notes)) throw new Error('자료를 불러올 수 없습니다.');
  list.replaceChildren(...data.notes.map(note => {
    const item = document.createElement('li');
    const title = document.createElement('strong');
    const content = document.createElement('span');
    title.textContent = note.title;
    content.textContent = note.content;
    const edit = document.createElement('button');
    edit.type = 'button'; edit.textContent = '수정';
    edit.addEventListener('click', () => {
      editingId = note.id;
      editor.elements.title.value = note.title;
      editor.elements.content.value = note.content;
      document.querySelector('#editor-heading').textContent = '메모 수정';
      editor.elements.title.focus();
    });
    const remove = document.createElement('button');
    remove.type = 'button'; remove.textContent = '삭제';
    remove.addEventListener('click', async () => {
      if (!confirm('이 가상 메모를 삭제할까요?')) return;
      remove.disabled = true;
      try {
        await request(`/api/notes?id=${encodeURIComponent(note.id)}`, { method: 'DELETE' });
        resetEditor(); await loadNotes(); status.textContent = '메모를 삭제했습니다.';
      } catch (error) { status.textContent = error.message; }
      finally { remove.disabled = false; }
    });
    item.append(title, content, document.createElement('br'), edit, remove);
    return item;
  }));
}
login.addEventListener('submit', async event => {
  event.preventDefault();
  const button = login.querySelector('button'); button.disabled = true;
  try {
    await request('/api/session', { method: 'POST', body: JSON.stringify({
      email: login.elements.email.value.trim(), password: login.elements.password.value,
    }) });
    generation++; login.hidden = true; approvalPanel.hidden = false;
    await updateDeviceApproval(); status.textContent = '로그인했습니다. 기기 승인 여부를 확인해 주세요.';
  } catch (error) { status.textContent = error.message; }
  finally { login.elements.password.value = ''; button.disabled = false; }
});
document.querySelector('#logout').addEventListener('click', async () => {
  try {
    await request('/api/session', { method: 'DELETE' });
    loggedOut(); status.textContent = '로그아웃했습니다.';
  } catch (error) { status.textContent = error.message; }
});
document.querySelector('#request-device').addEventListener('click', async () => {
  const button = document.querySelector('#request-device');
  button.disabled = true;
  lockWorkspace();
  try {
    const response = await fetch('/api/device-approval', {
      method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: { 'Content-Type': 'application/json' }, body: '{}'
    });
    if (response.status === 401) { loggedOut(); return; }
    if (!response.ok) throw new Error('승인 요청을 접수하지 못했습니다.');
    const data = await response.json();
    approvalResult.textContent = data.deviceApproval === 'pending'
      ? '요청 접수 · 서버 기기 증명과 별도 승인 대기 중' : '승인되지 않았습니다.';
    await updateDeviceApproval();
  } catch (error) { approvalResult.textContent = error.message; }
  finally { button.disabled = false; }
});
document.querySelector('#recheck-device').addEventListener('click', updateDeviceApproval);
document.querySelector('#pending-logout').addEventListener('click', () => document.querySelector('#logout').click());
document.querySelector('#cancel').addEventListener('click', resetEditor);
editor.addEventListener('submit', async event => {
  event.preventDefault();
  const button = editor.querySelector('button'); button.disabled = true;
  try {
    const path = editingId === null ? '/api/notes' : `/api/notes?id=${encodeURIComponent(editingId)}`;
    await request(path, { method: editingId === null ? 'POST' : 'PATCH', body: JSON.stringify({
      title: editor.elements.title.value, content: editor.elements.content.value,
    }) });
    resetEditor(); await loadNotes(); status.textContent = '메모를 저장했습니다.';
  } catch (error) { status.textContent = error.message; }
  finally { button.disabled = false; }
});
loggedOut();
try {
  await request('/api/session');
  generation++; login.hidden = true; approvalPanel.hidden = false;
  await updateDeviceApproval(); status.textContent = '로그인 상태입니다. 기기 승인 확인이 필요합니다.';
} catch (error) { status.textContent = error.message; }
