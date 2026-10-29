/* ============================================================================
   주식회사 상효 — 홈페이지 관리자 (GitHub Pages용, 서버 없이 동작)
   ----------------------------------------------------------------------------
   흐름
   1) 로그인 : 아이디+비밀번호 → PBKDF2(SHA-256, 60만 회) → 앞 32바이트가 auth.json의
               verifier와 같으면 통과. 뒤 32바이트는 GitHub 토큰을 여는 AES-GCM 키.
   2) 편집   : GitHub API로 최신 HTML을 받아 data-edit 속성 위치의 값을 폼으로 보여줌
   3) 저장   : 바뀐 값만 최신 HTML에 반영 → 이미지 업로드 → HTML 커밋
               → GitHub Pages가 자동 재배포 (보통 1분 안팎)
   보안 메모
   - 토큰은 메모리에만 존재하고, 새로고침·30분 미사용 시 다시 로그인해야 합니다.
   - 공개 저장소라면 auth.json도 공개됩니다. 반드시 길고 강한 비밀번호로 바꾸세요.
   ============================================================================ */
(() => {
  'use strict';

  /* ---------------------------------------------------------------- 설정 */
  const API = 'https://api.github.com';
  const IDLE_LIMIT_MS = 30 * 60 * 1000;      // 30분 미사용 시 자동 로그아웃
  const MAX_UPLOAD_BYTES = 10 * 1024 * 1024; // 원본 이미지 최대 10MB
  const PAGES = window.ADMIN_PAGES || [];

  /* ---------------------------------------------------------------- 상태 */
  const S = {
    auth: null,        // auth.json 내용
    authSha: null,     // auth.json 의 git sha (갱신 커밋에 필요)
    aesKey: null,      // 비밀번호에서 만든 토큰 암호화 키 (CryptoKey, 추출 불가)
    token: null,       // GitHub 토큰 (메모리에만)
    loginId: '',
    page: null,        // 현재 편집 중인 페이지 정의
    original: {},      // 불러온 값
    values: {},        // 현재 폼 값
    pendingImages: {}, // key → { blob, ext, url }
    fileSha: null,
    lastActive: Date.now()
  };

  /* ---------------------------------------------------------------- 공통 도우미 */
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  const b64FromBytes = bytes => {
    let s = '';
    for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return btoa(s);
  };
  const bytesFromB64 = b64 => Uint8Array.from(atob(String(b64).replace(/\s/g, '')), c => c.charCodeAt(0));
  const escapeHtml = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  const decodeEntities = (() => { const t = document.createElement('textarea'); return s => { t.innerHTML = s; return t.value; }; })();
  const sleep = ms => new Promise(r => setTimeout(r, ms));

  function toast(msg, kind = 'info') {
    const box = $('#toast'), inner = $('#toastInner');
    inner.textContent = msg;
    inner.className = 'rounded-full px-5 py-2.5 text-sm font-semibold shadow-xl ' +
      (kind === 'error' ? 'bg-red-600 text-white' : kind === 'ok' ? 'bg-gold-500 text-navy-900' : 'bg-navy-900 text-white');
    box.style.opacity = '1';
    clearTimeout(toast._t);
    toast._t = setTimeout(() => (box.style.opacity = '0'), kind === 'error' ? 6000 : 3200);
  }
  function showMsg(el, msg, ok) {
    el.textContent = msg;
    el.className = 'text-sm ' + (ok ? 'text-emerald-700' : 'text-red-600');
    el.hidden = false; el.classList.remove('hidden');
  }
  function setBusy(btn, busy, label) {
    if (busy) { btn.dataset.label = btn.textContent; btn.textContent = label || '처리 중…'; btn.disabled = true; }
    else { btn.textContent = btn.dataset.label || btn.textContent; btn.disabled = false; }
  }
  function show(view) {
    ['loginView', 'setupView', 'appView'].forEach(id => ($('#' + id).hidden = id !== view));
  }

  /* ---------------------------------------------------------------- 암호화 */
  const normId = id => String(id || '').trim().toLowerCase();

  async function deriveBits(id, pw, kdf) {
    const base = await crypto.subtle.importKey('raw', enc.encode(normId(id) + '\n' + pw), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: bytesFromB64(kdf.salt), iterations: kdf.iterations }, base, 512);
    return new Uint8Array(bits);
  }
  async function aesKeyFrom(bits) {
    return crypto.subtle.importKey('raw', bits.slice(32), 'AES-GCM', false, ['encrypt', 'decrypt']);
  }
  async function encryptToken(key, token) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(token)));
    return { iv: b64FromBytes(iv), data: b64FromBytes(data) };
  }
  async function decryptToken(key, box) {
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytesFromB64(box.iv) }, key, bytesFromB64(box.data));
    return dec.decode(plain);
  }
  /** 새 비밀번호용 kdf + verifier + 키 생성 */
  async function newCredentials(id, pw) {
    const kdf = { alg: 'PBKDF2-SHA256', iterations: 600000, salt: b64FromBytes(crypto.getRandomValues(new Uint8Array(16))) };
    const bits = await deriveBits(id, pw, kdf);
    return { kdf, verifier: b64FromBytes(bits.slice(0, 32)), key: await aesKeyFrom(bits) };
  }

  /* ---------------------------------------------------------------- GitHub API */
  const repo = () => S.auth.repo;
  const dirPrefix = () => { const d = (repo().dir || '').replace(/^\/+|\/+$/g, ''); return d ? d + '/' : ''; };
  const repoPath = p => dirPrefix() + p;
  const encPath = p => p.split('/').map(encodeURIComponent).join('/');

  async function gh(method, path, body, token = S.token) {
    const res = await fetch(API + path, {
      method,
      headers: {
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        ...(token ? { Authorization: 'Bearer ' + token } : {}),
        ...(body ? { 'Content-Type': 'application/json' } : {})
      },
      body: body ? JSON.stringify(body) : undefined,
      cache: 'no-store'
    });
    if (!res.ok) {
      let msg = '';
      try { msg = (await res.json()).message || ''; } catch (e) {}
      const err = new Error(ghErrorText(res.status, msg));
      err.status = res.status;
      throw err;
    }
    return res.status === 204 ? null : res.json();
  }
  function ghErrorText(status, msg) {
    if (status === 401) return 'GitHub 토큰이 유효하지 않거나 만료되었습니다. [GitHub 연결 설정]에서 새 토큰을 등록하세요.';
    if (status === 403) return 'GitHub 권한이 부족합니다. 토큰에 Contents: Read and write 권한이 있는지 확인하세요.' + (msg ? ` (${msg})` : '');
    if (status === 404) return '저장소 또는 파일을 찾을 수 없습니다. 계정명·저장소·브랜치·폴더를 확인하세요.';
    if (status === 409 || status === 422) return '다른 곳에서 먼저 변경되어 저장이 충돌했습니다. 다시 시도해 주세요.';
    return `GitHub 오류 (${status}) ${msg}`;
  }
  async function getFile(path, token) {
    const r = repo();
    const data = await gh('GET', `/repos/${r.owner}/${r.name}/contents/${encPath(path)}?ref=${encodeURIComponent(r.branch)}`, null, token);
    return { sha: data.sha, text: dec.decode(bytesFromB64(data.content || '')) };
  }
  async function putFile(path, base64, sha, message, token) {
    const r = repo();
    return gh('PUT', `/repos/${r.owner}/${r.name}/contents/${encPath(path)}`, {
      message, content: base64, branch: r.branch, ...(sha ? { sha } : {})
    }, token);
  }
  async function saveAuth(nextAuth, message, token = S.token) {
    nextAuth = Object.assign({}, nextAuth, { rev: (Number(S.auth && S.auth.rev) || 0) + 1 });
    const text = JSON.stringify(nextAuth, null, 2) + '\n';
    const res = await putFile(repoPath('admin/auth.json'), b64FromBytes(enc.encode(text)), S.authSha, message, token);
    S.auth = nextAuth;
    S.authSha = res.content.sha;
    rememberAuth(nextAuth);
  }
  // 저장 직후 GitHub Pages가 예전 auth.json을 보여주는 동안에도 로그인되도록 최신본을 이 브라우저에 보관
  // (auth.json 은 원래 저장소에 공개되는 암호화된 정보라 보관해도 안전)
  function rememberAuth(a) { try { localStorage.setItem('sh-admin-auth', JSON.stringify(a)); } catch (e) {} }
  function rememberedAuth() { try { return JSON.parse(localStorage.getItem('sh-admin-auth') || 'null'); } catch (e) { return null; } }
  const revOf = a => (a && Number(a.rev)) || 0;

  /* ---------------------------------------------------------------- auth.json 불러오기 */
  async function loadAuth() {
    const res = await fetch('auth.json?ts=' + Date.now(), { cache: 'no-store' });
    if (!res.ok) throw new Error('admin/auth.json 파일을 불러오지 못했습니다.');
    let auth = await res.json();
    // 이 브라우저에 보관한 더 최신 버전이 있으면 우선 사용
    const local = rememberedAuth();
    if (local && revOf(local) > revOf(auth)) auth = local;
    // GitHub Pages는 몇 분간 이전 파일을 보여줄 수 있어, 공개 저장소면 API에서 최신본을 한 번 더 확인
    if (auth.repo && auth.repo.owner && auth.repo.name) {
      try {
        S.auth = auth;
        const f = await getFile(repoPath('admin/auth.json'), null);
        const fresh = JSON.parse(f.text);
        if (revOf(fresh) >= revOf(auth)) { auth = fresh; S.authSha = f.sha; }
      } catch (e) { /* 비공개 저장소이거나 요청 제한 → 보유한 최신본 사용 */ }
    }
    S.auth = auth;
  }

  /* ---------------------------------------------------------------- 로그인 */
  function failCount() { try { return JSON.parse(localStorage.getItem('sh-admin-fail') || '{"n":0,"t":0}'); } catch (e) { return { n: 0, t: 0 }; } }
  function setFail(v) { try { localStorage.setItem('sh-admin-fail', JSON.stringify(v)); } catch (e) {} }

  async function onLogin(e) {
    e.preventDefault();
    const btn = $('#loginBtn'), err = $('#loginError');
    err.classList.add('hidden');
    const id = $('#loginId').value, pw = $('#loginPw').value;
    if (!id || !pw) { showMsg(err, '아이디와 비밀번호를 입력해 주세요.'); return; }

    // 연속 실패 시 잠시 대기 (5회 실패 → 30초)
    const f = failCount();
    const wait = f.n >= 5 ? Math.ceil((f.t + 30000 - Date.now()) / 1000) : 0;
    if (wait > 0) { showMsg(err, `로그인 시도가 많습니다. ${wait}초 후 다시 시도해 주세요.`); return; }

    setBusy(btn, true, '확인 중…');
    try {
      await loadAuth();
      const bits = await deriveBits(id, pw, S.auth.kdf);
      if (b64FromBytes(bits.slice(0, 32)) !== S.auth.verifier) {
        setFail({ n: f.n + 1, t: Date.now() });
        await sleep(400);
        showMsg(err, '아이디 또는 비밀번호가 올바르지 않습니다.');
        return;
      }
      setFail({ n: 0, t: 0 });
      S.aesKey = await aesKeyFrom(bits);
      S.loginId = normId(id);
      $('#loginPw').value = '';

      if (!S.auth.token) { openSetup(); return; }
      try { S.token = await decryptToken(S.aesKey, S.auth.token); }
      catch (e2) { showMsg(err, '저장된 GitHub 토큰을 열 수 없습니다. auth.json이 손상되었을 수 있습니다.'); return; }

      // 갱신 커밋에 필요한 auth.json sha 확보 (비공개 저장소 대응)
      if (!S.authSha) { try { S.authSha = (await getFile(repoPath('admin/auth.json'))).sha; } catch (e3) {} }
      await enterApp();
    } catch (e1) {
      showMsg(err, e1.message || '로그인 중 오류가 발생했습니다.');
    } finally {
      setBusy(btn, false);
    }
  }

  function logout(reason) {
    if (isDirty() && !reason && !confirm('저장하지 않은 변경 사항이 있습니다. 로그아웃할까요?')) return;
    Object.assign(S, { token: null, aesKey: null, loginId: '', original: {}, values: {}, pendingImages: {}, page: null });
    show('loginView');
    if (reason) showMsg($('#loginError'), reason);
    $('#loginId').focus();
  }

  /* ---------------------------------------------------------------- 최초 GitHub 연결 */
  function guessRepo() {
    // xxx.github.io/저장소/admin/ 주소이면 계정명·저장소를 자동으로 채움
    const host = location.hostname;
    if (!host.endsWith('.github.io')) return {};
    const owner = host.replace('.github.io', '');
    const parts = location.pathname.split('/').filter(Boolean);
    const adminIdx = parts.lastIndexOf('admin');
    const before = parts.slice(0, adminIdx);
    return before.length ? { owner, name: before[0] } : { owner, name: host };
  }
  function openSetup() {
    const r = Object.assign({ branch: 'main' }, guessRepo(), S.auth.repo || {});
    $('#sOwner').value = r.owner || '';
    $('#sRepo').value = r.name || '';
    $('#sBranch').value = r.branch || 'main';
    $('#sDir').value = r.dir || '';
    show('setupView');
    $('#sToken').focus();
  }

  /** 토큰과 저장소 정보를 검증하고 auth.json을 갱신 */
  async function connectRepo({ owner, name, branch, dir, token }, msgEl, btn) {
    owner = owner.trim(); name = name.trim(); branch = (branch || 'main').trim(); dir = (dir || '').trim().replace(/^\/+|\/+$/g, '');
    token = (token || '').trim();
    if (!owner || !name || !branch || !token) { showMsg(msgEl, '모든 항목을 입력해 주세요.'); return false; }
    setBusy(btn, true, '연결 확인 중…');
    const prev = { auth: S.auth, sha: S.authSha };
    try {
      S.auth = Object.assign({}, S.auth, { repo: { owner, name, branch, dir } });
      const info = await gh('GET', `/repos/${owner}/${name}`, null, token);
      if (info.permissions && info.permissions.push === false) throw new Error('이 토큰으로는 저장소에 쓸 수 없습니다. Contents 쓰기 권한을 확인하세요.');
      const f = await getFile(repoPath('admin/auth.json'), token).catch(e => {
        if (e.status === 404) throw new Error('저장소에서 admin/auth.json을 찾지 못했습니다. 브랜치와 사이트 폴더를 확인하세요.');
        throw e;
      });
      S.authSha = f.sha;
      const next = Object.assign({}, S.auth, { token: await encryptToken(S.aesKey, token), updatedAt: new Date().toISOString().slice(0, 10) });
      await saveAuth(next, 'admin: GitHub 연결 설정', token);
      S.token = token;
      return true;
    } catch (e) {
      S.auth = prev.auth; S.authSha = prev.sha;
      showMsg(msgEl, e.message);
      return false;
    } finally {
      setBusy(btn, false);
    }
  }

  async function onSetup(e) {
    e.preventDefault();
    const ok = await connectRepo({
      owner: $('#sOwner').value, name: $('#sRepo').value, branch: $('#sBranch').value, dir: $('#sDir').value, token: $('#sToken').value
    }, $('#setupError'), $('#setupBtn'));
    if (ok) { $('#sToken').value = ''; toast('GitHub 연결이 완료되었습니다.', 'ok'); await enterApp(); }
  }

  /* ---------------------------------------------------------------- HTML ↔ 값 변환 */
  /** 편집용 텍스트 → HTML (줄바꿈 → <br>, **굵게** → <strong>) */
  function textToHtml(v) {
    return escapeHtml(v).replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>').replace(/\r?\n/g, '<br>');
  }
  /** HTML → 편집용 텍스트 */
  function htmlToText(html) {
    let h = String(html).replace(/\s+/g, ' ');
    h = h.replace(/\s*<br\s*\/?>\s*/gi, '\n').replace(/<strong[^>]*>([\s\S]*?)<\/strong>/gi, '**$1**').replace(/<[^>]+>/g, '');
    return decodeEntities(h).split('\n').map(l => l.trim()).join('\n').trim();
  }
  function fieldsOf(page) {
    const out = [];
    page.groups.forEach(g => {
      (g.fields || []).forEach(f => out.push(f));
      (g.items || []).forEach(it => it.fields.forEach(f => out.push(f)));
    });
    return out;
  }
  function siteBase(doc) {
    const c = doc.querySelector('link[rel="canonical"]');
    return c ? c.getAttribute('href') : location.origin + '/';
  }

  /** 문서에서 현재 값을 읽음 */
  function readValue(doc, f) {
    const k = f.key;
    if (f.type === 'toggle') { const el = doc.querySelector(`[data-edit-show="${k}"]`); return el ? !el.hasAttribute('hidden') : true; }
    if (f.type === 'url') { const el = doc.querySelector(`[data-edit-href="${k}"]`); return el ? el.getAttribute('href') || '' : ''; }
    if (f.type === 'html') { const el = doc.querySelector(`[data-edit-html="${k}"]`); return el ? el.innerHTML.replace(/^\n+|\s+$/g, '') : ''; }
    if (f.type === 'image') {
      if (k === 'og_image') {
        const m = doc.querySelector('meta[property="og:image"]');
        if (!m) return '';
        const v = m.getAttribute('content') || '', base = siteBase(doc);
        return v.startsWith(base) ? v.slice(base.length) : v;
      }
      const el = doc.querySelector(`[data-edit-img="${k}"]`);
      return el && !el.hasAttribute('hidden') ? el.getAttribute('src') || '' : '';
    }
    const el = doc.querySelector(`[data-edit="${k}"]`);
    if (!el) return '';
    if (el.dataset.editAttr) return el.getAttribute(el.dataset.editAttr) || '';
    if (el.tagName === 'TITLE') return el.textContent.trim();
    return htmlToText(el.innerHTML);
  }

  /** 바뀐 값만 문서에 반영 */
  function applyValues(doc, changes) {
    const fieldMap = Object.fromEntries(allFields().map(f => [f.key, f]));
    for (const [k, v] of Object.entries(changes)) {
      const f = fieldMap[k] || { key: k, type: 'textarea' };
      if (f.type === 'toggle') { $$(`[data-edit-show="${k}"]`, doc).forEach(el => el.toggleAttribute('hidden', !v)); continue; }
      if (f.type === 'html') { $$(`[data-edit-html="${k}"]`, doc).forEach(el => (el.innerHTML = '\n' + v.trim() + '\n      ')); continue; }
      if (f.type === 'image') { applyImage(doc, k, v); continue; }
      if (f.type !== 'url') {
        $$(`[data-edit="${k}"]`, doc).forEach(el => {
          if (el.dataset.editAttr) el.setAttribute(el.dataset.editAttr, v);
          else if (el.tagName === 'TITLE') el.textContent = v;
          else el.innerHTML = textToHtml(f.type === 'text' ? v.replace(/\r?\n/g, ' ') : v);
        });
      }
      // 링크 주소 (url 필드, 또는 전화/이메일처럼 글자와 링크가 같은 키)
      $$(`[data-edit-href="${k}"]`, doc).forEach(el => {
        const t = el.dataset.hrefType;
        if (t === 'tel') el.setAttribute('href', 'tel:' + v.replace(/[^\d+]/g, ''));
        else if (t === 'mailto') el.setAttribute('href', 'mailto:' + v.trim());
        else {
          el.setAttribute('href', v.trim() || '#');
          if (/^https?:\/\//i.test(v.trim())) { el.setAttribute('target', '_blank'); el.setAttribute('rel', 'noopener'); }
          else { el.removeAttribute('target'); el.removeAttribute('rel'); }
        }
      });
    }
    if ('site_url' in changes && !('og_image' in changes)) {
      const m = doc.querySelector('meta[property="og:image"]');
      const prev = S.original.site_url || '';
      if (m && prev && (m.getAttribute('content') || '').startsWith(prev)) m.setAttribute('content', changes.site_url + m.getAttribute('content').slice(prev.length));
    }
    // 비어 있으면 숨기는 항목 (대표자, 사업자번호, 태그 등)
    $$('[data-hide-empty]', doc).forEach(el => {
      const targets = el.matches('[data-edit]') ? [el] : $$('[data-edit]', el);
      el.toggleAttribute('hidden', targets.length > 0 && targets.every(t => t.textContent.trim() === ''));
    });
    // 검색엔진용 구조화 데이터의 전화·이메일·회사명 동기화
    const ld = doc.querySelector('script[type="application/ld+json"]');
    if (ld && ['phone', 'email', 'company_name', 'site_url'].some(k => k in changes)) {
      try {
        const j = JSON.parse(ld.textContent);
        if ('phone' in changes) j.telephone = changes.phone;
        if ('email' in changes) j.email = changes.email;
        if ('company_name' in changes) j.name = changes.company_name;
        if ('site_url' in changes) j.url = changes.site_url;
        ld.textContent = '\n  ' + JSON.stringify(j, null, 2).replace(/\n/g, '\n  ') + '\n  ';
      } catch (e) { /* 형식이 다르면 건너뜀 */ }
    }
  }
  function applyImage(doc, k, v) {
    if (k === 'og_image') {
      let m = doc.querySelector('meta[property="og:image"]');
      if (!v) { if (m) m.remove(); return; }
      if (!m) {
        m = doc.createElement('meta');
        m.setAttribute('property', 'og:image');
        const anchor = doc.querySelector('meta[property="og:description"]') || doc.querySelector('title');
        anchor.after(m);
      }
      m.setAttribute('content', /^https?:/i.test(v) ? v : new URL(v, siteBase(doc)).href);
      return;
    }
    $$(`[data-edit-img="${k}"]`, doc).forEach(el => {
      if (v) { el.setAttribute('src', v); el.removeAttribute('hidden'); }
      else { el.removeAttribute('src'); el.setAttribute('hidden', ''); }
    });
  }
  /** 문서를 원래 형태(doctype + 주석 포함) 그대로 문자열로 */
  function serialize(doc) {
    return [...doc.childNodes].map(n =>
      n.nodeType === Node.DOCUMENT_TYPE_NODE ? '<!DOCTYPE html>' :
      n.nodeType === Node.COMMENT_NODE ? `<!--${n.data}-->` :
      n.outerHTML || ''
    ).join('\n') + '\n';
  }
  function allFields() {
    const base = fieldsOf(S.page);
    return base.concat(S.page._extra || []);
  }

  /* ---------------------------------------------------------------- 페이지 불러오기 */
  async function loadPage(page) {
    if (isDirty() && !confirm('저장하지 않은 변경 사항이 있습니다. 다른 페이지로 이동할까요?')) return;
    S.page = page;
    clearPendingImages();
    $('#pageTitle').textContent = page.title;
    $('#pageMeta').textContent = '불러오는 중…';
    $('#viewSiteBtn').href = '../' + page.file;
    $('#editor').innerHTML = '<div class="card animate-pulse text-sm text-silver-500">GitHub에서 최신 내용을 불러오는 중…</div>';
    renderTabs();
    try {
      const f = await getFile(repoPath(page.file));
      S.fileSha = f.sha;
      const doc = new DOMParser().parseFromString(f.text, 'text/html');
      // 스키마에 없는 data-edit 키는 '기타 항목'으로 자동 추가
      const known = new Set(fieldsOf(page).map(x => x.key));
      page._extra = [...new Set($$('[data-edit]', doc).map(el => el.dataset.edit))].filter(k => !known.has(k))
        .map(k => ({ key: k, label: k, type: 'textarea' }));
      S.original = {};
      allFields().forEach(fl => (S.original[fl.key] = readValue(doc, fl)));
      S.values = { ...S.original };
      renderEditor();
      $('#pageMeta').textContent = `${repoPath(page.file)} · 최신 버전`;
    } catch (e) {
      $('#editor').innerHTML = '';
      const c = document.createElement('div');
      c.className = 'card text-sm text-red-600';
      c.textContent = e.message;
      $('#editor').append(c);
      $('#pageMeta').textContent = '불러오기 실패';
      if (e.status === 401) logout('GitHub 토큰이 만료되었습니다. 다시 로그인 후 [GitHub 연결 설정]에서 토큰을 교체하세요.');
    }
    updateSaveBar();
  }

  /* ---------------------------------------------------------------- 화면 그리기 */
  function renderTabs() {
    const box = $('#pageTabs');
    box.innerHTML = '';
    PAGES.forEach(p => {
      const b = document.createElement('button');
      b.type = 'button';
      b.className = 'tab text-left' + (S.page && S.page.id === p.id ? ' active' : '');
      b.textContent = p.title;
      b.addEventListener('click', () => { if (!S.page || S.page.id !== p.id) loadPage(p); });
      box.append(b);
    });
  }

  function renderEditor() {
    const ed = $('#editor'), nav = $('#sectionNav');
    ed.innerHTML = ''; nav.innerHTML = '';
    const groups = S.page.groups.slice();
    if (S.page._extra && S.page._extra.length) groups.push({ id: 'extra', title: '기타 항목', desc: '편집 목록에 없는 항목입니다.', fields: S.page._extra });

    groups.forEach(g => {
      const sec = document.createElement('section');
      sec.className = 'card scroll-mt-28';
      sec.id = 'g-' + g.id;
      sec.innerHTML = `<h3 class="text-base font-bold">${escapeHtml(g.title)}</h3>` + (g.desc ? `<p class="help !mt-1">${escapeHtml(g.desc)}</p>` : '');
      if (g.fields && g.fields.length) {
        const grid = document.createElement('div');
        grid.className = 'mt-5 grid gap-5 md:grid-cols-2';
        g.fields.forEach(f => grid.append(renderField(f)));
        sec.append(grid);
      }
      if (g.items && g.items.length) {
        const wrap = document.createElement('div');
        wrap.className = 'mt-6 grid gap-4 xl:grid-cols-2';
        g.items.forEach(it => {
          const box = document.createElement('div');
          box.className = 'rounded-2xl border border-silver-200 bg-silver-100/60 p-4 md:p-5';
          box.innerHTML = `<p class="mb-4 text-sm font-bold text-navy-800">${escapeHtml(it.title)}</p>`;
          const grid = document.createElement('div');
          grid.className = 'grid gap-4';
          it.fields.forEach(f => grid.append(renderField(f)));
          box.append(grid);
          wrap.append(box);
        });
        sec.append(wrap);
      }
      ed.append(sec);

      const a = document.createElement('a');
      a.href = '#g-' + g.id; a.className = 'navlink'; a.textContent = g.title; a.dataset.group = g.id;
      nav.append(a);
    });
    markChanged();
  }

  function renderField(f) {
    const wrap = document.createElement('div');
    const id = 'f-' + f.key;
    wrap.dataset.field = f.key;
    const full = f.type === 'html' || f.type === 'image' || f.type === 'textarea';
    if (full) wrap.className = 'md:col-span-2';
    const v = S.values[f.key];

    if (f.type === 'toggle') {
      wrap.className = 'flex items-center justify-between gap-3 rounded-xl bg-white px-3.5 py-2.5 md:col-span-2';
      wrap.innerHTML = `<span class="text-[13px] font-semibold text-navy-800" id="${id}-l">${escapeHtml(f.label)}</span>
        <button type="button" role="switch" class="switch" id="${id}" aria-labelledby="${id}-l" aria-checked="${v ? 'true' : 'false'}"><span></span></button>`;
      $('button', wrap).addEventListener('click', e => {
        const on = e.currentTarget.getAttribute('aria-checked') !== 'true';
        e.currentTarget.setAttribute('aria-checked', String(on));
        S.values[f.key] = on; markChanged();
      });
      return wrap;
    }

    const label = `<label class="lbl" for="${id}">${escapeHtml(f.label)}</label>`;
    const help = f.help ? `<p class="help">${escapeHtml(f.help)}</p>` : '';

    if (f.type === 'image') {
      wrap.innerHTML = `${label}
        <div class="flex flex-col gap-4 sm:flex-row sm:items-center">
          <div class="relative grid h-36 w-full shrink-0 place-items-center overflow-hidden rounded-xl bg-navy-900 sm:w-56">
            <img class="max-h-full max-w-full object-contain" alt="" hidden />
            <span class="text-xs text-silver-400">기본 이미지 사용 중</span>
          </div>
          <div class="space-y-2">
            <input id="${id}" type="file" accept="image/png,image/jpeg,image/webp,image/gif" class="sr-only" />
            <div class="flex flex-wrap gap-2">
              <label for="${id}" class="btn-navy cursor-pointer">이미지 선택</label>
              <button type="button" class="btn-line js-clear">기본으로</button>
            </div>
            <p class="text-xs text-silver-500 js-info"></p>
            ${help}
          </div>
        </div>`;
      const input = $('input', wrap);
      input.addEventListener('change', async () => {
        const file = input.files[0];
        input.value = '';
        if (!file) return;
        try {
          const out = await prepareImage(file, f.maxDim || 1600);
          if (S.pendingImages[f.key]) URL.revokeObjectURL(S.pendingImages[f.key].url);
          S.pendingImages[f.key] = out;
          S.values[f.key] = '__pending__';
          updateImagePreview(f.key);
          markChanged();
        } catch (e) { toast(e.message, 'error'); }
      });
      $('.js-clear', wrap).addEventListener('click', () => {
        if (S.pendingImages[f.key]) { URL.revokeObjectURL(S.pendingImages[f.key].url); delete S.pendingImages[f.key]; }
        S.values[f.key] = '';
        updateImagePreview(f.key);
        markChanged();
      });
      queueMicrotask(() => updateImagePreview(f.key));
      return wrap;
    }

    let control;
    if (f.type === 'html') {
      control = `<textarea id="${id}" class="inp font-mono text-[13px] leading-relaxed" rows="24" spellcheck="false"></textarea>`;
    } else if (f.type === 'textarea') {
      const rows = Math.min(6, Math.max(2, String(v || '').split('\n').length + 1));
      control = `<textarea id="${id}" class="inp leading-relaxed" rows="${rows}"></textarea>`;
    } else {
      control = `<input id="${id}" class="inp" type="text" ${f.type === 'url' ? 'inputmode="url" placeholder="https://… 또는 #contact"' : ''} />`;
    }
    const hint = f.type === 'textarea' ? '<p class="help">Enter = 줄바꿈 · **글자** = 굵게</p>' : '';
    wrap.innerHTML = label + control + (help || hint);
    const el = $('#' + id, wrap);
    el.value = v == null ? '' : v;
    el.addEventListener('input', () => { S.values[f.key] = el.value; markChanged(); });
    return wrap;
  }

  function updateImagePreview(key) {
    const wrap = $(`[data-field="${key}"]`);
    if (!wrap) return;
    const img = $('img', wrap), ph = $('span', wrap), info = $('.js-info', wrap);
    const p = S.pendingImages[key], v = S.values[key];
    let src = '';
    if (p) { src = p.url; info.textContent = `새 이미지 · ${p.width}×${p.height}px · ${(p.blob.size / 1024).toFixed(0)}KB (저장 시 업로드)`; }
    else if (v) { src = /^https?:|^data:/.test(v) ? v : '../' + v; info.textContent = v; }
    else info.textContent = '';
    img.hidden = !src; ph.hidden = !!src;
    if (src) img.src = src; else img.removeAttribute('src');
  }

  /* ---------------------------------------------------------------- 이미지 최적화 */
  async function prepareImage(file, maxDim) {
    if (!/^image\/(png|jpeg|webp|gif)$/.test(file.type)) throw new Error('PNG, JPG, WEBP, GIF 이미지만 올릴 수 있습니다.');
    if (file.size > MAX_UPLOAD_BYTES) throw new Error('이미지는 10MB 이하만 올릴 수 있습니다.');
    const bmp = await createImageBitmap(file);
    const { width, height } = bmp;
    const extOf = t => ({ 'image/png': 'png', 'image/jpeg': 'jpg', 'image/webp': 'webp', 'image/gif': 'gif' }[t]);
    // GIF(움직이는 이미지)나 이미 충분히 작은 이미지는 그대로 사용
    if (file.type === 'image/gif' || (Math.max(width, height) <= maxDim && file.size <= 400 * 1024)) {
      bmp.close && bmp.close();
      return { blob: file, ext: extOf(file.type), url: URL.createObjectURL(file), width, height };
    }
    // 큰 이미지는 축소 후 WebP로 변환 (투명 배경 유지, 용량 대폭 감소)
    const scale = Math.min(1, maxDim / Math.max(width, height));
    const w = Math.round(width * scale), h = Math.round(height * scale);
    const canvas = document.createElement('canvas');
    canvas.width = w; canvas.height = h;
    canvas.getContext('2d').drawImage(bmp, 0, 0, w, h);
    bmp.close && bmp.close();
    let blob = await new Promise(r => canvas.toBlob(r, 'image/webp', 0.86));
    let ext = 'webp';
    if (!blob || blob.type !== 'image/webp') { blob = await new Promise(r => canvas.toBlob(r, file.type === 'image/png' ? 'image/png' : 'image/jpeg', 0.86)); ext = file.type === 'image/png' ? 'png' : 'jpg'; }
    if (scale === 1 && blob.size >= file.size) { blob = file; ext = extOf(file.type); }
    return { blob, ext, url: URL.createObjectURL(blob), width: w, height: h };
  }
  function clearPendingImages() {
    Object.values(S.pendingImages).forEach(p => URL.revokeObjectURL(p.url));
    S.pendingImages = {};
  }

  /* ---------------------------------------------------------------- 변경 표시 */
  function changedKeys() {
    return Object.keys(S.values).filter(k => S.values[k] !== S.original[k]);
  }
  function isDirty() { return !!S.page && changedKeys().length > 0; }

  function markChanged() {
    const changed = new Set(changedKeys());
    $$('[data-field]').forEach(w => {
      const k = w.dataset.field, on = changed.has(k);
      const c = $('.inp', w);
      if (c) c.classList.toggle('changed', on);
      const l = $('.lbl, span[id$="-l"]', w);
      if (l) l.classList.toggle('dot-changed', on);
    });
    // 섹션 바로가기에 변경 표시
    $$('#sectionNav [data-group]').forEach(a => {
      const sec = document.getElementById('g-' + a.dataset.group);
      a.classList.toggle('dot-changed', !!sec && $$('[data-field]', sec).some(w => changed.has(w.dataset.field)));
    });
    updateSaveBar();
  }
  function updateSaveBar(text) {
    const n = S.page ? changedKeys().length : 0;
    $('#saveStatus').textContent = text || (n ? `변경 ${n}건 · 저장하지 않음` : '변경 사항 없음');
    $('#saveBtn').disabled = !n;
    $('#resetBtn').disabled = !n;
  }

  /* ---------------------------------------------------------------- 저장 및 게시 */
  function validate(changes) {
    const fm = Object.fromEntries(allFields().map(f => [f.key, f]));
    for (const [k, v] of Object.entries(changes)) {
      const f = fm[k];
      if (!f) continue;
      if (f.type === 'url' && /^\s*(javascript|data|vbscript):/i.test(v)) return `${f.label}: 사용할 수 없는 주소입니다.`;
      if (k === 'email' && v && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v.trim())) return '이메일 형식이 올바르지 않습니다.';
      if (f.type === 'html' && /<script|\son\w+\s*=|javascript:/i.test(v)) return `${f.label}: 스크립트나 이벤트 속성은 넣을 수 없습니다.`;
    }
    return '';
  }

  async function onSave() {
    const keys = changedKeys();
    if (!keys.length) return;
    const changes = Object.fromEntries(keys.map(k => [k, S.values[k]]));
    const problem = validate(changes);
    if (problem) { toast(problem, 'error'); return; }

    const btn = $('#saveBtn');
    setBusy(btn, true, '저장 중…');
    $('#resetBtn').disabled = true;
    try {
      // 1) 새 이미지 업로드
      const stamp = new Date().toISOString().replace(/\D/g, '').slice(0, 14);
      for (const [k, p] of Object.entries(S.pendingImages)) {
        if (changes[k] !== '__pending__') continue;
        updateSaveBar(`이미지 업로드 중… (${k})`);
        const path = `images/${k.replace(/_/g, '-')}-${stamp}.${p.ext}`;
        const bytes = new Uint8Array(await p.blob.arrayBuffer());
        await putFile(repoPath(path), b64FromBytes(bytes), null, `admin: 이미지 업로드 (${k})`);
        changes[k] = path;
      }
      // 2) 최신 HTML에 바뀐 값만 반영 후 커밋 (충돌 시 1회 재시도)
      updateSaveBar('페이지 저장 중…');
      let commit;
      for (let attempt = 0; attempt < 2; attempt++) {
        const f = await getFile(repoPath(S.page.file));
        const doc = new DOMParser().parseFromString(f.text, 'text/html');
        applyValues(doc, changes);
        const html = serialize(doc);
        try {
          commit = await putFile(repoPath(S.page.file), b64FromBytes(enc.encode(html)), f.sha, `admin: ${S.page.title} 내용 수정 (${Object.keys(changes).length}건)`);
          break;
        } catch (e) { if (!(e.status === 409 || e.status === 422) || attempt) throw e; await sleep(800); }
      }
      // 3) 상태 갱신
      Object.assign(S.original, changes);
      S.values = { ...S.original };
      clearPendingImages();
      renderEditor();
      updateSaveBar('저장 완료 · 사이트 반영까지 보통 1분 정도 걸립니다');
      toast('저장되었습니다. 잠시 후 사이트에 반영됩니다.', 'ok');
      watchDeploy(commit && commit.commit && commit.commit.sha);
    } catch (e) {
      toast(e.message || '저장에 실패했습니다.', 'error');
      updateSaveBar();
      if (e.status === 401) logout('GitHub 토큰이 만료되었습니다. 다시 로그인 후 [GitHub 연결 설정]에서 토큰을 교체하세요.');
    } finally {
      setBusy(btn, false);
      updateSaveBar($('#saveStatus').textContent);
      $('#saveBtn').disabled = !changedKeys().length;
      $('#resetBtn').disabled = !changedKeys().length;
    }
  }

  /** GitHub Pages 배포 상태 확인 (토큰에 Pages 읽기 권한이 있을 때만) */
  async function watchDeploy(sha) {
    if (!sha) return;
    const r = repo();
    for (let i = 0; i < 36; i++) {
      await sleep(5000);
      if (!S.token) return;
      try {
        const b = await gh('GET', `/repos/${r.owner}/${r.name}/pages/builds/latest`);
        if (b.commit === sha && b.status === 'built') { updateSaveBar('사이트에 반영되었습니다 ✓'); toast('사이트에 반영되었습니다.', 'ok'); return; }
        if (b.commit === sha && b.status === 'errored') { updateSaveBar('배포 오류 — GitHub Actions 탭을 확인하세요'); return; }
      } catch (e) { return; /* 권한 없음 → 상태 표시 생략 */ }
    }
  }

  function onReset() {
    if (!confirm('저장하지 않은 변경 사항을 모두 되돌릴까요?')) return;
    clearPendingImages();
    S.values = { ...S.original };
    renderEditor();
  }

  /* ---------------------------------------------------------------- 설정: 비밀번호 */
  async function onChangePassword(e) {
    e.preventDefault();
    const msg = $('#pwMsg'), btn = $('#pwBtn');
    const cur = $('#pwCurrent').value, newId = $('#pwNewId').value.trim(), p1 = $('#pwNew').value, p2 = $('#pwNew2').value;
    if (!cur || !p1) { showMsg(msg, '현재 비밀번호와 새 비밀번호를 입력해 주세요.'); return; }
    if (p1 !== p2) { showMsg(msg, '새 비밀번호가 서로 다릅니다.'); return; }
    if (p1.length < 12 || !/[A-Za-z]/.test(p1) || !/\d/.test(p1) || !/[^A-Za-z0-9]/.test(p1)) { showMsg(msg, '새 비밀번호는 12자 이상, 영문·숫자·특수문자를 모두 포함해야 합니다.'); return; }
    if (newId && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(newId)) { showMsg(msg, '아이디는 이메일 형식으로 입력해 주세요.'); return; }
    setBusy(btn, true, '저장 중…');
    try {
      const bits = await deriveBits(S.loginId, cur, S.auth.kdf);
      if (b64FromBytes(bits.slice(0, 32)) !== S.auth.verifier) { showMsg(msg, '현재 비밀번호가 올바르지 않습니다.'); return; }
      const id = newId || S.loginId;
      const cred = await newCredentials(id, p1);
      const next = Object.assign({}, S.auth, {
        kdf: cred.kdf, verifier: cred.verifier, initial: false,
        token: S.token ? await encryptToken(cred.key, S.token) : null,
        updatedAt: new Date().toISOString().slice(0, 10)
      });
      if (!S.authSha) S.authSha = (await getFile(repoPath('admin/auth.json'))).sha;
      await saveAuth(next, 'admin: 관리자 계정 정보 변경');
      S.aesKey = cred.key; S.loginId = normId(id);
      ['pwCurrent', 'pwNewId', 'pwNew', 'pwNew2'].forEach(x => ($('#' + x).value = ''));
      $('#initialBanner').hidden = true;
      showMsg(msg, '변경되었습니다. 다음 로그인부터 새 정보로 접속하세요. (사이트 반영까지 1분 정도 걸릴 수 있습니다)', true);
    } catch (err) {
      showMsg(msg, err.message);
    } finally { setBusy(btn, false); }
  }

  /* ---------------------------------------------------------------- 설정: GitHub */
  async function onGithubSettings(e) {
    e.preventDefault();
    const ok = await connectRepo({
      owner: $('#gOwner').value, name: $('#gRepo').value, branch: $('#gBranch').value, dir: $('#gDir').value,
      token: $('#gToken').value.trim() || S.token
    }, $('#ghMsg'), $('#ghBtn'));
    if (ok) {
      $('#gToken').value = '';
      showMsg($('#ghMsg'), 'GitHub 연결 정보가 저장되었습니다.', true);
      $('#repoLabel').textContent = `${repo().owner}/${repo().name}`;
    }
  }

  /* ---------------------------------------------------------------- 설정: 변경 이력 */
  async function loadHistory() {
    const list = $('#historyList');
    list.innerHTML = '<li class="py-3 text-silver-500">불러오는 중…</li>';
    try {
      const r = repo();
      const commits = await gh('GET', `/repos/${r.owner}/${r.name}/commits?sha=${encodeURIComponent(r.branch)}&per_page=20`);
      list.innerHTML = '';
      commits.forEach(c => {
        const li = document.createElement('li');
        li.className = 'flex items-start justify-between gap-4 py-3';
        const d = new Date(c.commit.author.date);
        const left = document.createElement('div');
        left.innerHTML = `<p class="font-medium"></p><p class="text-xs text-silver-500"></p>`;
        left.children[0].textContent = c.commit.message.split('\n')[0];
        left.children[1].textContent = `${d.toLocaleString('ko-KR')} · ${c.commit.author.name}`;
        const a = document.createElement('a');
        a.href = c.html_url; a.target = '_blank'; a.rel = 'noopener';
        a.className = 'shrink-0 text-xs font-semibold text-gold-600 hover:underline';
        a.textContent = 'GitHub에서 보기 ↗';
        li.append(left, a);
        list.append(li);
      });
      if (!commits.length) list.innerHTML = '<li class="py-3 text-silver-500">기록이 없습니다.</li>';
    } catch (e) {
      list.innerHTML = '';
      const li = document.createElement('li'); li.className = 'py-3 text-red-600'; li.textContent = e.message; list.append(li);
    }
  }

  function openSettings(tab) {
    const dlg = $('#settingsDialog');
    const r = repo();
    $('#gOwner').value = r.owner || ''; $('#gRepo').value = r.name || ''; $('#gBranch').value = r.branch || 'main'; $('#gDir').value = r.dir || '';
    ['#pwMsg', '#ghMsg'].forEach(s => $(s).classList.add('hidden'));
    switchSettingsTab(tab);
    if (!dlg.open) dlg.showModal();
  }
  function switchSettingsTab(tab) {
    $$('[data-spanel]').forEach(p => (p.hidden = p.dataset.spanel !== tab));
    $$('.stab').forEach(b => {
      const on = b.dataset.stab === tab;
      b.classList.toggle('bg-white', on); b.classList.toggle('shadow', on);
      b.setAttribute('aria-selected', String(on));
    });
    if (tab === 'history') loadHistory();
  }

  /* ---------------------------------------------------------------- 앱 시작 */
  async function enterApp() {
    show('appView');
    $('#repoLabel').textContent = `${repo().owner}/${repo().name}`;
    $('#initialBanner').hidden = !S.auth.initial;
    S.lastActive = Date.now();
    await loadPage(PAGES[0]);
  }

  // 활동 감지 → 30분 미사용 시 자동 로그아웃
  ['pointerdown', 'keydown', 'scroll'].forEach(ev => window.addEventListener(ev, () => (S.lastActive = Date.now()), { passive: true }));
  setInterval(() => {
    if (S.token && Date.now() - S.lastActive > IDLE_LIMIT_MS) {
      if (isDirty()) { S.lastActive = Date.now(); toast('30분간 사용하지 않았습니다. 변경 내용을 저장해 주세요.'); return; }
      logout('30분 동안 사용하지 않아 자동 로그아웃되었습니다.');
    }
  }, 30000);

  window.addEventListener('beforeunload', e => { if (isDirty()) { e.preventDefault(); e.returnValue = ''; } });

  // 섹션 바로가기 하이라이트
  const secIO = new IntersectionObserver(entries => {
    entries.forEach(en => {
      if (!en.isIntersecting) return;
      $$('#sectionNav a').forEach(a => a.classList.toggle('active', a.getAttribute('href') === '#' + en.target.id));
    });
  }, { rootMargin: '-20% 0px -70% 0px' });
  new MutationObserver(() => $$('#editor > section').forEach(s => secIO.observe(s))).observe($('#editor'), { childList: true });

  // 이벤트 연결
  $('#loginForm').addEventListener('submit', onLogin);
  $('#setupForm').addEventListener('submit', onSetup);
  $('#saveBtn').addEventListener('click', onSave);
  $('#resetBtn').addEventListener('click', onReset);
  $('#pwForm').addEventListener('submit', onChangePassword);
  $('#ghForm').addEventListener('submit', onGithubSettings);
  $('#closeSettings').addEventListener('click', () => $('#settingsDialog').close());
  $$('.stab').forEach(b => b.addEventListener('click', () => switchSettingsTab(b.dataset.stab)));
  document.addEventListener('click', e => {
    const o = e.target.closest('[data-open-settings]');
    if (o) { if (!S.token) return; openSettings(o.dataset.openSettings); }
    if (e.target.closest('.js-logout')) logout();
  });
  // Ctrl/Cmd + S 저장
  document.addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's' && S.token) { e.preventDefault(); if (!$('#saveBtn').disabled) onSave(); }
  });

  if (!window.crypto || !crypto.subtle) {
    showMsg($('#loginError'), '이 브라우저에서는 관리자 기능을 쓸 수 없습니다. https 주소에서 최신 브라우저로 접속해 주세요.');
    $('#loginBtn').disabled = true;
  }
  $('#loginId').focus();
})();
