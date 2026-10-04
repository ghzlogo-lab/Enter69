'use strict';
/* ENTER — servidor de música (sem dependências externas, só Node >= 18) */
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');

const env = process.env;
const PORT = +env.PORT || 3000;
const DATA = env.DATA_DIR ? path.resolve(env.DATA_DIR) : path.join(__dirname, 'data');
const PUB = path.join(__dirname, 'public');
const ADD_NAME = String(env.ADD_NAME || 'psique').trim().toLowerCase();
const ADD_PASSWORD = env.ADD_PASSWORD || '';
const TTL_MS = (+env.SONG_TTL_HOURS || 168) * 3600 * 1000;       // 1 semana
const PREVIEW_SECONDS = 30;
const MAX_AUDIO = (+env.MAX_AUDIO_MB || 15) * 1024 * 1024;
const MAX_COVER = 150 * 1024;
const MAX_TOTAL = MAX_AUDIO + MAX_COVER + 8192;
const MAX_SONGS = +env.MAX_SONGS || 50;
const HOPS = env.TRUST_PROXY_HOPS === undefined ? 1 : +env.TRUST_PROXY_HOPS;

if (ADD_PASSWORD.length < 8) {
  console.error('\nERRO: defina a variável ADD_PASSWORD (mínimo 8 caracteres) — é a palavra-passe do add "' + ADD_NAME + '".\n');
  process.exit(1);
}

for (const d of ['audio', 'preview', 'cover']) fs.mkdirSync(path.join(DATA, d), { recursive: true });
const F_SONGS = path.join(DATA, 'songs.json'), F_PREV = path.join(DATA, 'previews.json'), F_KEY = path.join(DATA, 'secret.key');

/* ---------- armazenamento ---------- */
function readJSON(f, d) { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return d; } }
function writeJSON(f, o) { const t = f + '.' + process.pid + '.tmp'; fs.writeFileSync(t, JSON.stringify(o)); fs.renameSync(t, f); }
let songs = readJSON(F_SONGS, []);
let prev = readJSON(F_PREV, {});
let prevTimer = null;
function savePrev() { if (prevTimer) return; prevTimer = setTimeout(() => { prevTimer = null; writeJSON(F_PREV, prev); }, 1500); }
function saveSongs() { writeJSON(F_SONGS, songs); }

let SECRET;
try { SECRET = Buffer.from(fs.readFileSync(F_KEY, 'utf8').trim(), 'hex'); if (SECRET.length !== 32) throw 0; }
catch { SECRET = crypto.randomBytes(32); fs.writeFileSync(F_KEY, SECRET.toString('hex'), { mode: 0o600 }); }

const fAudio = id => path.join(DATA, 'audio', id + '.mp3');
const fPrev = id => path.join(DATA, 'preview', id + '.mp3');
const fCover = id => path.join(DATA, 'cover', id + '.bin');
const ID_RE = /^[A-Za-z0-9_-]{12}$/;

function removeFiles(id) { for (const f of [fAudio(id), fPrev(id), fCover(id)]) { try { fs.unlinkSync(f); } catch { } } }
function purge() {
  const now = Date.now(), dead = songs.filter(s => s.expiresAt <= now);
  if (!dead.length) return;
  for (const s of dead) { removeFiles(s.id); delete prev[s.id]; }
  songs = songs.filter(s => s.expiresAt > now);
  saveSongs(); savePrev();
}
function removeSong(id) { removeFiles(id); delete prev[id]; songs = songs.filter(s => s.id !== id); saveSongs(); savePrev(); }
function cleanOrphans() {
  const ids = new Set(songs.map(s => s.id));
  for (const [dir, ext] of [['audio', '.mp3'], ['preview', '.mp3'], ['cover', '.bin']]) {
    for (const f of fs.readdirSync(path.join(DATA, dir))) {
      const id = f.endsWith(ext) ? f.slice(0, -ext.length) : '';
      if (!ids.has(id)) { try { fs.unlinkSync(path.join(DATA, dir, f)); } catch { } }
    }
  }
}
purge(); cleanOrphans();
setInterval(purge, 10 * 60 * 1000);

/* ---------- utilitários de segurança ---------- */
const sha = s => crypto.createHash('sha256').update(s).digest('base64url');
const sign = v => crypto.createHmac('sha256', SECRET).update(v).digest('base64url').slice(0, 22);
function safeEq(a, b) { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); }
const scrypt = (pw, salt) => new Promise((res, rej) => crypto.scrypt(String(pw).normalize('NFKC'), salt, 32, { N: 16384, r: 8, p: 1 }, (e, k) => e ? rej(e) : res(k)));
async function hashCode(code) { const salt = crypto.randomBytes(16); return salt.toString('hex') + ':' + (await scrypt(code, salt)).toString('hex'); }
async function checkCode(code, stored) { const [s, h] = String(stored).split(':'); const d = await scrypt(code, Buffer.from(s, 'hex')); return crypto.timingSafeEqual(d, Buffer.from(h, 'hex')); }
const ADMIN_SALT = crypto.randomBytes(16);
let ADMIN_HASH = null;
const adminReady = scrypt(ADD_PASSWORD, ADMIN_SALT).then(h => { ADMIN_HASH = h; });
const sleep = ms => new Promise(r => setTimeout(r, ms));

const buckets = new Map();
function limit(key, max, ms) { const n = Date.now(); let b = buckets.get(key); if (!b || b.r < n) { b = { c: 0, r: n + ms }; buckets.set(key, b); } return ++b.c <= max; }
function blocked(key, max) { const b = buckets.get(key); return !!(b && b.r > Date.now() && b.c >= max); }
function fail(key, ms) { const n = Date.now(); let b = buckets.get(key); if (!b || b.r < n) { b = { c: 0, r: n + ms }; buckets.set(key, b); } b.c++; }
setInterval(() => { const n = Date.now(); for (const [k, b] of buckets) if (b.r < n) buckets.delete(k); for (const [k, t] of tokens) if (t.exp < n) tokens.delete(k); for (const [k, s] of sessions) if (s.exp < n) sessions.delete(k); }, 60 * 1000).unref();

function clientIp(req) {
  if (HOPS > 0) { const xf = String(req.headers['x-forwarded-for'] || '').split(',').map(s => s.trim()).filter(Boolean); if (xf.length >= HOPS) return xf[xf.length - HOPS]; }
  return req.socket.remoteAddress || 'x';
}
function isHttps(req) { return !!req.socket.encrypted || (HOPS > 0 && String(req.headers['x-forwarded-proto'] || '').split(',').pop().trim() === 'https'); }
function cookies(req) { const o = {}; String(req.headers.cookie || '').split(';').forEach(p => { const i = p.indexOf('='); if (i > 0) o[p.slice(0, i).trim()] = p.slice(i + 1).trim(); }); return o; }
function setCookie(req, res, name, val, o) {
  let c = `${name}=${val}; Path=/; HttpOnly; SameSite=${o.sameSite}; Max-Age=${o.maxAge}`;
  if (isHttps(req)) c += '; Secure';
  res.setHeader('Set-Cookie', [].concat(res.getHeader('Set-Cookie') || [], c));
}
function visitor(req, res) {
  const c = cookies(req).eid;
  if (c) { const [id, sig] = c.split('.'); if (id && sig && id.length === 24 && safeEq(sig, sign(id))) return id; }
  const id = crypto.randomBytes(18).toString('base64url');
  setCookie(req, res, 'eid', id + '.' + sign(id), { maxAge: 31536000, sameSite: 'Lax' });
  return id;
}

const sessions = new Map(), tokens = new Map();
function session(req) { const sid = cookies(req).ens; if (!sid) return null; const s = sessions.get(sid); if (!s || s.exp < Date.now()) { sessions.delete(sid); return null; } return s; }
function mkToken(o) { const t = crypto.randomBytes(24).toString('base64url'); tokens.set(t, { id: o.id, kind: o.kind, vid: o.vid, exp: Date.now() + o.ttl, hits: 0, max: o.max }); return t; }

/* ---------- respostas ---------- */
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; media-src 'self'; connect-src 'self'; manifest-src 'self'; worker-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
function secHeaders(req, res) {
  res.setHeader('Content-Security-Policy', CSP);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  if (isHttps(req)) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
}
function json(res, status, obj) { res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(obj)); }
function err(res, status, message, code) { json(res, status, { error: code || 'erro', message }); }

function sendFile(req, res, file, type, extra) {
  fs.stat(file, (e, st) => {
    if (e) return err(res, 404, 'Não encontrado.');
    let start = 0, end = st.size - 1, status = 200;
    const r = req.headers.range;
    if (r) {
      const m = /^bytes=(\d*)-(\d*)$/.exec(r);
      if (!m || (m[1] === '' && m[2] === '')) { res.writeHead(416, { 'Content-Range': 'bytes */' + st.size }); return res.end(); }
      if (m[1] === '') start = Math.max(0, st.size - +m[2]);
      else { start = +m[1]; if (m[2] !== '') end = Math.min(+m[2], end); }
      if (start > end || start >= st.size) { res.writeHead(416, { 'Content-Range': 'bytes */' + st.size }); return res.end(); }
      status = 206;
    }
    const h = Object.assign({ 'Content-Type': type, 'Content-Length': end - start + 1, 'Accept-Ranges': 'bytes' }, extra);
    if (status === 206) h['Content-Range'] = `bytes ${start}-${end}/${st.size}`;
    res.writeHead(status, h);
    if (req.method === 'HEAD') return res.end();
    const s = fs.createReadStream(file, { start, end });
    s.on('error', () => res.destroy());
    res.on('close', () => s.destroy());
    s.pipe(res);
  });
}

function readBody(req, max) {
  return new Promise((resolve, reject) => {
    let n = 0; const c = [];
    req.on('data', d => { n += d.length; if (n > max) { reject(Object.assign(new Error('Ficheiro demasiado grande.'), { status: 413 })); req.destroy(); return; } c.push(d); });
    req.on('end', () => resolve(Buffer.concat(c)));
    req.on('error', reject);
  });
}
async function readJSONBody(req) {
  if (!/^application\/json/i.test(req.headers['content-type'] || '')) throw Object.assign(new Error('Pedido inválido.'), { status: 415 });
  const b = await readBody(req, 4096);
  try { const o = JSON.parse(b.toString('utf8')); if (o && typeof o === 'object') return o; } catch { }
  throw Object.assign(new Error('Pedido inválido.'), { status: 400 });
}

/* ---------- MP3: validação e corte da prévia (30 s) ---------- */
const BR1 = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0];
const BR2 = [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0];
const SR = { 3: [44100, 48000, 32000], 2: [22050, 24000, 16000], 0: [11025, 12000, 8000] };
function frameHeader(b, i) {
  if (i + 4 > b.length || b[i] !== 0xFF || (b[i + 1] & 0xE0) !== 0xE0) return null;
  const ver = (b[i + 1] >> 3) & 3, layer = (b[i + 1] >> 1) & 3;
  if (ver === 1 || layer !== 1) return null;                       // só MPEG Layer III (MP3)
  const bi = b[i + 2] >> 4, si = (b[i + 2] >> 2) & 3;
  if (bi === 0 || bi === 15 || si === 3) return null;
  const sr = SR[ver][si], kbps = (ver === 3 ? BR1 : BR2)[bi], pad = (b[i + 2] >> 1) & 1;
  const len = (ver === 3 ? Math.floor(144000 * kbps / sr) : Math.floor(72000 * kbps / sr)) + pad;
  return { len, dur: (ver === 3 ? 1152 : 576) / sr };
}
function analyzeMp3(buf, maxSec) {
  let pos = 0;
  if (buf.length > 10 && buf.toString('latin1', 0, 3) === 'ID3') {
    pos = 10 + (((buf[6] & 0x7f) << 21) | ((buf[7] & 0x7f) << 14) | ((buf[8] & 0x7f) << 7) | (buf[9] & 0x7f)) + ((buf[5] & 0x10) ? 10 : 0);
  }
  let total = 0, frames = 0, first = true, pvStart = -1, pvEnd = -1, pvDur = 0;
  while (pos + 4 <= buf.length) {
    const h = frameHeader(buf, pos);
    if (!h || pos + h.len > buf.length) { pos++; continue; }
    const n = pos + h.len;
    if (n + 4 <= buf.length && !frameHeader(buf, n) && buf.toString('latin1', n, n + 3) !== 'TAG') { pos++; continue; }
    if (first) {
      first = false;
      if (/Xing|Info|VBRI/.test(buf.toString('latin1', pos, Math.min(pos + h.len, pos + 64)))) { pos = n; continue; } // frame de cabeçalho VBR (traz a duração total)
    }
    if (pvDur < maxSec) { if (pvStart < 0) pvStart = pos; pvEnd = n; pvDur += h.dur; }
    total += h.dur; frames++; pos = n;
  }
  if (frames < 20) return null;
  return { duration: total, preview: buf.subarray(pvStart, pvEnd) };
}
function coverType(b) {
  if (b.length > 12 && b[0] === 0xFF && b[1] === 0xD8 && b[2] === 0xFF) return 'image/jpeg';
  if (b.length > 12 && b.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]))) return 'image/png';
  if (b.length > 12 && b.toString('latin1', 0, 4) === 'RIFF' && b.toString('latin1', 8, 12) === 'WEBP') return 'image/webp';
  return null;
}
function cleanText(v, max, min) {
  if (typeof v !== 'string') return null;
  const s = v.replace(/[\u0000-\u001f\u007f]/g, '').trim();
  return s.length >= (min || 0) && s.length <= max ? s : null;
}
function downloadName(song) {
  const base = (song.artist + ' - ' + song.title).replace(/[\\/:*?"<>|\u0000-\u001f]/g, '_').slice(0, 120) + '.mp3';
  const ascii = base.replace(/[^\x20-\x7e]/g, '_');
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(base).replace(/['()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase())}`;
}

/* ---------- API ---------- */
async function api(req, res, p) {
  const m = req.method, ip = clientIp(req), vid = visitor(req, res);
  if (m !== 'GET' && m !== 'HEAD') {
    if (req.headers['x-requested-with'] !== 'enter') return err(res, 403, 'Pedido inválido.');
    const o = req.headers.origin;
    if (o) { try { if (new URL(o).host !== req.headers.host) return err(res, 403, 'Origem não permitida.'); } catch { return err(res, 403, 'Origem inválida.'); } }
    if (!limit('w:' + ip, 90, 60000)) return err(res, 429, 'Demasiados pedidos. Espera um momento.');
  }

  if (p === '/api/songs' && m === 'GET') {
    purge();
    const s = session(req), vh = sha(vid).slice(0, 16);
    const list = songs.slice().sort((a, b) => b.createdAt - a.createdAt).map(x => ({
      id: x.id, title: x.title, artist: x.artist, category: x.category, createdAt: x.createdAt, expiresAt: x.expiresAt,
      duration: Math.round(x.duration), hasCover: !!x.ctype, previewUsed: !!(prev[x.id] && prev[x.id].includes(vh))
    }));
    return json(res, 200, { admin: !!s, name: s ? s.name : null, previewSeconds: PREVIEW_SECONDS, now: Date.now(), songs: list });
  }

  if (p === '/api/login' && m === 'POST') {
    await adminReady;
    if (blocked('lg:' + ip, 5) || blocked('lg:all', 100)) return err(res, 429, 'Demasiadas tentativas. Tenta novamente mais tarde.');
    const b = await readJSONBody(req);
    const name = String(b.name || '').trim().toLowerCase().slice(0, 100), pw = String(b.password || '').slice(0, 200);
    const h = await scrypt(pw, ADMIN_SALT);
    const okPw = crypto.timingSafeEqual(h, ADMIN_HASH), okName = safeEq(name, ADD_NAME);
    if (!(okPw && okName)) { fail('lg:' + ip, 15 * 60 * 1000); fail('lg:all', 3600 * 1000); await sleep(500); return err(res, 401, 'Nome ou palavra-passe incorretos.'); }
    const sid = crypto.randomBytes(32).toString('base64url');
    sessions.set(sid, { name: ADD_NAME, exp: Date.now() + 8 * 3600 * 1000 });
    setCookie(req, res, 'ens', sid, { maxAge: 8 * 3600, sameSite: 'Strict' });
    return json(res, 200, { ok: true, name: ADD_NAME });
  }
  if (p === '/api/logout' && m === 'POST') {
    const sid = cookies(req).ens; if (sid) sessions.delete(sid);
    setCookie(req, res, 'ens', '', { maxAge: 0, sameSite: 'Strict' });
    return json(res, 200, { ok: true });
  }

  if (p === '/api/songs' && m === 'POST') {            // adicionar música (só o add)
    const s = session(req);
    if (!s || s.name !== ADD_NAME) return err(res, 401, 'Entra como "' + ADD_NAME + '" para adicionar músicas.', 'auth');
    purge();
    if (songs.length >= MAX_SONGS) return err(res, 409, 'Limite de músicas atingido. Elimina alguma antes de adicionar.');
    if (!limit('up:' + s.name, 20, 3600 * 1000)) return err(res, 429, 'Muitos envios seguidos. Tenta mais tarde.');
    const cl = +req.headers['content-length'];
    if (!cl) return err(res, 411, 'Pedido inválido.');
    if (cl > MAX_TOTAL) { res.setHeader('Connection', 'close'); return err(res, 413, 'Ficheiro demasiado grande (máx. ' + Math.round(MAX_AUDIO / 1048576) + ' MB).'); }
    const buf = await readBody(req, MAX_TOTAL);
    const bad = () => err(res, 400, 'Pedido inválido.');
    if (buf.length < 12) return bad();
    const mlen = buf.readUInt32BE(0);
    if (mlen > 4096 || 8 + mlen > buf.length) return bad();
    let meta; try { meta = JSON.parse(buf.subarray(4, 4 + mlen).toString('utf8')); } catch { return bad(); }
    let off = 4 + mlen; const clen = buf.readUInt32BE(off); off += 4;
    if (clen > MAX_COVER) return err(res, 413, 'Capa demasiado grande.');
    if (off + clen >= buf.length) return bad();
    const cover = buf.subarray(off, off + clen), audio = buf.subarray(off + clen);
    if (audio.length > MAX_AUDIO) return err(res, 413, 'Ficheiro demasiado grande (máx. ' + Math.round(MAX_AUDIO / 1048576) + ' MB).');
    const title = cleanText(meta && meta.title, 90, 1), artist = cleanText((meta && meta.artist) || 'Artista desconhecido', 90, 1),
      category = cleanText((meta && meta.category) || 'Música', 40, 1), code = typeof (meta && meta.code) === 'string' ? meta.code : '';
    if (!title || !artist || !category) return err(res, 400, 'Verifica o nome, o artista e a categoria.');
    if (code.length < 6 || code.length > 64) return err(res, 400, 'O código deve ter entre 6 e 64 caracteres.');
    const info = analyzeMp3(audio, PREVIEW_SECONDS);
    if (!info) return err(res, 415, 'O ficheiro não é um MP3 válido.');
    let ctype = null;
    if (cover.length) { ctype = coverType(cover); if (!ctype) return err(res, 415, 'A capa deve ser JPG, PNG ou WebP.'); }
    const id = crypto.randomBytes(9).toString('base64url'), codeHash = await hashCode(code), now = Date.now();
    try {
      fs.writeFileSync(fAudio(id), audio); fs.writeFileSync(fPrev(id), info.preview);
      if (ctype) fs.writeFileSync(fCover(id), cover);
    } catch (e) { removeFiles(id); throw e; }
    songs.push({ id, title, artist, category, codeHash, ctype, duration: info.duration, addedBy: s.name, createdAt: now, expiresAt: now + TTL_MS });
    saveSongs();
    return json(res, 201, { ok: true, id });
  }

  if (p.startsWith('/api/stream/') && (m === 'GET' || m === 'HEAD')) {
    const t = tokens.get(p.slice(12));
    if (!t || t.exp < Date.now() || t.vid !== vid) return err(res, 404, 'Ligação expirada.');
    if (++t.hits > t.max) return err(res, 403, 'Ligação expirada.');
    purge();
    const song = songs.find(x => x.id === t.id);
    if (!song) return err(res, 404, 'Esta música já não está disponível.');
    const extra = { 'Cache-Control': 'private, no-store' };
    if (t.kind === 'download') extra['Content-Disposition'] = downloadName(song);
    return sendFile(req, res, t.kind === 'preview' ? fPrev(song.id) : fAudio(song.id), 'audio/mpeg', extra);
  }

  const ms = /^\/api\/songs\/([A-Za-z0-9_-]{12})(?:\/(cover|preview|unlock))?$/.exec(p);
  if (!ms) return err(res, 404, 'Não encontrado.');
  purge();
  const id = ms[1], sub = ms[2], song = songs.find(x => x.id === id);
  if (!song) return err(res, 404, 'Esta música já não está disponível.');

  if (sub === 'cover' && (m === 'GET' || m === 'HEAD')) {
    if (!song.ctype) return err(res, 404, 'Sem capa.');
    return sendFile(req, res, fCover(id), song.ctype, { 'Cache-Control': 'public, max-age=300' });
  }

  if (sub === 'preview' && m === 'POST') {             // prévia de 30 s: só uma vez por pessoa/dispositivo
    if (!limit('pv:' + ip, 40, 600000)) return err(res, 429, 'Muitos pedidos. Tenta mais tarde.');
    const vh = sha(vid).slice(0, 16), arr = prev[id] || (prev[id] = []);
    if (arr.includes(vh)) return err(res, 409, 'Já ouviste a prévia desta música.', 'preview_used');
    arr.push(vh); savePrev();
    return json(res, 200, { url: '/api/stream/' + mkToken({ id, kind: 'preview', vid, ttl: 5 * 60000, max: 30 }), seconds: PREVIEW_SECONDS });
  }

  if (sub === 'unlock' && m === 'POST') {              // código certo => música completa + download
    const b = await readJSONBody(req), s = session(req);
    if (!(s && s.name === song.addedBy)) {
      const code = typeof b.code === 'string' ? b.code : '';
      const k1 = 'u:' + ip + ':' + id, k2 = 'ua:' + ip, k3 = 'us:' + id;
      if (blocked(k1, 5) || blocked(k2, 20) || blocked(k3, 30)) return err(res, 429, 'Demasiadas tentativas. Tenta mais tarde.');
      if (code.length < 1 || code.length > 64 || !(await checkCode(code, song.codeHash))) {
        fail(k1, 15 * 60000); fail(k2, 15 * 60000); fail(k3, 3600000);
        await sleep(400);
        return err(res, 403, 'Código incorreto.');
      }
      buckets.delete(k1);
    }
    return json(res, 200, {
      stream: '/api/stream/' + mkToken({ id, kind: 'full', vid, ttl: 60 * 60000, max: 400 }),
      download: '/api/stream/' + mkToken({ id, kind: 'download', vid, ttl: 2 * 60000, max: 3 })
    });
  }

  if (!sub && m === 'DELETE') {                        // o add elimina só o que adicionou
    const s = session(req);
    if (!s) return err(res, 401, 'Entra como "' + ADD_NAME + '" para eliminar.', 'auth');
    if (s.name !== song.addedBy) return err(res, 403, 'Só podes eliminar músicas que tu adicionaste.');
    removeSong(id);
    return json(res, 200, { ok: true });
  }

  return err(res, 405, 'Método não permitido.');
}

/* ---------- ficheiros estáticos ---------- */
const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.json': 'application/manifest+json', '.svg': 'image/svg+xml', '.png': 'image/png' };
const STATIC = {};
for (const f of fs.readdirSync(PUB)) {
  const ext = path.extname(f), body = fs.readFileSync(path.join(PUB, f));
  STATIC['/' + f] = { body, type: MIME[ext] || 'application/octet-stream', cache: ext === '.png' || ext === '.svg' ? 'public, max-age=86400' : 'no-cache' };
}
STATIC['/'] = STATIC['/index.html'];
function serveStatic(req, res, p) {
  if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405, { Allow: 'GET, HEAD' }); return res.end(); }
  const f = Object.prototype.hasOwnProperty.call(STATIC, p) ? STATIC[p] : null;
  if (!f) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('Não encontrado'); }
  res.writeHead(200, { 'Content-Type': f.type, 'Content-Length': f.body.length, 'Cache-Control': f.cache });
  res.end(req.method === 'HEAD' ? undefined : f.body);
}

/* ---------- servidor ---------- */
const server = http.createServer(async (req, res) => {
  try {
    secHeaders(req, res);
    const p = new URL(req.url, 'http://x').pathname;
    if (p.startsWith('/api/')) return await api(req, res, p);
    return serveStatic(req, res, p);
  } catch (e) {
    if (!e.status) console.error(e);
    if (!res.headersSent) err(res, e.status || 500, e.status ? e.message : 'Erro interno.'); else res.end();
  }
});
server.headersTimeout = 15000; server.requestTimeout = 300000; server.keepAliveTimeout = 5000;
server.listen(PORT, () => console.log(`ENTER online na porta ${PORT} — add: "${ADD_NAME}" — músicas duram ${TTL_MS / 3600000} h`));
function bye() { try { if (prevTimer) writeJSON(F_PREV, prev); } catch { } process.exit(0); }
process.on('SIGTERM', bye); process.on('SIGINT', bye);
