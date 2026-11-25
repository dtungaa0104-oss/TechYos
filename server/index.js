// ТехЁс — сурагчдын дүн цуглуулах сервер (Node + Express + Postgres)
// Орчны хувьсагч: DATABASE_URL (заавал), PORT (Render өөрөө өгнө), ALLOWED_ORIGINS (таслалаар, сонголттой)
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { Pool } = require('pg');

const DB = process.env.DATABASE_URL;
if (!DB) { console.error('DATABASE_URL тохируулаагүй байна'); process.exit(1); }
const pool = new Pool({
  connectionString: DB,
  ssl: /localhost|127\.0\.0\.1/.test(DB) ? false : { rejectUnauthorized: false },
  max: 5,
});
const q = (text, params) => pool.query(text, params);

const SCHEMA = `
CREATE TABLE IF NOT EXISTS teachers(
  id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
  pass TEXT NOT NULL, created TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS sessions(
  token TEXT PRIMARY KEY, teacher_id INT REFERENCES teachers(id) ON DELETE CASCADE,
  created TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS classes(
  id SERIAL PRIMARY KEY, teacher_id INT REFERENCES teachers(id) ON DELETE CASCADE,
  code TEXT UNIQUE NOT NULL, name TEXT NOT NULL, subj TEXT NOT NULL, grade INT NOT NULL,
  created TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS students(
  id SERIAL PRIMARY KEY, class_id INT REFERENCES classes(id) ON DELETE CASCADE,
  name TEXT NOT NULL, nkey TEXT NOT NULL, created TIMESTAMPTZ DEFAULT now(),
  UNIQUE(class_id, nkey));
CREATE TABLE IF NOT EXISTS results(
  id SERIAL PRIMARY KEY, student_id INT REFERENCES students(id) ON DELETE CASCADE,
  kind TEXT NOT NULL, ekey TEXT NOT NULL, title TEXT, unit INT, score INT, max INT,
  detail JSONB, created TIMESTAMPTZ DEFAULT now());
CREATE INDEX IF NOT EXISTS results_student ON results(student_id);
CREATE TABLE IF NOT EXISTS prog(
  student_id INT REFERENCES students(id) ON DELETE CASCADE, pid TEXT NOT NULL,
  attempts INT DEFAULT 0, best INT DEFAULT 0, total INT DEFAULT 0, solved_at TIMESTAMPTZ,
  updated TIMESTAMPTZ DEFAULT now(), PRIMARY KEY(student_id, pid));
`;

const app = express();
app.set('trust proxy', 1);
const allowed = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({ origin: allowed.length ? allowed : true }));
app.use(express.json({ limit: '200kb' }));

// --- энгийн хурд хязгаарлагч (IP тус бүрээр) ---
const hits = new Map();
function limit(max, windowMs) {
  return (req, res, next) => {
    const k = req.ip + '|' + max, now = Date.now();
    const h = hits.get(k) || { n: 0, t: now };
    if (now - h.t > windowMs) { h.n = 0; h.t = now; }
    h.n++; hits.set(k, h);
    if (h.n > max) return res.status(429).json({ error: 'Хэт олон хүсэлт. Түр хүлээгээд дахин оролдоно уу.' });
    next();
  };
}
setInterval(() => { const now = Date.now(); for (const [k, h] of hits) if (now - h.t > 600000) hits.delete(k); }, 300000).unref();

// --- туслах функцууд ---
const str = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
const int = (v, lo, hi) => { const n = Number.parseInt(v, 10); return Number.isFinite(n) && n >= lo && n <= hi ? n : null; };
const nkey = name => name.toLocaleLowerCase('mn').replace(/\s+/g, ' ').trim();
const bad = (res, msg, code = 400) => res.status(code).json({ error: msg });
function hashPass(p) {
  const salt = crypto.randomBytes(16).toString('hex');
  return salt + ':' + crypto.scryptSync(p, salt, 64).toString('hex');
}
function checkPass(p, stored) {
  const [salt, h] = String(stored).split(':');
  if (!salt || !h) return false;
  const a = Buffer.from(h, 'hex'), b = crypto.scryptSync(p, salt, 64);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
async function newSession(tid) {
  const token = crypto.randomBytes(32).toString('hex');
  await q('INSERT INTO sessions(token, teacher_id) VALUES($1,$2)', [token, tid]);
  return token;
}
async function auth(req, res, next) {
  const m = /^Bearer ([a-f0-9]{64})$/.exec(req.get('authorization') || '');
  if (!m) return bad(res, 'Нэвтрээгүй байна', 401);
  const r = await q('SELECT t.id, t.name, t.email FROM sessions s JOIN teachers t ON t.id=s.teacher_id WHERE s.token=$1', [m[1]]);
  if (!r.rows[0]) return bad(res, 'Нэвтрэх хугацаа дууссан. Дахин нэвтэрнэ үү.', 401);
  req.teacher = r.rows[0]; req.token = m[1]; next();
}
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
async function newCode() {
  for (let i = 0; i < 20; i++) {
    const c = String(crypto.randomInt(100000, 1000000));
    const r = await q('SELECT 1 FROM classes WHERE code=$1', [c]);
    if (!r.rows[0]) return c;
  }
  throw new Error('Код үүсгэж чадсангүй');
}
async function classByCode(code) {
  const c = str(code, 6);
  if (!/^\d{6}$/.test(c)) return null;
  const r = await q('SELECT id, name, subj, grade FROM classes WHERE code=$1', [c]);
  return r.rows[0] || null;
}
async function studentFor(classId, name) {
  const k = nkey(name);
  const r = await q(`INSERT INTO students(class_id, name, nkey) VALUES($1,$2,$3)
    ON CONFLICT(class_id, nkey) DO UPDATE SET name=students.name RETURNING id`, [classId, name.replace(/\s+/g, ' '), k]);
  return r.rows[0].id;
}

// --- эрүүл мэнд ---
app.get('/', (req, res) => res.type('text').send('ТехЁс API ажиллаж байна'));
app.get('/api/health', wrap(async (req, res) => { await q('SELECT 1'); res.json({ ok: true }); }));

// --- багш ---
app.post('/api/teacher/register', limit(10, 60000), wrap(async (req, res) => {
  const name = str(req.body.name, 80), email = str(req.body.email, 120).toLowerCase(), pass = typeof req.body.password === 'string' ? req.body.password : '';
  if (!name) return bad(res, 'Нэрээ оруулна уу');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return bad(res, 'Имэйл хаяг буруу байна');
  if (pass.length < 8 || pass.length > 200) return bad(res, 'Нууц үг дор хаяж 8 тэмдэгт байна');
  const ex = await q('SELECT 1 FROM teachers WHERE email=$1', [email]);
  if (ex.rows[0]) return bad(res, 'Энэ имэйлээр бүртгэл үүссэн байна. Нэвтэрнэ үү.');
  const r = await q('INSERT INTO teachers(email, name, pass) VALUES($1,$2,$3) RETURNING id', [email, name, hashPass(pass)]);
  res.json({ token: await newSession(r.rows[0].id), name, email });
}));
app.post('/api/teacher/login', limit(10, 60000), wrap(async (req, res) => {
  const email = str(req.body.email, 120).toLowerCase(), pass = typeof req.body.password === 'string' ? req.body.password : '';
  const r = await q('SELECT id, name, pass FROM teachers WHERE email=$1', [email]);
  const t = r.rows[0];
  if (!t || !checkPass(pass, t.pass)) return bad(res, 'Имэйл эсвэл нууц үг буруу байна', 401);
  res.json({ token: await newSession(t.id), name: t.name, email });
}));
app.post('/api/teacher/logout', wrap(auth), wrap(async (req, res) => {
  await q('DELETE FROM sessions WHERE token=$1', [req.token]); res.json({ ok: true });
}));
app.get('/api/me', wrap(auth), (req, res) => res.json({ name: req.teacher.name, email: req.teacher.email }));

// --- анги ---
app.get('/api/classes', wrap(auth), wrap(async (req, res) => {
  const r = await q(`SELECT c.id, c.code, c.name, c.subj, c.grade, c.created,
      (SELECT count(*) FROM students s WHERE s.class_id=c.id)::int AS students
    FROM classes c WHERE c.teacher_id=$1 ORDER BY c.created DESC`, [req.teacher.id]);
  res.json(r.rows);
}));
app.post('/api/classes', wrap(auth), limit(30, 60000), wrap(async (req, res) => {
  const name = str(req.body.name, 60), subj = req.body.subj === 'ie' ? 'ie' : 'mt', grade = int(req.body.grade, 6, 12);
  if (!name) return bad(res, 'Ангийн нэр оруулна уу');
  if (grade === null) return bad(res, 'Анги 6–12 байна');
  const code = await newCode();
  const r = await q('INSERT INTO classes(teacher_id, code, name, subj, grade) VALUES($1,$2,$3,$4,$5) RETURNING id, code, name, subj, grade',
    [req.teacher.id, code, name, subj, grade]);
  res.json(r.rows[0]);
}));
async function ownClass(req, res) {
  const id = int(req.params.id, 1, 2e9);
  const r = id && await q('SELECT id, code, name, subj, grade FROM classes WHERE id=$1 AND teacher_id=$2', [id, req.teacher.id]);
  if (!r || !r.rows[0]) { bad(res, 'Анги олдсонгүй', 404); return null; }
  return r.rows[0];
}
app.delete('/api/classes/:id', wrap(auth), wrap(async (req, res) => {
  const c = await ownClass(req, res); if (!c) return;
  await q('DELETE FROM classes WHERE id=$1', [c.id]); res.json({ ok: true });
}));
app.get('/api/classes/:id/report', wrap(auth), wrap(async (req, res) => {
  const c = await ownClass(req, res); if (!c) return;
  const st = await q('SELECT id, name, created FROM students WHERE class_id=$1 ORDER BY nkey', [c.id]);
  const rs = await q(`SELECT r.id, r.student_id, r.kind, r.ekey, r.title, r.unit, r.score, r.max, r.detail, r.created
    FROM results r JOIN students s ON s.id=r.student_id WHERE s.class_id=$1 ORDER BY r.created`, [c.id]);
  const pg = await q(`SELECT p.student_id, p.pid, p.attempts, p.best, p.total, p.solved_at
    FROM prog p JOIN students s ON s.id=p.student_id WHERE s.class_id=$1`, [c.id]);
  res.json({ class: c, students: st.rows, results: rs.rows, prog: pg.rows });
}));
app.delete('/api/students/:id', wrap(auth), wrap(async (req, res) => {
  const id = int(req.params.id, 1, 2e9);
  const r = id && await q('DELETE FROM students s USING classes c WHERE s.id=$1 AND s.class_id=c.id AND c.teacher_id=$2 RETURNING s.id', [id, req.teacher.id]);
  if (!r || !r.rows[0]) return bad(res, 'Сурагч олдсонгүй', 404);
  res.json({ ok: true });
}));
app.delete('/api/results/:id', wrap(auth), wrap(async (req, res) => {
  const id = int(req.params.id, 1, 2e9);
  const r = id && await q(`DELETE FROM results r USING students s, classes c
    WHERE r.id=$1 AND r.student_id=s.id AND s.class_id=c.id AND c.teacher_id=$2 RETURNING r.id`, [id, req.teacher.id]);
  if (!r || !r.rows[0]) return bad(res, 'Дүн олдсонгүй', 404);
  res.json({ ok: true });
}));

// --- сурагч (нэвтрэлтгүй, ангийн кодоор) ---
app.get('/api/class/:code', limit(60, 60000), wrap(async (req, res) => {
  const c = await classByCode(req.params.code);
  if (!c) return bad(res, 'Ангийн код олдсонгүй', 404);
  res.json({ name: c.name, subj: c.subj, grade: c.grade });
}));
app.post('/api/submit', limit(30, 60000), wrap(async (req, res) => {
  const c = await classByCode(req.body.code); if (!c) return bad(res, 'Ангийн код олдсонгүй', 404);
  const name = str(req.body.name, 60); if (name.length < 2) return bad(res, 'Нэрээ бүтэн оруулна уу');
  const kind = req.body.kind === 'gu' ? 'gu' : 'unit';
  const ekey = str(req.body.key, 400); if (!ekey) return bad(res, 'Үнэлгээний түлхүүр алга');
  const score = int(req.body.score, 0, 1000), max = int(req.body.max, 0, 1000);
  if (score === null || max === null || score > max) return bad(res, 'Оноо буруу байна');
  let detail = req.body.detail && typeof req.body.detail === 'object' ? req.body.detail : null;
  if (detail && JSON.stringify(detail).length > 100000) detail = null;
  const sid = await studentFor(c.id, name);
  const r = await q('INSERT INTO results(student_id, kind, ekey, title, unit, score, max, detail) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id',
    [sid, kind, ekey, str(req.body.title, 200), int(req.body.unit, 0, 100), score, max, detail]);
  res.json({ ok: true, id: r.rows[0].id, class: c.name });
}));
app.post('/api/prog', limit(120, 60000), wrap(async (req, res) => {
  const c = await classByCode(req.body.code); if (!c) return bad(res, 'Ангийн код олдсонгүй', 404);
  const name = str(req.body.name, 60); if (name.length < 2) return bad(res, 'Нэрээ бүтэн оруулна уу');
  const pid = str(req.body.pid, 20); if (!/^p\d{1,3}$/.test(pid)) return bad(res, 'Бодлогын дугаар буруу');
  const passed = int(req.body.passed, 0, 1000) || 0, total = int(req.body.total, 0, 1000) || 0, ok = !!req.body.ok && total > 0 && passed === total;
  const sid = await studentFor(c.id, name);
  await q(`INSERT INTO prog(student_id, pid, attempts, best, total, solved_at) VALUES($1,$2,1,$3,$4,${ok ? 'now()' : 'NULL'})
    ON CONFLICT(student_id, pid) DO UPDATE SET attempts=prog.attempts+1, best=GREATEST(prog.best, EXCLUDED.best),
      total=EXCLUDED.total, solved_at=COALESCE(prog.solved_at, EXCLUDED.solved_at), updated=now()`, [sid, pid, passed, total]);
  res.json({ ok: true, class: c.name });
}));

app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: 'Серверийн алдаа' }); });

(async () => {
  await q(SCHEMA);
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log('ТехЁс API: ' + port));
})().catch(e => { console.error(e); process.exit(1); });
