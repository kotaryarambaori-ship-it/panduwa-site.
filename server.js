const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const path = require("path");

const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: "100kb" }));
app.use(cookieParser());

const DB = process.env.DATABASE_URL;
const SECRET = process.env.JWT_SECRET || "change-this-secret";
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").toLowerCase();
const PROD = process.env.NODE_ENV === "production";
const pool = new Pool({
  connectionString: DB,
  ssl: DB && !/localhost|127\.0\.0\.1/.test(DB) ? { rejectUnauthorized: false } : false,
});
pool.on("connect", (c) => c.query("set search_path to pp"));

async function init() {
  await pool.query("create schema if not exists pp");
  await pool.query(`
    create table if not exists users(
      id serial primary key, name text not null,
      email text unique not null, pass text not null,
      role text not null default 'user', created_at timestamptz default now());
    create table if not exists posts(
      id serial primary key,
      type text not null check (type in ('news','notice','project')),
      title text not null, title_hi text, body text, body_hi text,
      status text, image_url text, created_at timestamptz default now());
    create table if not exists gallery(
      id serial primary key, url text not null, caption text,
      created_at timestamptz default now());
    create table if not exists complaints(
      id serial primary key,
      user_id int references users(id) on delete set null,
      name text not null, mobile text not null,
      subject text not null, details text not null,
      status text not null default 'pending',
      created_at timestamptz default now());
  `);
}

const s = (v, n) => String(v == null ? "" : v).trim().slice(0, n);
const sign = (u) => jwt.sign({ id: u.id, role: u.role }, SECRET, { expiresIn: "7d" });
const setCookie = (res, t) =>
  res.cookie("tk", t, { httpOnly: true, sameSite: "lax", secure: PROD, maxAge: 7 * 24 * 3600 * 1000 });
const wrap = (fn) => (req, res) =>
  fn(req, res).catch((e) => {
    console.error(req.method, req.path, e.message);
    res.status(500).json({ error: "Server error" });
  });

app.use((req, res, next) => {
  try { req.user = jwt.verify(req.cookies.tk, SECRET); } catch (e) { req.user = null; }
  next();
});
const need = (req, res, next) => (req.user ? next() : res.status(401).json({ error: "Pehle login karo" }));
const admin = (req, res, next) =>
  req.user && req.user.role === "admin" ? next() : res.status(403).json({ error: "Sirf admin" });
const authLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, message: { error: "Bahut koshish, baad me try karo" } });

app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.get("/api/health", wrap(async (req, res) => {
  await pool.query("select 1");
  res.json({ ok: true, db: "connected" });
}));

// ---------- auth ----------
app.post("/api/auth/register", authLimit, wrap(async (req, res) => {
  const name = s(req.body.name, 80), email = s(req.body.email, 120).toLowerCase();
  const pw = String(req.body.password || "");
  if (name.length < 2) return res.status(400).json({ error: "Naam likho" });
  if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: "Sahi email daalo" });
  if (pw.length < 6) return res.status(400).json({ error: "Password 6+ akshar ka ho" });
  try {
    const role = email === ADMIN_EMAIL ? "admin" : "user";
    const r = await pool.query(
      "insert into users(name,email,pass,role) values($1,$2,$3,$4) returning id,name,email,role",
      [name, email, await bcrypt.hash(pw, 10), role]
    );
    setCookie(res, sign(r.rows[0]));
    res.status(201).json({ user: r.rows[0] });
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "Ye email pehle se hai" });
    throw e;
  }
}));

app.post("/api/auth/login", authLimit, wrap(async (req, res) => {
  const email = s(req.body.email, 120).toLowerCase(), pw = String(req.body.password || "");
  const r = await pool.query("select id,name,email,role,pass from users where email=$1", [email]);
  if (!r.rows.length || !(await bcrypt.compare(pw, r.rows[0].pass)))
    return res.status(401).json({ error: "Email ya password galat hai" });
  const u = r.rows[0];
  delete u.pass;
  setCookie(res, sign(u));
  res.json({ user: u });
}));

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("tk");
  res.json({ ok: true });
});

app.get("/api/me", wrap(async (req, res) => {
  if (!req.user) return res.json({ user: null });
  const r = await pool.query("select id,name,email,role from users where id=$1", [req.user.id]);
  res.json({ user: r.rows[0] || null });
}));

app.put("/api/me", need, wrap(async (req, res) => {
  const name = s(req.body.name, 80);
  if (name.length < 2) return res.status(400).json({ error: "Naam likho" });
  const r = await pool.query("update users set name=$1 where id=$2 returning id,name,email,role", [name, req.user.id]);
  res.json({ user: r.rows[0] });
}));

app.put("/api/me/password", need, wrap(async (req, res) => {
  const oldp = String(req.body.oldpass || ""), np = String(req.body.newpass || "");
  if (np.length < 6) return res.status(400).json({ error: "Naya password 6+ akshar ka ho" });
  const r = await pool.query("select pass from users where id=$1", [req.user.id]);
  if (!r.rows.length || !(await bcrypt.compare(oldp, r.rows[0].pass)))
    return res.status(401).json({ error: "Purana password galat hai" });
  await pool.query("update users set pass=$1 where id=$2", [await bcrypt.hash(np, 10), req.user.id]);
  res.json({ ok: true });
}));

// ---------- posts (news / notice / project) ----------
const TYPES = ["news", "notice", "project"];
app.get("/api/posts", wrap(async (req, res) => {
  const type = s(req.query.type, 10), q = s(req.query.q, 50);
  const page = Math.max(1, parseInt(req.query.page, 10) || 1), lim = 6;
  const r = await pool.query(
    "select * from posts where ($1='' or type=$1) and ($2='' or title ilike '%'||$2||'%' or title_hi ilike '%'||$2||'%') order by created_at desc limit $3 offset $4",
    [type, q, lim + 1, (page - 1) * lim]
  );
  res.json({ items: r.rows.slice(0, lim), more: r.rows.length > lim });
}));

function postVals(b) {
  return [s(b.type, 10), s(b.title, 200), s(b.title_hi, 200), s(b.body, 4000), s(b.body_hi, 4000), s(b.status, 20), s(b.image_url, 500)];
}
function postOk(v, res) {
  if (!TYPES.includes(v[0])) { res.status(400).json({ error: "Type galat hai" }); return false; }
  if (!v[1]) { res.status(400).json({ error: "Title likho" }); return false; }
  if (v[6] && !/^https?:\/\//.test(v[6])) { res.status(400).json({ error: "Photo ka link http se shuru ho" }); return false; }
  return true;
}
app.post("/api/admin/posts", need, admin, wrap(async (req, res) => {
  const v = postVals(req.body);
  if (!postOk(v, res)) return;
  const r = await pool.query(
    "insert into posts(type,title,title_hi,body,body_hi,status,image_url) values($1,$2,$3,$4,$5,$6,$7) returning id", v);
  res.status(201).json({ id: r.rows[0].id });
}));
app.put("/api/admin/posts/:id", need, admin, wrap(async (req, res) => {
  const v = postVals(req.body);
  if (!postOk(v, res)) return;
  await pool.query(
    "update posts set type=$1,title=$2,title_hi=$3,body=$4,body_hi=$5,status=$6,image_url=$7 where id=$8",
    [...v, parseInt(req.params.id, 10) || 0]);
  res.json({ ok: true });
}));
app.delete("/api/admin/posts/:id", need, admin, wrap(async (req, res) => {
  await pool.query("delete from posts where id=$1", [parseInt(req.params.id, 10) || 0]);
  res.json({ ok: true });
}));

// ---------- gallery ----------
app.get("/api/gallery", wrap(async (req, res) => {
  const r = await pool.query("select * from gallery order by created_at desc limit 60");
  res.json({ items: r.rows });
}));
app.post("/api/admin/gallery", need, admin, wrap(async (req, res) => {
  const url = s(req.body.url, 500), cap = s(req.body.caption, 200);
  if (!/^https?:\/\//.test(url)) return res.status(400).json({ error: "Photo ka link http se shuru ho" });
  await pool.query("insert into gallery(url,caption) values($1,$2)", [url, cap]);
  res.status(201).json({ ok: true });
}));
app.delete("/api/admin/gallery/:id", need, admin, wrap(async (req, res) => {
  await pool.query("delete from gallery where id=$1", [parseInt(req.params.id, 10) || 0]);
  res.json({ ok: true });
}));

// ---------- complaints ----------
app.post("/api/complaints", wrap(async (req, res) => {
  const v = [s(req.body.name, 80), s(req.body.mobile, 15), s(req.body.subject, 150), s(req.body.details, 2000)];
  if (v[0].length < 2 || !/^\d{10}$/.test(v[1]) || !v[2] || v[3].length < 5)
    return res.status(400).json({ error: "Sab details sahi bharo (mobile 10 ank ka)" });
  await pool.query(
    "insert into complaints(user_id,name,mobile,subject,details) values($1,$2,$3,$4,$5)",
    [req.user ? req.user.id : null, ...v]);
  res.status(201).json({ ok: true });
}));
app.get("/api/complaints/mine", need, wrap(async (req, res) => {
  const r = await pool.query("select id,subject,status,created_at from complaints where user_id=$1 order by id desc limit 50", [req.user.id]);
  res.json({ items: r.rows });
}));

// ---------- admin ----------
app.get("/api/admin/stats", need, admin, wrap(async (req, res) => {
  const r = await pool.query(`select
    (select count(*) from users) as users,
    (select count(*) from complaints) as total,
    (select count(*) from complaints where status='pending') as pending,
    (select count(*) from complaints where status='resolved') as resolved`);
  res.json(r.rows[0]);
}));
app.get("/api/admin/complaints", need, admin, wrap(async (req, res) => {
  const r = await pool.query("select * from complaints order by id desc limit 100");
  res.json({ items: r.rows });
}));
app.put("/api/admin/complaints/:id", need, admin, wrap(async (req, res) => {
  const st = s(req.body.status, 20);
  if (!["pending", "in_progress", "resolved"].includes(st)) return res.status(400).json({ error: "Status galat hai" });
  await pool.query("update complaints set status=$1 where id=$2", [st, parseInt(req.params.id, 10) || 0]);
  res.json({ ok: true });
}));
app.get("/api/admin/users", need, admin, wrap(async (req, res) => {
  const r = await pool.query("select id,name,email,role,created_at from users order by id desc limit 100");
  res.json({ items: r.rows });
}));
app.delete("/api/admin/users/:id", need, admin, wrap(async (req, res) => {
  const id = parseInt(req.params.id, 10) || 0;
  if (id === req.user.id) return res.status(400).json({ error: "Khud ko delete nahi kar sakte" });
  await pool.query("delete from users where id=$1", [id]);
  res.json({ ok: true });
}));

app.use((req, res) =>
  res.status(404).send('<!DOCTYPE html><meta name="viewport" content="width=device-width,initial-scale=1"><body style="font-family:sans-serif;text-align:center;padding:40px"><h1>404</h1><p>Page nahi mila.</p><a href="/">Home</a></body>'));

const PORT = process.env.PORT || 5000;
init()
  .then(() => app.listen(PORT, () => console.log("Server running on " + PORT)))
  .catch((e) => { console.error("DB setup failed:", e.message); process.exit(1); });
