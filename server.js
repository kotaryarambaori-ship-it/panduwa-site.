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
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// सुरक्षा: Render में ये Environment Variables जरूर सेट करें।
const DB = process.env.DATABASE_URL;
const SECRET = process.env.JWT_SECRET;
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const ADMIN_NAME = process.env.ADMIN_NAME || "Raju Prasad Pradhan";

if (!DB) throw new Error("DATABASE_URL missing");
if (!SECRET || SECRET.length < 32) {
  throw new Error("JWT_SECRET missing or too short. Use a random secret of at least 32 characters.");
}
if (!ADMIN_EMAIL || !ADMIN_PASSWORD || ADMIN_PASSWORD.length < 8) {
  throw new Error("Set ADMIN_EMAIL and ADMIN_PASSWORD (minimum 8 characters)");
}

const pool = new Pool({
  connectionString: DB,
  ssl: /localhost|127\.0\.0\.1/.test(DB)
    ? false
    : { rejectUnauthorized: false }
});

const q = (sql, values) => pool.query(sql, values);

const wrap = fn => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(err => {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  });

const clean = (v, n = 2000) =>
  String(v ?? "").trim().slice(0, n);

const sign = user =>
  jwt.sign(
    { id: user.id, role: user.role },
    SECRET,
    { expiresIn: "7d" }
  );

function setCookie(res, token) {
  res.cookie("tk", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
}

app.use((req, res, next) => {
  try {
    req.user = jwt.verify(req.cookies.tk, SECRET);
  } catch {
    req.user = null;
  }
  next();
});

const need = (req, res, next) =>
  req.user ? next() : res.status(401).json({ error: "Pehle login karo" });

const admin = (req, res, next) =>
  req.user?.role === "admin"
    ? next()
    : res.status(403).json({ error: "Sirf admin ke liye" });

const authLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { error: "Bahut koshish hui. Baad mein try karein." }
});

// Database setup
async function init() {
  await q("CREATE SCHEMA IF NOT EXISTS pp");

  await q(`
    CREATE TABLE IF NOT EXISTS pp.users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      pass TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS pp.posts (
      id SERIAL PRIMARY KEY,
      type TEXT NOT NULL CHECK (type IN ('news','notice','project')),
      title TEXT NOT NULL,
      title_hi TEXT,
      body TEXT,
      body_hi TEXT,
      status TEXT,
      image_url TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS pp.gallery (
      id SERIAL PRIMARY KEY,
      url TEXT NOT NULL,
      caption TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS pp.complaints (
      id SERIAL PRIMARY KEY,
      user_id INT REFERENCES pp.users(id) ON DELETE SET NULL,
      name TEXT NOT NULL,
      mobile TEXT NOT NULL,
      subject TEXT NOT NULL,
      details TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // Create admin securely from Render environment variables.
  const email = ADMIN_EMAIL;
  const hash = await bcrypt.hash(ADMIN_PASSWORD, 12);

  await q(`
    INSERT INTO pp.users (name, email, pass, role)
    VALUES ($1, $2, $3, 'admin')
    ON CONFLICT (email)
    DO UPDATE SET role = 'admin'
  `, [ADMIN_NAME, email, hash]);

  console.log("Database ready");
}

// Static files and homepage
app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Health
app.get("/api/health", wrap(async (req, res) => {
  await q("SELECT 1");
  res.json({ ok: true, db: "connected" });
}));

// Register
app.post("/api/auth/register", authLimit, wrap(async (req, res) => {
  const name = clean(req.body.name, 100);
  const email = clean(req.body.email, 150).toLowerCase();
  const password = String(req.body.password || "");

  if (!name || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: "Sahi naam aur email dalein" });
  }

  if (password.length < 6 || password.length > 100) {
    return res.status(400).json({ error: "Password 6 se 100 characters ka hona chahiye" });
  }

  const hash = await bcrypt.hash(password, 12);

  try {
    const r = await q(`
      INSERT INTO pp.users(name,email,pass,role)
      VALUES($1,$2,$3,'user')
      RETURNING id,name,email,role
    `, [name, email, hash]);

    setCookie(res, sign(r.rows[0]));
    res.json({ user: r.rows[0] });
  } catch (e) {
    if (e.code === "23505") {
      return res.status(409).json({ error: "Ye email pehle se registered hai" });
    }
    throw e;
  }
}));

// Login
app.post("/api/auth/login", authLimit, wrap(async (req, res) => {
  const email = clean(req.body.email, 150).toLowerCase();
  const password = String(req.body.password || "");

  const r = await q(
    "SELECT * FROM pp.users WHERE email=$1",
    [email]
  );

  const user = r.rows[0];

  if (!user || !(await bcrypt.compare(password, user.pass))) {
    return res.status(401).json({ error: "Email ya password galat hai" });
  }

  setCookie(res, sign(user));

  res.json({
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role
    }
  });
}));

// Logout
app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("tk", { path: "/" });
  res.json({ ok: true });
});

// Current user
app.get("/api/me", need, wrap(async (req, res) => {
  const r = await q(
    "SELECT id,name,email,role FROM pp.users WHERE id=$1",
    [req.user.id]
  );

  if (!r.rows[0]) return res.status(401).json({ error: "User nahi mila" });

  res.json({ user: r.rows[0] });
}));

// Update profile
app.put("/api/me", need, wrap(async (req, res) => {
  const name = clean(req.body.name, 100);
  if (!name) return res.status(400).json({ error: "Naam zaroori hai" });

  const r = await q(
    "UPDATE pp.users SET name=$1 WHERE id=$2 RETURNING id,name,email,role",
    [name, req.user.id]
  );

  res.json({ user: r.rows[0] });
}));

// Change password
app.put("/api/me/password", need, wrap(async (req, res) => {
  const oldpass = String(req.body.oldpass || "");
  const newpass = String(req.body.newpass || "");

  const r = await q("SELECT pass FROM pp.users WHERE id=$1", [req.user.id]);

  if (!r.rows[0] || !(await bcrypt.compare(oldpass, r.rows[0].pass))) {
    return res.status(400).json({ error: "Purana password galat hai" });
  }

  if (newpass.length < 6 || newpass.length > 100) {
    return res.status(400).json({ error: "Naya password 6 se 100 characters ka hona chahiye" });
  }

  const hash = await bcrypt.hash(newpass, 12);

  await q("UPDATE pp.users SET pass=$1 WHERE id=$2", [hash, req.user.id]);

  res.json({ ok: true });
}));

// Public posts
app.get("/api/posts", wrap(async (req, res) => {
  const type = ["news", "notice", "project"].includes(req.query.type)
    ? req.query.type
    : null;

  const page = Math.max(1, Math.min(1000, Number(req.query.page) || 1));
  const limit = 10;
  const offset = (page - 1) * limit;
  const search = clean(req.query.q, 100);

  const r = await q(`
    SELECT * FROM pp.posts
    WHERE ($1::text IS NULL OR type=$1)
    AND (
      $2::text = ''
      OR title ILIKE '%' || $2 || '%'
      OR title_hi ILIKE '%' || $2 || '%'
      OR body ILIKE '%' || $2 || '%'
      OR body_hi ILIKE '%' || $2 || '%'
    )
    ORDER BY created_at DESC
    LIMIT $3 OFFSET $4
  `, [type, search, limit + 1, offset]);

  res.json({
    items: r.rows.slice(0, limit),
    more: r.rows.length > limit
  });
}));

// Admin: add post
app.post("/api/admin/posts", need, admin, wrap(async (req, res) => {
  const type = clean(req.body.type, 20);
  const title = clean(req.body.title, 200);

  if (!["news", "notice", "project"].includes(type) || !title) {
    return res.status(400).json({ error: "Sahi type aur title dalein" });
  }

  const image = clean(req.body.image_url, 1000);
  if (image && !/^https?:\/\//i.test(image)) {
    return res.status(400).json({ error: "Photo link http ya https hona chahiye" });
  }

  const r = await q(`
    INSERT INTO pp.posts(type,title,title_hi,body,body_hi,status,image_url)
    VALUES($1,$2,$3,$4,$5,$6,$7)
    RETURNING *
  `, [
    type,
    title,
    clean(req.body.title_hi, 200),
    clean(req.body.body, 5000),
    clean(req.body.body_hi, 5000),
    clean(req.body.status, 50),
    image || null
  ]);

  res.json({ item: r.rows[0] });
}));

// Admin: edit post
app.put("/api/admin/posts/:id", need, admin, wrap(async (req, res) => {
  const r = await q(`
    UPDATE pp.posts SET
      type=$1,title=$2,title_hi=$3,body=$4,body_hi=$5,
      status=$6,image_url=$7
    WHERE id=$8 RETURNING *
  `, [
    clean(req.body.type, 20),
    clean(req.body.title, 200),
    clean(req.body.title_hi, 200),
    clean(req.body.body, 5000),
    clean(req.body.body_hi, 5000),
    clean(req.body.status, 50),
    clean(req.body.image_url, 1000) || null,
    req.params.id
  ]);

  if (!r.rows[0]) return res.status(404).json({ error: "Post nahi mila" });
  res.json({ item: r.rows[0] });
}));

// Admin: delete post
app.delete("/api/admin/posts/:id", need, admin, wrap(async (req, res) => {
  await q("DELETE FROM pp.posts WHERE id=$1", [req.params.id]);
  res.json({ ok: true });
}));

// Gallery
app.get("/api/gallery", wrap(async (req, res) => {
  const r = await q("SELECT * FROM pp.gallery ORDER BY created_at DESC");
  res.json({ items: r.rows });
}));

app.post("/api/admin/gallery", need, admin, wrap(async (req, res) => {
  const url = clean(req.body.url, 1000);
  if (!/^https?:\/\//i.test(url)) {
    return res.status(400).json({ error: "Sahi photo URL dalein" });
  }

  const r = await q(
    "INSERT INTO pp.gallery(url,caption) VALUES($1,$2) RETURNING *",
    [url, clean(req.body.caption, 200)]
  );

  res.json({ item: r.rows[0] });
}));

app.delete("/api/admin/gallery/:id", need, admin, wrap(async (req, res) => {
  await q("DELETE FROM pp.gallery WHERE id=$1", [req.params.id]);
  res.json({ ok: true });
}));

// Complaints
app.post("/api/complaints", wrap(async (req, res) => {
  const name = clean(req.body.name, 100);
  const mobile = clean(req.body.mobile, 10);
  const subject = clean(req.body.subject, 200);
  const details = clean(req.body.details, 3000);

  if (!name || !/^[0-9]{10}$/.test(mobile) || !subject || !details) {
    return res.status(400).json({ error: "Sabhi details sahi bharein" });
  }

  const r = await q(`
    INSERT INTO pp.complaints(user_id,name,mobile,subject,details)
    VALUES($1,$2,$3,$4,$5)
    RETURNING id
  `, [req.user?.id || null, name, mobile, subject, details]);

  res.json({ ok: true, id: r.rows[0].id });
}));

app.get("/api/complaints/mine", need, wrap(async (req, res) => {
  const r = await q(`
    SELECT * FROM pp.complaints
    WHERE user_id=$1 ORDER BY created_at DESC
  `, [req.user.id]);

  res.json({ items: r.rows });
}));

// Admin statistics
app.get("/api/admin/stats", need, admin, wrap(async (req, res) => {
  const r = await q(`
    SELECT
      (SELECT COUNT(*) FROM pp.users) AS users,
      (SELECT COUNT(*) FROM pp.complaints) AS total,
      (SELECT COUNT(*) FROM pp.complaints WHERE status='pending') AS pending,
      (SELECT COUNT(*) FROM pp.complaints WHERE status='resolved') AS resolved
  `);

  const s = r.rows[0];
  res.json({
    users: Number(s.users),
    total: Number(s.total),
    pending: Number(s.pending),
    resolved: Number(s.resolved)
  });
}));

// Admin complaints
app.get("/api/admin/complaints", need, admin, wrap(async (req, res) => {
  const r = await q("SELECT * FROM pp.complaints ORDER BY created_at DESC");
  res.json({ items: r.rows });
}));

app.put("/api/admin/complaints/:id", need, admin, wrap(async (req, res) => {
  const status = clean(req.body.status, 30);

  if (!["pending", "in_progress", "resolved"].includes(status)) {
    return res.status(400).json({ error: "Galat status" });
  }

  const r = await q(
    "UPDATE pp.complaints SET status=$1 WHERE id=$2 RETURNING *",
    [status, req.params.id]
  );

  if (!r.rows[0]) return res.status(404).json({ error: "Complaint nahi mili" });

  res.json({ item: r.rows[0] });
}));

// Admin users
app.get("/api/admin/users", need, admin, wrap(async (req, res) => {
  const r = await q(`
    SELECT id,name,email,role,created_at
    FROM pp.users ORDER BY created_at DESC
  `);

  res.json({ items: r.rows });
}));

app.delete("/api/admin/users/:id", need, admin, wrap(async (req, res) => {
  if (Number(req.params.id) === Number(req.user.id)) {
    return res.status(400).json({ error: "Apna admin account delete nahi kar sakte" });
  }

  await q("DELETE FROM pp.users WHERE id=$1", [req.params.id]);
  res.json({ ok: true });
}));

// Not found
app.use((req, res) => {
  res.status(404).json({ error: "Page nahi mila" });
});

const PORT = process.env.PORT || 5000;

init()
  .then(() => {
    app.listen(PORT, () => console.log("Server running on " + PORT));
  })
  .catch(err => {
    console.error("Startup error:", err);
    process.exit(1);
  });
