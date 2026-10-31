const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const path = require("path");

const app = express();

app.use(express.json({ limit: "2mb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("localhost")
    ? false
    : { rejectUnauthorized: false }
});

const SECRET = process.env.JWT_SECRET;

if (!process.env.DATABASE_URL || !SECRET || SECRET.length < 32) {
  console.error("DATABASE_URL or valid JWT_SECRET missing");
  process.exit(1);
}

const loginLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false
});

async function initDB() {
  await pool.query(`CREATE SCHEMA IF NOT EXISTS pp`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS pp.cms_content (
      id SERIAL PRIMARY KEY,
      section VARCHAR(50) NOT NULL,
      title TEXT NOT NULL,
      description TEXT DEFAULT '',
      image TEXT DEFAULT '',
      extra TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS pp.cms_messages (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      phone TEXT DEFAULT '',
      message TEXT NOT NULL,
      status VARCHAR(30) DEFAULT 'Pending',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS pp.cms_settings (
      key TEXT PRIMARY KEY,
      value TEXT DEFAULT ''
    )
  `);

  console.log("CMS database ready");
}

function adminOnly(req, res, next) {
  try {
    const token = req.cookies.panduwa_token;
    if (!token) return res.status(401).json({ error: "Login required" });

    const data = jwt.verify(token, SECRET);
    if (data.role !== "admin") {
      return res.status(403).json({ error: "Admin only" });
    }

    req.admin = data;
    next();
  } catch {
    res.status(401).json({ error: "Please login again" });
  }
}

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, database: "connected" });
  } catch {
    res.status(500).json({ ok: false, database: "error" });
  }
});

/* ADMIN LOGIN */

app.post("/api/admin/login", loginLimit, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (
      !email ||
      !password ||
      email.toLowerCase() !==
        (process.env.ADMIN_EMAIL || "").toLowerCase() ||
      password !== process.env.ADMIN_PASSWORD
    ) {
      return res.status(401).json({ error: "Wrong email or password" });
    }

    const token = jwt.sign(
      { role: "admin", email },
      SECRET,
      { expiresIn: "7d" }
    );

    res.cookie("panduwa_token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({ success: true });
  } catch {
    res.status(500).json({ error: "Login failed" });
  }
});

app.post("/api/admin/logout", (req, res) => {
  res.clearCookie("panduwa_token");
  res.json({ success: true });
});

app.get("/api/admin/me", adminOnly, (req, res) => {
  res.json({ email: req.admin.email, role: "admin" });
});

/* PUBLIC CONTENT */

app.get("/api/content", async (req, res) => {
  try {
    const section = req.query.section;

    let result;

    if (section) {
      result = await pool.query(
        `SELECT * FROM pp.cms_content
         WHERE section=$1 ORDER BY created_at DESC`,
        [section]
      );
    } else {
      result = await pool.query(
        `SELECT * FROM pp.cms_content ORDER BY created_at DESC`
      );
    }

    res.json({ items: result.rows });
  } catch {
    res.status(500).json({ error: "Could not load content" });
  }
});

/* ADMIN ADD CONTENT */

app.post("/api/admin/content", adminOnly, async (req, res) => {
  try {
    const { section, title, description, image, extra } = req.body;

    const allowed = [
      "news", "notice", "gallery", "development",
      "members", "services", "schemes", "about"
    ];

    if (!allowed.includes(section) || !title?.trim()) {
      return res.status(400).json({ error: "Invalid information" });
    }

    const result = await pool.query(
      `INSERT INTO pp.cms_content
       (section,title,description,image,extra)
       VALUES($1,$2,$3,$4,$5) RETURNING *`,
      [
        section,
        title.trim(),
        description || "",
        image || "",
        extra || ""
      ]
    );

    res.json({ success: true, item: result.rows[0] });
  } catch {
    res.status(500).json({ error: "Could not save content" });
  }
});

/* ADMIN EDIT CONTENT */

app.put("/api/admin/content/:id", adminOnly, async (req, res) => {
  try {
    const { title, description, image, extra } = req.body;

    const result = await pool.query(
      `UPDATE pp.cms_content
       SET title=$1, description=$2, image=$3, extra=$4
       WHERE id=$5 RETURNING *`,
      [
        title,
        description || "",
        image || "",
        extra || "",
        req.params.id
      ]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: "Not found" });
    }

    res.json({ success: true, item: result.rows[0] });
  } catch {
    res.status(500).json({ error: "Update failed" });
  }
});

/* ADMIN DELETE CONTENT */

app.delete("/api/admin/content/:id", adminOnly, async (req, res) => {
  try {
    await pool.query(
      "DELETE FROM pp.cms_content WHERE id=$1",
      [req.params.id]
    );

    res.json({ success: true });
  } catch {
    res.status(500).json({ error: "Delete failed" });
  }
});

/* PUBLIC COMPLAINT FORM */

app.post("/api/messages", async (req, res) => {
  try {
    const { name, phone, message } = req.body;

    if (
      !name?.trim() ||
      !message?.trim() ||
      name.length > 100 ||
      message.length > 3000 ||
      (phone && phone.length > 20)
    ) {
      return res.status(400).json({ error: "Please check your details" });
    }

    await pool.query(
      `INSERT INTO pp.cms_messages(name,phone,message)
       VALUES($1,$2,$3)`,
      [name.trim(), phone || "", message.trim()]
    );

    res.json({ success: true, message: "Message submitted" });
  } catch {
    res.status(500).json({ error: "Message could not be saved" });
  }
});

/* ADMIN VIEW MESSAGES */

app.get("/api/admin/messages", adminOnly, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM pp.cms_messages ORDER BY created_at DESC"
    );

    res.json({ items: result.rows });
  } catch {
    res.status(500).json({ error: "Could not load messages" });
  }
});

/* ADMIN UPDATE MESSAGE STATUS */

app.put("/api/admin/messages/:id", adminOnly, async (req, res) => {
  try {
    const { status } = req.body;

    if (!["Pending", "In Progress", "Completed"].includes(status)) {
      return res.status(400).json({ error: "Invalid status" });
    }

    await pool.query(
      "UPDATE pp.cms_messages SET status=$1 WHERE id=$2",
      [status, req.params.id]
    );

    res.json({ success: true });
  } catch {
    res.status(500).json({ error: "Status update failed" });
  }
});

/* ADMIN DASHBOARD STATS */

app.get("/api/admin/stats", adminOnly, async (req, res) => {
  try {
    const content = await pool.query(
      "SELECT section, COUNT(*)::int AS total FROM pp.cms_content GROUP BY section"
    );

    const messages = await pool.query(
      "SELECT COUNT(*)::int AS total FROM pp.cms_messages"
    );

    res.json({
      content: content.rows,
      messages: messages.rows[0].total
    });
  } catch {
    res.status(500).json({ error: "Stats failed" });
  }
});

/* SETTINGS */

app.get("/api/settings", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM pp.cms_settings");
    const settings = {};

    result.rows.forEach(row => {
      settings[row.key] = row.value;
    });

    res.json(settings);
  } catch {
    res.status(500).json({ error: "Settings failed" });
  }
});

app.put("/api/admin/settings", adminOnly, async (req, res) => {
  try {
    const allowed = ["panchayat_name", "phone", "whatsapp", "address"];

    for (const key of allowed) {
      if (req.body[key] !== undefined) {
        await pool.query(
          `INSERT INTO pp.cms_settings(key,value)
           VALUES($1,$2)
           ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value`,
          [key, String(req.body[key]).slice(0, 500)]
        );
      }
    }

    res.json({ success: true });
  } catch {
    res.status(500).json({ error: "Settings update failed" });
  }
});

/* WEBSITE */

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

const PORT = process.env.PORT || 10000;

initDB()
  .then(() => {
    app.listen(PORT, () => {
      console.log("Panduwa website running on port " + PORT);
    });
  })
  .catch(err => {
    console.error("Database startup failed:", err);
    process.exit(1);
  });
