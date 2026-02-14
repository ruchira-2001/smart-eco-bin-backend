import express from "express";
import cors from "cors";
import mysql from "mysql2/promise";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import crypto from "crypto";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// ✅ DB pool (TiDB Cloud uses TLS)
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT),
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  ssl: { rejectUnauthorized: true },
});

// ---------- helpers ----------
function makeActivationToken() {
  // token format: ACT_<id>.<secret>
  const id = crypto.randomBytes(6).toString("hex"); // 12 chars
  const secret = crypto.randomBytes(24).toString("base64url");
  return { id, token: `ACT_${id}.${secret}` };
}

async function getUserByCode(user_code) {
  const [rows] = await pool.query(
    "SELECT * FROM users WHERE user_code = ? LIMIT 1",
    [user_code]
  );
  return rows[0] || null;
}

// ---------- health ----------
app.get("/health", async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT 1 AS ok");
    res.json({ ok: true, db: rows[0].ok });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e.message || e) });
  }
});

// ---------- ADMIN: generate activation token for a TECHxxx ----------
/**
 * POST /admin/tech/:techCode/generate-activation
 * returns an activation link that can be turned into a QR code in admin UI
 */
app.post("/admin/tech/:techCode/generate-activation", async (req, res) => {
  try {
    const techCode = req.params.techCode;

    const user = await getUserByCode(techCode);
    if (!user) return res.status(404).json({ error: "Technician not found" });
    if (user.role !== "TECHNICIAN")
      return res.status(400).json({ error: "Not a technician" });

    if (user.status === "ACTIVE") {
      return res.status(400).json({ error: "Technician already active" });
    }

    const { id, token } = makeActivationToken();
    const tokenHash = await bcrypt.hash(token, 10);

    await pool.query(
      `UPDATE users
       SET activation_token_id = ?,
           activation_token_hash = ?,
           activation_expires_at = DATE_ADD(NOW(), INTERVAL 24 HOUR)
       WHERE user_id = ?`,
      [id, tokenHash, user.user_id]
    );

    const activationLink = `${req.protocol}://${req.get(
      "host"
    )}/activate?token=${encodeURIComponent(token)}`;

    res.json({
      techCode,
      activationLink,
      expiresHours: 24,
      note: "Generate QR from activationLink and share privately with technician.",
    });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

// ---------- TECHNICIAN: activate account by token + set password ----------
/**
 * POST /auth/activate
 * body: { token, newPassword }
 */
app.post("/auth/activate", async (req, res) => {
  try {
    const { token, newPassword } = req.body || {};
    if (!token || !newPassword) {
      return res
        .status(400)
        .json({ error: "token and newPassword are required" });
    }

    // token format: ACT_<id>.<secret>
    const parts = String(token).split(".");
    if (parts.length !== 2 || !parts[0].startsWith("ACT_")) {
      return res.status(400).json({ error: "Invalid token format" });
    }
    const tokenId = parts[0].replace("ACT_", "");

    const [rows] = await pool.query(
      `SELECT user_id, user_code, activation_token_hash, activation_expires_at, status
       FROM users
       WHERE role='TECHNICIAN'
         AND activation_token_id = ?
         AND activation_token_hash IS NOT NULL
         AND activation_expires_at IS NOT NULL
         AND activation_expires_at > NOW()
       LIMIT 1`,
      [tokenId]
    );

    if (rows.length === 0) {
      return res.status(400).json({ error: "Invalid or expired token" });
    }

    const match = rows[0];

    // Optional: prevent activating suspended accounts
    if (match.status === "SUSPENDED") {
      return res.status(403).json({ error: "Account is SUSPENDED" });
    }

    const ok = await bcrypt.compare(token, match.activation_token_hash);
    if (!ok) {
      return res.status(400).json({ error: "Invalid or expired token" });
    }

    const passwordHash = await bcrypt.hash(newPassword, 10);

    await pool.query(
      `UPDATE users
       SET password_hash = ?,
           status='ACTIVE',
           activation_token_id = NULL,
           activation_token_hash = NULL,
           activation_expires_at = NULL
       WHERE user_id = ?`,
      [passwordHash, match.user_id]
    );

    res.json({
      ok: true,
      techCode: match.user_code,
      message: "Account activated. You can now login.",
    });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

// ---------- TECH LOGIN ----------
/**
 * POST /auth/login
 * body: { userCode, password }
 */
app.post("/auth/login", async (req, res) => {
  try {
    const { userCode, password } = req.body || {};
    if (!userCode || !password) {
      return res
        .status(400)
        .json({ error: "userCode and password are required" });
    }

    const user = await getUserByCode(userCode);
    if (!user) return res.status(404).json({ error: "User not found" });

    if (user.role !== "TECHNICIAN") {
      return res.status(403).json({ error: "Not a technician account" });
    }
    if (user.status !== "ACTIVE") {
      return res.status(403).json({ error: `Account is ${user.status}` });
    }
    if (!user.password_hash) {
      return res.status(403).json({ error: "Account not activated" });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Invalid password" });

    // simple token placeholder (upgrade to JWT later)
    const sessionToken = crypto.randomBytes(24).toString("base64url");

    res.json({
      ok: true,
      techCode: user.user_code,
      fullName: user.full_name,
      sessionToken,
    });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

// ---------- TECH DASHBOARD ----------
/**
 * GET /tech/dashboard/:techCode
 */
app.get("/tech/dashboard/:techCode", async (req, res) => {
  try {
    const techCode = req.params.techCode;

    const tech = await getUserByCode(techCode);
    if (!tech) return res.status(404).json({ error: "Technician not found" });
    if (tech.role !== "TECHNICIAN")
      return res.status(400).json({ error: "Not a technician" });
    if (tech.status !== "ACTIVE")
      return res.status(403).json({ error: `Account is ${tech.status}` });

    const [asgRows] = await pool.query(
      `SELECT bin_id
       FROM bin_assignments
       WHERE technician_user_id = ? AND is_active = 1
       LIMIT 1`,
      [tech.user_id]
    );

    if (asgRows.length === 0) {
      return res
        .status(404)
        .json({ error: "No active bin assignment found" });
    }

    const binId = asgRows[0].bin_id;

    const [binRows] = await pool.query(
      `SELECT bin_id, bin_code, location_name, specification_area, status, public_complaint_url
       FROM waste_bins
       WHERE bin_id = ?
       LIMIT 1`,
      [binId]
    );

    const bin = binRows[0];

    const [containers] = await pool.query(
      `SELECT container_id, container_code, capacity_l, current_weight_g, particle_count, updated_at
       FROM containers
       WHERE bin_id = ?
       ORDER BY container_code ASC`,
      [binId]
    );

    const [alerts] = await pool.query(
      `SELECT alert_id, container_id, alert_type, severity, message, status, created_at, resolved_at
       FROM alerts
       WHERE bin_id = ?
       ORDER BY created_at DESC
       LIMIT 20`,
      [binId]
    );

    const [complaints] = await pool.query(
      `SELECT complaint_id, reporter_name, reporter_contact, description, status, created_at
       FROM public_complaints
       WHERE bin_id = ?
       ORDER BY created_at DESC
       LIMIT 20`,
      [binId]
    );

    res.json({
      ok: true,
      technician: { userCode: tech.user_code, fullName: tech.full_name },
      bin,
      containers,
      alerts,
      complaints,
    });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

// ---------- PUBLIC: submit complaint ----------
/**
 * POST /public/complaints
 * body: { binCode, reporterName, reporterContact, description }
 */
app.post("/public/complaints", async (req, res) => {
  try {
    const { binCode, reporterName, reporterContact, description } = req.body || {};
    if (!binCode || !description) {
      return res
        .status(400)
        .json({ error: "binCode and description are required" });
    }

    const [bins] = await pool.query(
      "SELECT bin_id FROM waste_bins WHERE bin_code = ? LIMIT 1",
      [binCode]
    );
    if (bins.length === 0) return res.status(404).json({ error: "Bin not found" });

    await pool.query(
      `INSERT INTO public_complaints (bin_id, reporter_name, reporter_contact, description)
       VALUES (?, ?, ?, ?)`,
      [bins[0].bin_id, reporterName || null, reporterContact || null, description]
    );

    res.json({ ok: true, message: "Complaint submitted" });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

const PORT = process.env.PORT || 3000;
// ✅ listen on all interfaces so phone can connect
app.listen(PORT, "0.0.0.0", () => console.log(`API running on port ${PORT}`));
