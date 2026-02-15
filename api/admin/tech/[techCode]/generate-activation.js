import crypto from "crypto";
import bcrypt from "bcryptjs";
import { pool } from "../../../../_db.js";
import { applyCors } from "../../../../_cors.js";

function makeActivationToken() {
  const id = crypto.randomBytes(6).toString("hex");
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

export default async function handler(req, res) {
  if (applyCors(req, res)) return;

  try {
    if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

    const techCode = req.query.techCode;

    const user = await getUserByCode(techCode);
    if (!user) return res.status(404).json({ error: "Technician not found" });
    if (user.role !== "TECHNICIAN") return res.status(400).json({ error: "Not a technician" });
    if (user.status === "ACTIVE") return res.status(400).json({ error: "Technician already active" });

    const { id, token } = makeActivationToken();
    const tokenHash = await bcrypt.hash(token, 10);

    await pool.query(
      `UPDATE users
       SET activation_token_id = ?, activation_token_hash = ?, activation_expires_at = DATE_ADD(NOW(), INTERVAL 24 HOUR)
       WHERE user_id = ?`,
      [id, tokenHash, user.user_id]
    );

    const host = req.headers["x-forwarded-host"] || req.headers.host;
    const proto = (req.headers["x-forwarded-proto"] || "https").split(",")[0].trim();
    const activationLink = `${proto}://${host}/activate?token=${encodeURIComponent(token)}`;

    res.status(200).json({ ok: true, techCode, activationLink, expiresHours: 24 });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
}
