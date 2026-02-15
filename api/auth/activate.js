import bcrypt from "bcryptjs";
import { pool } from "../_db.js";
import { applyCors } from "../_cors.js";

export default async function handler(req, res) {
  if (applyCors(req, res)) return;

  try {
    if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

    const { token, newPassword } = req.body || {};
    if (!token || !newPassword) return res.status(400).json({ error: "token and newPassword are required" });

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

    if (rows.length === 0) return res.status(400).json({ error: "Invalid or expired token" });

    const user = rows[0];
    if (user.status === "SUSPENDED") return res.status(403).json({ error: "Account is SUSPENDED" });

    const ok = await bcrypt.compare(token, user.activation_token_hash);
    if (!ok) return res.status(400).json({ error: "Invalid or expired token" });

    const passwordHash = await bcrypt.hash(newPassword, 10);

    await pool.query(
      `UPDATE users
       SET password_hash = ?, status='ACTIVE',
           activation_token_id = NULL, activation_token_hash = NULL, activation_expires_at = NULL
       WHERE user_id = ?`,
      [passwordHash, user.user_id]
    );

    res.status(200).json({ ok: true, techCode: user.user_code, message: "Account activated. You can now login." });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
}
