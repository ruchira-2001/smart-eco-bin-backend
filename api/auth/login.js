import bcrypt from "bcryptjs";
import crypto from "crypto";
import { pool } from "../_db.js";
import { applyCors } from "../_cors.js";

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

    const { userCode, password } = req.body || {};
    if (!userCode || !password) return res.status(400).json({ error: "userCode and password are required" });

    const user = await getUserByCode(userCode);
    if (!user) return res.status(404).json({ error: "User not found" });
    if (user.role !== "TECHNICIAN") return res.status(403).json({ error: "Not a technician account" });
    if (user.status !== "ACTIVE") return res.status(403).json({ error: `Account is ${user.status}` });
    if (!user.password_hash) return res.status(403).json({ error: "Account not activated" });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Invalid password" });

    const sessionToken = crypto.randomBytes(24).toString("base64url");

    res.status(200).json({
      ok: true,
      techCode: user.user_code,
      fullName: user.full_name,
      sessionToken
    });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
}
