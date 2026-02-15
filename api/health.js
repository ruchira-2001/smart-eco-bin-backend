import { pool } from "./_db.js";
import { applyCors } from "./_cors.js";

export default async function handler(req, res) {
  if (applyCors(req, res)) return;

  try {
    const [rows] = await pool.query("SELECT 1 AS ok");
    res.status(200).json({ ok: true, db: rows[0].ok });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e.message || e) });
  }
}
