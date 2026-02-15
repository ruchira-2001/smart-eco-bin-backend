import { pool } from "../_db.js";
import { applyCors } from "../_cors.js";

export default async function handler(req, res) {
  if (applyCors(req, res)) return;

  try {
    if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

    const { binCode, reporterName, reporterContact, description } = req.body || {};
    if (!binCode || !description) return res.status(400).json({ error: "binCode and description are required" });

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

    res.status(200).json({ ok: true, message: "Complaint submitted" });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
}
