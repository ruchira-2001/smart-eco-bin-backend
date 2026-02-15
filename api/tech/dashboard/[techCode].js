import { pool } from "../../../_db.js";
import { applyCors } from "../../../_cors.js";

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
    if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });

    const techCode = req.query.techCode;

    const tech = await getUserByCode(techCode);
    if (!tech) return res.status(404).json({ error: "Technician not found" });
    if (tech.role !== "TECHNICIAN") return res.status(400).json({ error: "Not a technician" });
    if (tech.status !== "ACTIVE") return res.status(403).json({ error: `Account is ${tech.status}` });

    const [asgRows] = await pool.query(
      `SELECT bin_id FROM bin_assignments WHERE technician_user_id = ? AND is_active = 1 LIMIT 1`,
      [tech.user_id]
    );

    if (asgRows.length === 0) return res.status(404).json({ error: "No active bin assignment found" });

    const binId = asgRows[0].bin_id;

    const [binRows] = await pool.query(
      `SELECT bin_id, bin_code, location_name, specification_area, status, public_complaint_url
       FROM waste_bins WHERE bin_id = ? LIMIT 1`,
      [binId]
    );

    const [containers] = await pool.query(
      `SELECT container_id, container_code, capacity_l, current_weight_g, particle_count, updated_at
       FROM containers WHERE bin_id = ? ORDER BY container_code ASC`,
      [binId]
    );

    const [alerts] = await pool.query(
      `SELECT alert_id, container_id, alert_type, severity, message, status, created_at, resolved_at
       FROM alerts WHERE bin_id = ? ORDER BY created_at DESC LIMIT 20`,
      [binId]
    );

    const [complaints] = await pool.query(
      `SELECT complaint_id, reporter_name, reporter_contact, description, status, created_at
       FROM public_complaints WHERE bin_id = ? ORDER BY created_at DESC LIMIT 20`,
      [binId]
    );

    res.status(200).json({
      ok: true,
      technician: { userCode: tech.user_code, fullName: tech.full_name },
      bin: binRows[0] || null,
      containers,
      alerts,
      complaints
    });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
}
