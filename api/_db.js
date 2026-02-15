import mysql from "mysql2/promise";

export const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT || 4000),
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,

  // TiDB Cloud over TLS
  ssl: { rejectUnauthorized: true },

  waitForConnections: true,
  connectionLimit: 5,
  queueLimit: 0,
});
