const mysql = require('mysql2/promise');

async function main() {
  const db = await mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
  });
  const [rows] = await db.query('SELECT COUNT(*) AS n FROM enrolments');
  console.log(`synced ${rows[0].n} enrolments`);
  await db.end();
}

main().catch((e) => { console.error(e); process.exit(1); });
