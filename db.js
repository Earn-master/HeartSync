const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');

if (!process.env.DATABASE_URL) {
    console.error('FATAL: DATABASE_URL is not set. Add a PostgreSQL database to this Railway project (New -> Database -> PostgreSQL), which sets DATABASE_URL automatically.');
    process.exit(1);
}

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    // Railway's internal Postgres does not require SSL; managed external Postgres providers often do.
    ssl: process.env.DATABASE_SSL === 'true' ? { rejectUnauthorized: false } : false
});

async function runMigrations() {
    const schema = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
    await pool.query(schema);
    console.log('Database schema ready.');
}

module.exports = { pool, runMigrations };
