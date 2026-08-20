const Database = require("better-sqlite3");
const path = require("path");

// ============================================
// DATABASE CONNECTION
// ============================================

const dataDir = path.join(__dirname, "data");

const dbPath = path.join(
    dataDir,
    "phishguard.db"
);

const db = new Database(dbPath);


// ============================================
// DATABASE SETTINGS
// ============================================

db.pragma("journal_mode = WAL");


// ============================================
// USERS TABLE
// ============================================

db.exec(`
    CREATE TABLE IF NOT EXISTS users (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        name TEXT NOT NULL,

        email TEXT NOT NULL UNIQUE,

        password TEXT NOT NULL,

        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP

    );
`);


// ============================================
// SCAN HISTORY TABLE
// ============================================

db.exec(`
    CREATE TABLE IF NOT EXISTS scans (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        user_id INTEGER,

        type TEXT NOT NULL,

        target TEXT,

        subject TEXT,

        score INTEGER,

        level TEXT,

        status TEXT,

        flags TEXT,

        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

        FOREIGN KEY (user_id)
            REFERENCES users(id)

    );
`);


// ============================================
// EXPORT
// ============================================

module.exports = db;