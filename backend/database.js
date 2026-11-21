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
// CYBERGUARD INCIDENTS TABLE
// ============================================

db.exec(`
    CREATE TABLE IF NOT EXISTS incidents (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        type TEXT NOT NULL,

        target TEXT,

        category TEXT,

        risk_score INTEGER,

        risk_level TEXT,

        verdict TEXT,

        evidence TEXT,

        recommended_actions TEXT,

        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP

    );
`);

// ============================================
// AI MODEL RUNS TABLE
// ============================================

db.exec(`
    CREATE TABLE IF NOT EXISTS ai_model_runs (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        model TEXT NOT NULL,

        input_type TEXT NOT NULL,

        score INTEGER,

        category TEXT,

        features TEXT,

        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP

    );
`);

db.getUserByEmail = function getUserByEmail(email) {
    return db.prepare(
        "SELECT id, name, email, password, created_at FROM users WHERE email = ?"
    ).get(email);
};

db.getUserById = function getUserById(id) {
    return db.prepare(
        "SELECT id, name, email, password, created_at FROM users WHERE id = ?"
    ).get(id);
};

db.createUser = function createUser({ name, email, password }) {
    const result = db.prepare(
        "INSERT INTO users (name, email, password) VALUES (?, ?, ?)"
    ).run(name, email, password);

    return db.getUserById(result.lastInsertRowid);
};

// ============================================
// EXPORT
// ============================================

module.exports = db;