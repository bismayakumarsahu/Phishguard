const express = require("express");
const cors = require("cors");
const path = require("path");
const fs = require("fs");

const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("./database");

const {
    analyzeURL,
    analyzeEmail
} = require("./heuristics");

const app = express();
const PORT = 3001;

const JWT_SECRET =
    process.env.JWT_SECRET ||
    "phishguard-development-secret-change-later";

// ============================================
// DATA STORAGE
// ============================================

const DATA_DIR = path.join(__dirname, "data");
const HISTORY_FILE = path.join(
    DATA_DIR,
    "scan-history.json"
);


// Create data folder if it doesn't exist

if (!fs.existsSync(DATA_DIR)) {

    fs.mkdirSync(DATA_DIR, {
        recursive: true
    });

}


// Create history file if it doesn't exist

if (!fs.existsSync(HISTORY_FILE)) {

    fs.writeFileSync(
        HISTORY_FILE,
        JSON.stringify([], null, 2)
    );

}


// ============================================
// HISTORY FUNCTIONS
// ============================================

function readHistory() {

    try {

        const data =
            fs.readFileSync(
                HISTORY_FILE,
                "utf8"
            );

        return JSON.parse(data);

    } catch (error) {

        console.error(
            "Could not read scan history:",
            error
        );

        return [];

    }

}


function saveHistory(history) {

    try {

        fs.writeFileSync(
            HISTORY_FILE,
            JSON.stringify(
                history,
                null,
                2
            )
        );

    } catch (error) {

        console.error(
            "Could not save scan history:",
            error
        );

    }

}


function addHistory(record) {

    const history =
        readHistory();

    history.unshift(record);

    // Keep latest 1000 scans

    if (history.length > 1000) {

        history.length = 1000;

    }

    saveHistory(history);

}


// ============================================
// MIDDLEWARE
// ============================================

app.use(cors());

app.use(express.json());


// ============================================
// SERVE FRONTEND
// ============================================

app.use(
    express.static(
        path.join(
            __dirname,
            "../frontend"
        )
    )
);


// ============================================
// HOME PAGE
// ============================================

app.get("/", (req, res) => {

    res.sendFile(
        path.join(
            __dirname,
            "../frontend/index.html"
        )
    );

});


// ============================================
// API HEALTH CHECK
// ============================================

app.get(
    "/api/status",
    (req, res) => {

        res.json({

            status: "online",

            service:
                "PhishGuard API",

            version:
                "1.0.0"

        });

    }
);


// ============================================
// URL SCANNER API
// ============================================

app.post(
    "/api/scan-url",
    (req, res) => {

        try {

            const {
                url
            } = req.body;


            // Validate URL

            if (
                !url ||
                typeof url !== "string"
            ) {

                return res.status(400).json({

                    success: false,

                    error:
                        "A valid URL is required."

                });

            }


            // Analyze URL

            const result =
                analyzeURL(url);


            // Save scan

            addHistory({

                id:
                    Date.now().toString(),

                type:
                    "url",

                target:
                    url,

                score:
                    result.score,

                level:
                    result.level,

                status:
                    result.status,

                flags:
                    result.flags || [],

                timestamp:
                    new Date().toISOString()

            });


            // Return result

            res.json({

                success: true,

                url: url,

                result: result

            });


        } catch (error) {

            console.error(
                "URL scan error:",
                error
            );


            res.status(500).json({

                success: false,

                error:
                    "Internal server error."

            });

        }

    }
);


// ============================================
// EMAIL ANALYZER API
// ============================================

app.post(
    "/api/analyze-email",
    (req, res) => {

        try {

            const {

                senderName,

                senderEmail,

                replyTo,

                subject,

                body

            } = req.body;


            // Analyze email

            const result =
                analyzeEmail({

                    senderName,

                    senderEmail,

                    replyTo,

                    subject,

                    body

                });


            // Save email scan

            addHistory({

                id:
                    Date.now().toString(),

                type:
                    "email",

                target:
                    senderEmail ||
                    "Unknown sender",

                subject:
                    subject ||
                    "",

                score:
                    result.score,

                level:
                    result.level,

                status:
                    result.status,

                flags:
                    result.flags || [],

                timestamp:
                    new Date().toISOString()

            });


            // Return result

            res.json({

                success: true,

                result: result

            });


        } catch (error) {

            console.error(
                "Email analysis error:",
                error
            );


            res.status(500).json({

                success: false,

                error:
                    "Email analysis failed."

            });

        }

    }
);


// ============================================
// SCAN STATISTICS API
// ============================================

app.get(
    "/api/stats",
    (req, res) => {

        try {

            const history =
                readHistory();


            const totalScans =
                history.length;


            const urlScans =
                history.filter(
                    item =>
                        item.type === "url"
                ).length;


            const emailScans =
                history.filter(
                    item =>
                        item.type === "email"
                ).length;


            const safeScans =
                history.filter(
                    item =>
                        Number(item.score) < 35
                ).length;


            const suspiciousScans =
                history.filter(
                    item =>
                        Number(item.score) >= 35 &&
                        Number(item.score) < 70
                ).length;


            const dangerousScans =
                history.filter(
                    item =>
                        Number(item.score) >= 70
                ).length;


            const threatsDetected =
                suspiciousScans +
                dangerousScans;


            const protectionRate =
                totalScans > 0
                    ? Math.round(
                        (
                            safeScans /
                            totalScans
                        ) * 100
                    )
                    : 100;


            res.json({

                success: true,

                stats: {

                    totalScans,

                    urlScans,

                    emailScans,

                    safeScans,

                    suspiciousScans,

                    dangerousScans,

                    threatsDetected,

                    protectionRate

                }

            });


        } catch (error) {

            console.error(
                "Stats error:",
                error
            );


            res.status(500).json({

                success: false,

                error:
                    "Unable to load statistics."

            });

        }

    }
);


// ============================================
// SCAN HISTORY API
// ============================================

app.get(
    "/api/history",
    (req, res) => {

        try {

            const history =
                readHistory();


            const limit =
                Math.min(
                    Number(req.query.limit) || 50,
                    100
                );


            res.json({

                success: true,

                count:
                    history.length,

                history:
                    history.slice(
                        0,
                        limit
                    )

            });


        } catch (error) {

            console.error(
                "History error:",
                error
            );


            res.status(500).json({

                success: false,

                error:
                    "Unable to load scan history."

            });

        }

    }
);


// ============================================
// CLEAR HISTORY
// ============================================

app.delete(
    "/api/history",
    (req, res) => {

        try {

            saveHistory([]);

            res.json({

                success: true,

                message:
                    "Scan history cleared."

            });

        } catch (error) {

            console.error(
                "Clear history error:",
                error
            );


            res.status(500).json({

                success: false,

                error:
                    "Unable to clear history."

            });

        }

    }
);

// ============================================
// REGISTER API
// ============================================

app.post(
    "/api/auth/register",
    async (req, res) => {

        try {

            const {
                name,
                email,
                password
            } = req.body;


            // Validate name

            if (
                !name ||
                typeof name !== "string" ||
                name.trim().length < 2
            ) {

                return res.status(400).json({

                    success: false,

                    error:
                        "Name must contain at least 2 characters."

                });

            }


            // Validate email

            if (
                !email ||
                typeof email !== "string"
            ) {

                return res.status(400).json({

                    success: false,

                    error:
                        "A valid email is required."

                });

            }


            const normalizedEmail =
                email.trim().toLowerCase();


            const emailPattern =
                /^[^\s@]+@[^\s@]+\.[^\s@]+$/;


            if (
                !emailPattern.test(
                    normalizedEmail
                )
            ) {

                return res.status(400).json({

                    success: false,

                    error:
                        "Please enter a valid email address."

                });

            }


            // Validate password

            if (
                !password ||
                typeof password !== "string" ||
                password.length < 6
            ) {

                return res.status(400).json({

                    success: false,

                    error:
                        "Password must contain at least 6 characters."

                });

            }


            // Check existing user

            const existingUser =
                db.prepare(
                    "SELECT id FROM users WHERE email = ?"
                ).get(
                    normalizedEmail
                );


            if (existingUser) {

                return res.status(409).json({

                    success: false,

                    error:
                        "An account with this email already exists."

                });

            }


            // Hash password

            const passwordHash =
                await bcrypt.hash(
                    password,
                    12
                );


            // Create user

            const insertUser =
                db.prepare(`
                    INSERT INTO users
                    (
                        name,
                        email,
                        password
                    )
                    VALUES
                    (
                        ?,
                        ?,
                        ?
                    )
                `);


            const result =
                insertUser.run(
                    name.trim(),
                    normalizedEmail,
                    passwordHash
                );


            res.status(201).json({

                success: true,

                message:
                    "Account created successfully.",

                user: {

                    id:
                        result.lastInsertRowid,

                    name:
                        name.trim(),

                    email:
                        normalizedEmail

                }

            });


        } catch (error) {

            console.error(
                "Registration error:",
                error
            );


            res.status(500).json({

                success: false,

                error:
                    "Registration failed."

            });

        }

    }
);

// ============================================
// LOGIN API
// ============================================

app.post(
    "/api/auth/login",
    async (req, res) => {

        try {

            const {
                email,
                password
            } = req.body;


            // Validate input

            if (
                !email ||
                !password
            ) {

                return res.status(400).json({

                    success: false,

                    error:
                        "Email and password are required."

                });

            }


            const normalizedEmail =
                email.trim().toLowerCase();


            // Find user

            const user =
                db.prepare(
                    `
                    SELECT
                        id,
                        name,
                        email,
                        password
                    FROM users
                    WHERE email = ?
                    `
                ).get(
                    normalizedEmail
                );


            if (!user) {

                return res.status(401).json({

                    success: false,

                    error:
                        "Invalid email or password."

                });

            }


            // Compare password

            const passwordMatch =
                await bcrypt.compare(
                    password,
                    user.password
                );


            if (!passwordMatch) {

                return res.status(401).json({

                    success: false,

                    error:
                        "Invalid email or password."

                });

            }


            // Create JWT

            const token =
                jwt.sign(

                    {
                        userId:
                            user.id,

                        email:
                            user.email

                    },

                    JWT_SECRET,

                    {
                        expiresIn:
                            "7d"
                    }

                );


            // Send response

            res.json({

                success: true,

                message:
                    "Login successful.",

                token: token,

                user: {

                    id:
                        user.id,

                    name:
                        user.name,

                    email:
                        user.email

                }

            });


        } catch (error) {

            console.error(
                "Login error:",
                error
            );


            res.status(500).json({

                success: false,

                error:
                    "Login failed."

            });

        }

    }
);
// ============================================
// 404 API HANDLER
// ============================================

app.use(
    "/api",
    (req, res) => {

        res.status(404).json({

            success: false,

            error:
                "API endpoint not found."

        });

    }
);


// ============================================
// START SERVER
// ============================================

app.listen(
    PORT,
    () => {

        console.log(
            "----------------------------------------"
        );

        console.log(
            "        PHISHGUARD API SERVER"
        );

        console.log(
            "----------------------------------------"
        );

        console.log(
            `Dashboard: http://localhost:${PORT}`
        );

        console.log(
            `API Status: http://localhost:${PORT}/api/status`
        );

        console.log(
            `URL Scanner: POST /api/scan-url`
        );

        console.log(
            `Email Analyzer: POST /api/analyze-email`
        );

        console.log(
            `Statistics: GET /api/stats`
        );

        console.log(
            `History: GET /api/history`
        );

        console.log(
            "----------------------------------------"
        );

    }
);