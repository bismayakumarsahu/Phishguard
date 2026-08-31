// ============================================
// PHISHGUARD API SERVER
// ============================================

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

const {
    evaluateRisk
} = require("./risk-engine");

const {
    checkDomainReputation
} = require("./threat-intel");

const {
    analyzePage
} = require("./behavior-analyzer");


// ============================================
// APP CONFIGURATION
// ============================================

const app = express();

const PORT = 3001;

const JWT_SECRET =
    process.env.JWT_SECRET ||
    "phishguard-development-secret-change-later";


// ============================================
// DATA STORAGE
// ============================================

const DATA_DIR =
    path.join(
        __dirname,
        "data"
    );

const HISTORY_FILE =
    path.join(
        DATA_DIR,
        "scan-history.json"
    );


if (
    !fs.existsSync(DATA_DIR)
) {

    fs.mkdirSync(
        DATA_DIR,
        {
            recursive: true
        }
    );

}


if (
    !fs.existsSync(HISTORY_FILE)
) {

    fs.writeFileSync(
        HISTORY_FILE,
        JSON.stringify(
            [],
            null,
            2
        )
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

        return JSON.parse(
            data
        );

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

    history.unshift(
        record
    );

    if (
        history.length > 1000
    ) {

        history.length = 1000;

    }

    saveHistory(
        history
    );

}


// ============================================
// MIDDLEWARE
// ============================================

app.use(
    cors()
);

app.use(
    express.json(
        {
            limit: "1mb"
        }
    )
);


// ============================================
// FRONTEND
// ============================================

app.use(
    express.static(
        path.join(
            __dirname,
            "../frontend"
        )
    )
);


app.get(
    "/",
    (req, res) => {

        res.sendFile(
            path.join(
                __dirname,
                "../frontend/index.html"
            )
        );

    }
);


// ============================================
// API STATUS
// ============================================

app.get(
    "/api/status",
    (req, res) => {

        res.json({

            status:
                "online",

            service:
                "PhishGuard API",

            version:
                "3.0.0"

        });

    }
);


// ============================================
// HELPER:
// COMBINE URL + THREAT INTELLIGENCE
// ============================================

async function analyzeURLWithIntelligence(
    url
) {

    const heuristicResult =
        analyzeURL(
            url
        );


    let threatResult;


    try {

        threatResult =
            await checkDomainReputation(
                heuristicResult.hostname ||
                heuristicResult.domain
            );

    } catch (error) {

        console.error(
            "Threat intelligence error:",
            error
        );


        threatResult = {

            success:
                false,

            reputation:
                "unknown",

            confidence:
                "low",

            score:
                0,

            evidence: [],

            error:
                error.message

        };

    }


    return {

        heuristicResult,

        threatResult

    };

}


// ============================================
// URL SCANNER
// ============================================

app.post(
    "/api/scan-url",
    async (req, res) => {

        try {

            const {
                url
            } = req.body;


            // --------------------------------
            // Validate
            // --------------------------------

            if (
                !url ||
                typeof url !== "string"
            ) {

                return res.status(
                    400
                ).json({

                    success:
                        false,

                    error:
                        "A valid URL is required."

                });

            }


            // --------------------------------
            // URL + THREAT INTELLIGENCE
            // --------------------------------

            const {

                heuristicResult,

                threatResult

            } =
                await analyzeURLWithIntelligence(
                    url
                );


            // --------------------------------
            // Build threat evidence
            // --------------------------------

            const threatEvidence =
                Array.isArray(
                    threatResult.evidence
                )
                    ? threatResult.evidence
                    : [];


            // --------------------------------
            // Create combined heuristic result
            //
            // Threat intelligence is added as
            // additional evidence.
            // --------------------------------

            const combinedInput = {

                ...heuristicResult,

                flags: [

                    ...(Array.isArray(
                        heuristicResult.flags
                    )
                        ? heuristicResult.flags
                        : []),

                    ...threatEvidence

                ],

                categories: [

                    ...(Array.isArray(
                        heuristicResult.categories
                    )
                        ? heuristicResult.categories
                        : []),

                    ...(threatResult.reputation ===
                        "malicious"
                        ? ["THREAT_INTELLIGENCE"]
                        : []),

                    ...(threatResult.reputation ===
                        "suspicious"
                        ? ["THREAT_INTELLIGENCE"]
                        : [])

                ]

            };


            // --------------------------------
            // RISK ENGINE
            // --------------------------------

            const riskResult =
                evaluateRisk(
                    combinedInput
                );


            // --------------------------------
            // Final result
            // --------------------------------

            const result = {

                ...riskResult,

                flags:
                    riskResult.evidence ||
                    combinedInput.flags ||
                    [],

                threatIntelligence: {

                    reputation:
                        threatResult.reputation,

                    confidence:
                        threatResult.confidence,

                    score:
                        threatResult.score,

                    sources:
                        threatResult.sources ||
                        []

                }

            };


            // --------------------------------
            // History
            // --------------------------------

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

                verdict:
                    result.verdict,

                confidence:
                    result.confidence,

                flags:
                    result.flags,

                categories:
                    result.categories,

                timestamp:
                    new Date().toISOString()

            });


            // --------------------------------
            // Response
            // --------------------------------

            res.json({

                success:
                    true,

                url,

                result

            });


        } catch (error) {

            console.error(
                "URL scan error:",
                error
            );


            res.status(
                500
            ).json({

                success:
                    false,

                error:
                    "Internal server error."

            });

        }

    }
);


// ============================================
// FULL PAGE ANALYSIS
// ============================================
//
// This endpoint accepts page metadata collected
// by the browser extension.
//
// URL-only scanning remains available through
// /api/scan-url.
//

app.post(
    "/api/analyze-page",
    async (req, res) => {

        try {

            const pageData =
                req.body;


            // --------------------------------
            // Validate URL
            // --------------------------------

            if (
                !pageData ||
                typeof pageData.url !==
                    "string"
            ) {

                return res.status(
                    400
                ).json({

                    success:
                        false,

                    error:
                        "Page URL is required."

                });

            }


            // --------------------------------
            // URL analysis
            // --------------------------------

            const {

                heuristicResult,

                threatResult

            } =
                await analyzeURLWithIntelligence(
                    pageData.url
                );


            // --------------------------------
            // PAGE BEHAVIOR
            // --------------------------------

            const behaviorResult =
                analyzePage(
                    pageData
                );


            // --------------------------------
            // Collect all evidence
            // --------------------------------

            const urlFlags =
                Array.isArray(
                    heuristicResult.flags
                )
                    ? heuristicResult.flags
                    : [];


            const threatFlags =
                Array.isArray(
                    threatResult.evidence
                )
                    ? threatResult.evidence
                    : [];


            const behaviorFlags =
                Array.isArray(
                    behaviorResult.signals
                )
                    ? behaviorResult.signals
                    : [];


            // --------------------------------
            // Combined categories
            // --------------------------------

            const categories =
                Array.from(
                    new Set([

                        ...(heuristicResult.categories ||
                            []),

                        ...(behaviorResult.categories ||
                            []),

                        ...(threatResult.reputation ===
                            "malicious"
                            ? ["THREAT_INTELLIGENCE"]
                            : []),

                        ...(threatResult.reputation ===
                            "suspicious"
                            ? ["THREAT_INTELLIGENCE"]
                            : [])

                    ])
                );


            // --------------------------------
            // Combined evidence
            // --------------------------------

            const combinedFlags = [

                ...urlFlags,

                ...threatFlags,

                ...behaviorFlags

            ];


            // --------------------------------
            // Combined input
            // --------------------------------

            const combinedInput = {

                ...heuristicResult,

                score:
                    heuristicResult.score,

                categories,

                flags:
                    combinedFlags

            };


            // --------------------------------
            // FINAL RISK ENGINE
            // --------------------------------

            const riskResult =
                evaluateRisk(
                    combinedInput
                );


            // --------------------------------
            // Final response
            // --------------------------------

            const result = {

                ...riskResult,

                flags:
                    riskResult.evidence ||
                    combinedFlags,

                categories,

                threatIntelligence: {

                    reputation:
                        threatResult.reputation,

                    confidence:
                        threatResult.confidence,

                    score:
                        threatResult.score,

                    sources:
                        threatResult.sources ||
                        []

                },

                behavior: {

                    score:
                        behaviorResult.score,

                    verdict:
                        behaviorResult.verdict,

                    categories:
                        behaviorResult.categories,

                    signals:
                        behaviorResult.signals,

                    metrics:
                        behaviorResult.metrics

                }

            };


            // --------------------------------
            // Save history
            // --------------------------------

            addHistory({

                id:
                    Date.now().toString(),

                type:
                    "page",

                target:
                    pageData.url,

                score:
                    result.score,

                level:
                    result.level,

                status:
                    result.status,

                verdict:
                    result.verdict,

                confidence:
                    result.confidence,

                flags:
                    result.flags,

                categories:
                    result.categories,

                timestamp:
                    new Date().toISOString()

            });


            // --------------------------------
            // Return
            // --------------------------------

            res.json({

                success:
                    true,

                url:
                    pageData.url,

                result

            });


        } catch (error) {

            console.error(
                "Page analysis error:",
                error
            );


            res.status(
                500
            ).json({

                success:
                    false,

                error:
                    "Page analysis failed."

            });

        }

    }
);


// ============================================
// EMAIL ANALYZER
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


            const result =
                analyzeEmail({

                    senderName,

                    senderEmail,

                    replyTo,

                    subject,

                    body

                });


            addHistory({

                id:
                    Date.now().toString(),

                type:
                    "email",

                target:
                    senderEmail ||
                    "Unknown sender",

                subject:
                    subject || "",

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


            res.json({

                success:
                    true,

                result

            });


        } catch (error) {

            console.error(
                "Email analysis error:",
                error
            );


            res.status(
                500
            ).json({

                success:
                    false,

                error:
                    "Email analysis failed."

            });

        }

    }
);


// ============================================
// STATISTICS
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
                        item.type ===
                        "url"
                ).length;


            const pageScans =
                history.filter(
                    item =>
                        item.type ===
                        "page"
                ).length;


            const emailScans =
                history.filter(
                    item =>
                        item.type ===
                        "email"
                ).length;


            const safeScans =
                history.filter(
                    item =>
                        Number(
                            item.score
                        ) < 35
                ).length;


            const suspiciousScans =
                history.filter(
                    item =>
                        Number(
                            item.score
                        ) >= 35 &&
                        Number(
                            item.score
                        ) < 70
                ).length;


            const dangerousScans =
                history.filter(
                    item =>
                        Number(
                            item.score
                        ) >= 70
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

                success:
                    true,

                stats: {

                    totalScans,

                    urlScans,

                    pageScans,

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


            res.status(
                500
            ).json({

                success:
                    false,

                error:
                    "Unable to load statistics."

            });

        }

    }
);


// ============================================
// HISTORY
// ============================================

app.get(
    "/api/history",
    (req, res) => {

        try {

            const history =
                readHistory();


            const requestedLimit =
                Number(
                    req.query.limit
                ) || 50;


            const limit =
                Math.min(
                    requestedLimit,
                    100
                );


            res.json({

                success:
                    true,

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


            res.status(
                500
            ).json({

                success:
                    false,

                error:
                    "Unable to load history."

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

            saveHistory(
                []
            );


            res.json({

                success:
                    true,

                message:
                    "Scan history cleared."

            });


        } catch (error) {

            console.error(
                "Clear history error:",
                error
            );


            res.status(
                500
            ).json({

                success:
                    false,

                error:
                    "Unable to clear history."

            });

        }

    }
);


// ============================================
// REGISTER
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


            if (
                !name ||
                typeof name !==
                    "string" ||
                name.trim().length < 2
            ) {

                return res.status(
                    400
                ).json({

                    success:
                        false,

                    error:
                        "Name must contain at least 2 characters."

                });

            }


            if (
                !email ||
                typeof email !==
                    "string"
            ) {

                return res.status(
                    400
                ).json({

                    success:
                        false,

                    error:
                        "A valid email is required."

                });

            }


            const normalizedEmail =
                email
                    .trim()
                    .toLowerCase();


            const emailPattern =
                /^[^\s@]+@[^\s@]+\.[^\s@]+$/;


            if (
                !emailPattern.test(
                    normalizedEmail
                )
            ) {

                return res.status(
                    400
                ).json({

                    success:
                        false,

                    error:
                        "Please enter a valid email address."

                });

            }


            if (
                !password ||
                typeof password !==
                    "string" ||
                password.length < 6
            ) {

                return res.status(
                    400
                ).json({

                    success:
                        false,

                    error:
                        "Password must contain at least 6 characters."

                });

            }


            const existingUser =
                db.prepare(
                    `
                    SELECT id
                    FROM users
                    WHERE email = ?
                    `
                ).get(
                    normalizedEmail
                );


            if (
                existingUser
            ) {

                return res.status(
                    409
                ).json({

                    success:
                        false,

                    error:
                        "An account with this email already exists."

                });

            }


            const passwordHash =
                await bcrypt.hash(
                    password,
                    12
                );


            const insertUser =
                db.prepare(
                    `
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
                    `
                );


            const result =
                insertUser.run(

                    name.trim(),

                    normalizedEmail,

                    passwordHash

                );


            res.status(
                201
            ).json({

                success:
                    true,

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


            res.status(
                500
            ).json({

                success:
                    false,

                error:
                    "Registration failed."

            });

        }

    }
);


// ============================================
// LOGIN
// ============================================

app.post(
    "/api/auth/login",
    async (req, res) => {

        try {

            const {

                email,

                password

            } = req.body;


            if (
                !email ||
                !password
            ) {

                return res.status(
                    400
                ).json({

                    success:
                        false,

                    error:
                        "Email and password are required."

                });

            }


            const normalizedEmail =
                email
                    .trim()
                    .toLowerCase();


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


            if (
                !user
            ) {

                return res.status(
                    401
                ).json({

                    success:
                        false,

                    error:
                        "Invalid email or password."

                });

            }


            const passwordMatch =
                await bcrypt.compare(
                    password,
                    user.password
                );


            if (
                !passwordMatch
            ) {

                return res.status(
                    401
                ).json({

                    success:
                        false,

                    error:
                        "Invalid email or password."

                });

            }


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


            res.json({

                success:
                    true,

                message:
                    "Login successful.",

                token,

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


            res.status(
                500
            ).json({

                success:
                    false,

                error:
                    "Login failed."

            });

        }

    }
);


// ============================================
// UNKNOWN API ENDPOINT
// ============================================

app.use(
    "/api",
    (req, res) => {

        res.status(
            404
        ).json({

            success:
                false,

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
            "URL Scanner: POST /api/scan-url"
        );

        console.log(
            "Page Analyzer: POST /api/analyze-page"
        );

        console.log(
            "Email Analyzer: POST /api/analyze-email"
        );

        console.log(
            "Statistics: GET /api/stats"
        );

        console.log(
            "History: GET /api/history"
        );

        console.log(
            "----------------------------------------"
        );

    }
);