// ============================================
// PHISHGUARD API SERVER
// ============================================

const express = require("express");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

require("dotenv").config({
    path: path.join(__dirname, ".env")
});

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

const {
    extractURLFeatures,
    analyzeText,
    analyzeLoginBehavior,
    buildAssessment
} = require("./ai-engine");

const {
    buildScanExplanation
} = require("./explanation-engine");


// ============================================
// APP CONFIGURATION
// ============================================

const app = express();

const PORT = 3001;

const JWT_SECRET = process.env.JWT_SECRET ||
    (process.env.NODE_ENV === "production"
        ? ""
        : crypto.randomBytes(32).toString("hex"));

if (!JWT_SECRET) {
    throw new Error("JWT_SECRET must be configured in production.");
}


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
                "CYBERGUARD API",

            version:
                "4.0.0"

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

            const { url } = req.body || {};

            // --------------------------------
            // Validate
            // --------------------------------

            if (!url || typeof url !== "string") {

                return res.status(400).json({

                    success:
                        false,

                    error:
                        "A valid URL is required."

                });

            }

            const cleanUrl =
                url.trim();


            if (
                !/^https?:\/\//i.test(
                    cleanUrl
                )
            ) {

                return res.status(400).json({

                    success:
                        false,

                    error:
                        "URL must start with http:// or https://"

                });

            }


            // --------------------------------
            // 1. Traditional heuristic analysis
            // --------------------------------

            const {
                heuristicResult,
                threatResult
            } =
                await analyzeURLWithIntelligence(
                    cleanUrl
                );


            // --------------------------------
            // 2. AI feature analysis
            // --------------------------------

            let aiResult;
            let urlFeatures;


            try {

                urlFeatures =
                    extractURLFeatures(
                        cleanUrl
                    );


                aiResult =
                    analyzeText(
                        cleanUrl,
                        {
                            url:
                                cleanUrl
                        }
                    );

            } catch (aiError) {

                console.error(
                    "AI URL analysis error:",
                    aiError
                );


                urlFeatures = {

                    valid:
                        true,

                    featureScore:
                        0,

                    reasons:
                        []

                };


                aiResult = {

                    score:
                        0,

                    evidence:
                        [],

                    category:
                        "UNKNOWN",

                    features:
                        {}

                };

            }


            // --------------------------------
            // 3. Collect threat intelligence
            // --------------------------------

            const threatEvidence =
                Array.isArray(
                    threatResult?.evidence
                )
                    ? threatResult.evidence
                    : [];


            // --------------------------------
            // 4. Combine all evidence
            // --------------------------------

            const combinedFlags = [

                ...(Array.isArray(
                    heuristicResult?.flags
                )
                    ? heuristicResult.flags
                    : []),

                ...threatEvidence,

                ...(Array.isArray(
                    aiResult?.evidence
                )
                    ? aiResult.evidence
                    : []),

                ...(Array.isArray(
                    urlFeatures?.reasons
                )
                    ? urlFeatures.reasons
                    : [])

            ];


            const combinedCategories =
                Array.from(
                    new Set([

                        ...(Array.isArray(
                            heuristicResult?.categories
                        )
                            ? heuristicResult.categories
                            : []),

                        ...(aiResult?.category
                            ? [aiResult.category]
                            : []),

                        ...(threatResult?.reputation ===
                            "malicious"
                            ? [
                                "THREAT_INTELLIGENCE"
                            ]
                            : []),

                        ...(threatResult?.reputation ===
                            "suspicious"
                            ? [
                                "THREAT_INTELLIGENCE"
                            ]
                            : [])

                    ])
                );


            // --------------------------------
            // 5. Unified risk-engine input
            // --------------------------------

            const combinedInput = {

                ...heuristicResult,

                score:
                    Number(
                        heuristicResult?.score
                    ) || 0,

                heuristicScore:
                    Number(
                        heuristicResult?.score
                    ) || 0,

                aiScore:
                    Number(
                        aiResult?.score
                    ) ||
                    Number(
                        urlFeatures?.featureScore
                    ) ||
                    0,

                threatIntelScore:
                    Number(
                        threatResult?.score
                    ) || 0,

                flags:
                    combinedFlags,

                categories:
                    combinedCategories,


                features: {

                    ...(urlFeatures || {}),

                    ...(aiResult?.features || {}),


                    // Compatibility aliases
                    // for the risk engine.

                    hasIPAddress:
                        Boolean(
                            urlFeatures?.ipHost
                        ),

                    suspiciousTLD:
                        Boolean(
                            urlFeatures?.suspiciousTld
                        ),

                    credentialRequest:
                        Boolean(
                            aiResult
                                ?.features
                                ?.credentialCount
                        ),

                    urgency:
                        Boolean(
                            aiResult
                                ?.features
                                ?.urgencyCount
                        ),

                    paymentRequest:
                        Boolean(
                            aiResult
                                ?.features
                                ?.moneyCount
                        )

                },


                ai:
                    aiResult,


                threatIntel: {

                    ...threatResult,

                    malicious:
                        threatResult
                            ?.reputation ===
                        "malicious"

                }

            };


            // --------------------------------
            // 6. FINAL RISK FUSION
            // --------------------------------

            const riskResult =
                evaluateRisk(
                    combinedInput,
                    aiResult
                );


            // --------------------------------
            // 7. Frontend compatibility
            // --------------------------------

            const finalScore =
                Math.round(
                    Number(
                        riskResult?.riskScore ??
                        riskResult?.score ??
                        0
                    )
                );


            const finalLevel =
                riskResult?.riskLevel ||
                riskResult?.level ||
                (
                    finalScore >= 80
                        ? "CRITICAL"
                        : finalScore >= 60
                            ? "HIGH"
                            : finalScore >= 35
                                ? "MEDIUM"
                                : finalScore >= 15
                                    ? "LOW"
                                    : "SAFE"
                );


            const finalVerdict =
                riskResult?.verdict ||
                (
                    finalScore >= 70
                        ? "THREAT_DETECTED"
                        : finalScore >= 35
                            ? "SUSPICIOUS"
                            : "LOW_RISK"
                );


            const result = {

                ...riskResult,


                // --------------------------------
                // Existing frontend fields
                // --------------------------------

                score:
                    finalScore,

                level:
                    finalLevel,

                status:
                    riskResult?.status ||
                    finalVerdict,

                verdict:
                    finalVerdict,


                flags:
                    Array.from(
                        new Set(
                            combinedFlags
                        )
                    ),


                categories:
                    combinedCategories,


                // --------------------------------
                // AI/ML information
                // --------------------------------

                ai: {

                    model:
                        aiResult?.model ||
                        "cyberguard-feature-engine-v1",

                    modelType:
                        aiResult?.modelType ||
                        "feature-engineering + weighted classifier",

                    score:
                        Number(
                            aiResult?.score
                        ) || 0,

                    category:
                        aiResult?.category ||
                        "UNKNOWN",

                    features:
                        aiResult?.features ||
                        {},

                    evidence:
                        aiResult?.evidence ||
                        []

                },


                // --------------------------------
                // URL feature analysis
                // --------------------------------

                urlFeatures:
                    urlFeatures || {},


                // --------------------------------
                // Threat intelligence
                // --------------------------------

                threatIntelligence: {

                    reputation:
                        threatResult?.reputation ||
                        "unknown",

                    confidence:
                        threatResult?.confidence ||
                        "low",

                    score:
                        Number(
                            threatResult?.score
                        ) || 0,

                    sources:
                        threatResult?.sources ||
                        [],

                    evidence:
                        threatEvidence

                }

            };


            // --------------------------------
            // 8. Plain-English AI explanation
            // --------------------------------

            result.explanation =
                buildScanExplanation(
                    result,
                    {
                        type: "url",
                        url: cleanUrl
                    }
                );


            // --------------------------------
            // 9. History
            // --------------------------------

            addHistory({

                id:
                    Date.now().toString(),

                type:
                    "url",

                target:
                    cleanUrl,

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

                aiScore:
                    result.ai.score,

                timestamp:
                    new Date().toISOString()

            });


            // --------------------------------
            // 10. Response
            // --------------------------------

            return res.json({

                success:
                    true,

                url:
                    cleanUrl,

                result

            });


        } catch (error) {

            console.error(
                "URL scan error:",
                error
            );


            return res.status(
                500
            ).json({

                success:
                    false,

                error:
                    "Internal server error.",

                details:
                    process.env.NODE_ENV ===
                    "development"
                        ? error.message
                        : undefined

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
// ============================================

app.post(
    "/api/analyze-page",
    async (req, res) => {

        try {

            const pageData =
                req.body || {};


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


            const pageUrl =
                pageData.url.trim();


            // --------------------------------
            // URL analysis
            // --------------------------------

            const {

                heuristicResult,

                threatResult

            } =
                await analyzeURLWithIntelligence(
                    pageUrl
                );


            // --------------------------------
            // PAGE BEHAVIOR
            // --------------------------------

            const behaviorResult =
                analyzePage(
                    pageData
                );


            // --------------------------------
            // AI URL analysis
            // --------------------------------

            let aiResult;
            let urlFeatures;


            try {

                urlFeatures =
                    extractURLFeatures(
                        pageUrl
                    );


                const pageText =
                    [
                        pageData.title,
                        pageData.text,
                        pageData.content,
                        pageData.description
                    ]
                        .filter(
                            Boolean
                        )
                        .join(" ");


                aiResult =
                    analyzeText(
                        pageText ||
                        pageUrl,
                        {
                            url:
                                pageUrl
                        }
                    );

            } catch (aiError) {

                console.error(
                    "AI page analysis error:",
                    aiError
                );


                aiResult = {

                    score:
                        0,

                    evidence:
                        [],

                    category:
                        "UNKNOWN",

                    features:
                        {}

                };


                urlFeatures = {

                    valid:
                        true,

                    featureScore:
                        0,

                    reasons:
                        []

                };

            }


            // --------------------------------
            // Collect evidence
            // --------------------------------

            const urlFlags =
                Array.isArray(
                    heuristicResult?.flags
                )
                    ? heuristicResult.flags
                    : [];


            const threatFlags =
                Array.isArray(
                    threatResult?.evidence
                )
                    ? threatResult.evidence
                    : [];


            const behaviorFlags =
                Array.isArray(
                    behaviorResult?.signals
                )
                    ? behaviorResult.signals
                    : [];


            const aiFlags =
                Array.isArray(
                    aiResult?.evidence
                )
                    ? aiResult.evidence
                    : [];


            const featureFlags =
                Array.isArray(
                    urlFeatures?.reasons
                )
                    ? urlFeatures.reasons
                    : [];


            const allFlags = [

                ...urlFlags,

                ...threatFlags,

                ...behaviorFlags,

                ...aiFlags,

                ...featureFlags

            ];


            // --------------------------------
            // Categories
            // --------------------------------

            const categories =
                Array.from(
                    new Set([

                        ...(Array.isArray(
                            heuristicResult?.categories
                        )
                            ? heuristicResult.categories
                            : []),

                        ...(Array.isArray(
                            behaviorResult?.categories
                        )
                            ? behaviorResult.categories
                            : []),

                        ...(aiResult?.category
                            ? [aiResult.category]
                            : []),

                        ...(threatResult?.reputation ===
                            "malicious"
                            ? [
                                "THREAT_INTELLIGENCE"
                            ]
                            : []),

                        ...(threatResult?.reputation ===
                            "suspicious"
                            ? [
                                "THREAT_INTELLIGENCE"
                            ]
                            : [])

                    ])
                );


            // --------------------------------
            // Unified risk input
            // --------------------------------

            const pageRiskInput = {

                ...heuristicResult,

                heuristicScore:
                    Number(
                        heuristicResult?.score
                    ) || 0,

                aiScore:
                    Number(
                        aiResult?.score
                    ) ||
                    Number(
                        urlFeatures?.featureScore
                    ) ||
                    0,

                threatIntelScore:
                    Number(
                        threatResult?.score
                    ) || 0,

                behaviorScore:
                    Number(
                        behaviorResult?.score
                    ) || 0,


                flags:
                    allFlags,

                categories,


                features: {

                    ...(urlFeatures || {}),

                    ...(aiResult?.features || {}),

                    ...(behaviorResult?.features || {}),


                    hasIPAddress:
                        Boolean(
                            urlFeatures?.ipHost
                        ),

                    suspiciousTLD:
                        Boolean(
                            urlFeatures?.suspiciousTld
                        ),

                    credentialRequest:
                        Boolean(
                            aiResult
                                ?.features
                                ?.credentialCount
                        ),

                    urgency:
                        Boolean(
                            aiResult
                                ?.features
                                ?.urgencyCount
                        ),

                    paymentRequest:
                        Boolean(
                            aiResult
                                ?.features
                                ?.moneyCount
                        )

                },


                ai:
                    aiResult,


                behavior:
                    behaviorResult,


                threatIntel: {

                    ...threatResult,

                    malicious:
                        threatResult
                            ?.reputation ===
                        "malicious"

                }

            };


            // --------------------------------
            // Final risk evaluation
            // --------------------------------

            const riskResult =
                evaluateRisk(
                    pageRiskInput,
                    aiResult
                );


            // --------------------------------
            // Build final assessment
            // --------------------------------

            const assessment =
                buildAssessment({

                    ...aiResult,

                    score:
                        Number(
                            riskResult?.riskScore ??
                            riskResult?.score ??
                            aiResult?.score ??
                            0
                        ),

                    category:
                        riskResult?.classification ||
                        aiResult?.category ||
                        "SUSPICIOUS_ACTIVITY",

                    evidence:
                        allFlags

                });


            // --------------------------------
            // Final result
            // --------------------------------

            const finalScore =
                Math.round(
                    Number(
                        riskResult?.riskScore ??
                        riskResult?.score ??
                        assessment?.score ??
                        0
                    )
                );


            const result = {

                ...riskResult,

                score:
                    finalScore,

                level:
                    riskResult?.riskLevel ||
                    riskResult?.level ||
                    "SAFE",

                verdict:
                    riskResult?.verdict ||
                    (
                        finalScore >= 70
                            ? "THREAT_DETECTED"
                            : finalScore >= 35
                                ? "SUSPICIOUS"
                                : "LOW_RISK"
                    ),

                status:
                    riskResult?.status ||
                    riskResult?.verdict ||
                    "LOW_RISK",

                flags:
                    Array.from(
                        new Set(
                            allFlags
                        )
                    ),

                categories,


                behavior:
                    behaviorResult,


                ai:
                    aiResult,


                urlFeatures:
                    urlFeatures,


                threatIntelligence: {

                    reputation:
                        threatResult?.reputation ||
                        "unknown",

                    confidence:
                        threatResult?.confidence ||
                        "low",

                    score:
                        Number(
                            threatResult?.score
                        ) || 0,

                    sources:
                        threatResult?.sources ||
                        [],

                    evidence:
                        threatFlags

                },


                assessment

            };


            // --------------------------------
            // Plain-English AI explanation
            // --------------------------------

            result.explanation =
                buildScanExplanation(
                    result,
                    {
                        type: "page",
                        url: pageUrl
                    }
                );


            // --------------------------------
            // History
            // --------------------------------

            addHistory({

                id:
                    Date.now().toString(),

                type:
                    "page",

                target:
                    pageUrl,

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

                aiScore:
                    Number(
                        aiResult?.score
                    ) || 0,

                behaviorScore:
                    Number(
                        behaviorResult?.score
                    ) || 0,

                timestamp:
                    new Date().toISOString()

            });


            // --------------------------------
            // Response
            // --------------------------------

            return res.json({

                success:
                    true,

                url:
                    pageUrl,

                result

            });


        } catch (error) {

            console.error(
                "Page analysis error:",
                error
            );


            return res.status(
                500
            ).json({

                success:
                    false,

                error:
                    "Internal server error.",

                details:
                    process.env.NODE_ENV ===
                    "development"
                        ? error.message
                        : undefined

            });

        }

    }
);


// ============================================
// EMAIL ANALYZER
// ============================================

app.post(
    "/api/analyze-email",
    async (req, res) => {

        try {

            const {

                subject = "",

                body = "",

                sender = "",

                senderName = "",

                senderEmail = "",

                replyTo = "",

                links = []

            } =
                req.body || {};


            // --------------------------------
            // Validate
            // --------------------------------

            if (
                !subject &&
                !body &&
                !sender
            ) {

                return res.status(
                    400
                ).json({

                    success:
                        false,

                    error:
                        "Email content is required."

                });

            }


            // --------------------------------
            // Traditional email analysis
            // --------------------------------

            const emailResult =
                analyzeEmail({

                    senderName,

                    senderEmail:
                        senderEmail || sender,

                    replyTo,

                    subject,

                    body,

                    links

                });


            // --------------------------------
            // AI text analysis
            // --------------------------------

            const emailText = [

                subject,

                body,

                senderName,

                senderEmail,

                sender,

                replyTo,

                ...(Array.isArray(
                    links
                )
                    ? links
                    : [])

            ]
                .filter(
                    Boolean
                )
                .join(" ");


            let aiResult;


            try {

                aiResult =
                    analyzeText(
                        emailText
                    );

            } catch (aiError) {

                console.error(
                    "AI email analysis error:",
                    aiError
                );


                aiResult = {

                    score:
                        0,

                    evidence:
                        [],

                    category:
                        "UNKNOWN",

                    features:
                        {}

                };

            }


            // --------------------------------
            // Risk engine
            // --------------------------------

            const riskResult =
                evaluateRisk({

                    ...emailResult,

                    heuristicScore:
                        Number(
                            emailResult?.score
                        ) || 0,

                    aiScore:
                        Number(
                            aiResult?.score
                        ) || 0,

                    features:
                        aiResult?.features ||
                        {},

                    ai:
                        aiResult

                });


            const finalScore =
                Math.round(
                    Number(
                        riskResult?.riskScore ??
                        riskResult?.score ??
                        emailResult?.score ??
                        0
                    )
                );


            // --------------------------------
            // Final response
            // --------------------------------

            const result = {

                ...emailResult,

                ...riskResult,

                score:
                    finalScore,

                level:
                    riskResult?.riskLevel ||
                    riskResult?.level ||
                    "SAFE",

                verdict:
                    riskResult?.verdict ||
                    (
                        finalScore >= 70
                            ? "THREAT_DETECTED"
                            : finalScore >= 35
                                ? "SUSPICIOUS"
                                : "LOW_RISK"
                    ),

                ai:
                    aiResult

            };


            // --------------------------------
            // Plain-English AI explanation
            // --------------------------------

            result.explanation =
                buildScanExplanation(
                    result,
                    {
                        type: "email"
                    }
                );


            // --------------------------------
            // History
            // --------------------------------

            addHistory({

                id:
                    Date.now().toString(),

                type:
                    "email",

                target:
                    sender ||
                    subject ||
                    "Email",

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
                    result.flags ||
                    result.evidence ||
                    [],

                categories:
                    result.categories ||
                    [],

                aiScore:
                    Number(
                        aiResult?.score
                    ) || 0,

                timestamp:
                    new Date().toISOString()

            });


            return res.json({

                success:
                    true,

                result

            });


        } catch (error) {

            console.error(
                "Email analysis error:",
                error
            );


            return res.status(
                500
            ).json({

                success:
                    false,

                error:
                    "Internal server error.",

                details:
                    process.env.NODE_ENV ===
                    "development"
                        ? error.message
                        : undefined

            });

        }

    }
);


// ============================================
// UNIFIED CYBERGUARD AI ANALYZER
// ============================================

app.post(
    "/api/cyberguard/analyze",
    async (req, res) => {

        try {

            const {

                type = "text",

                text = "",

                url = "",

                context = {}

            } =
                req.body || {};


            // --------------------------------
            // URL analysis
            // --------------------------------

            if (
                type === "url" ||
                url
            ) {

                const targetUrl =
                    url ||
                    text;


                if (
                    !targetUrl ||
                    typeof targetUrl !==
                    "string"
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


                const urlFeatures =
                    extractURLFeatures(
                        targetUrl
                    );


                const aiResult =
                    analyzeText(
                        targetUrl,
                        {
                            ...context,

                            url:
                                targetUrl
                        }
                    );


                const assessment =
                    buildAssessment(
                        aiResult
                    );


                return res.json({

                    success:
                        true,

                    type:
                        "url",

                    input:
                        targetUrl,

                    result: {

                        ...assessment,

                        urlFeatures

                    }

                });

            }


            // --------------------------------
            // Text analysis
            // --------------------------------

            if (
                !text ||
                typeof text !==
                "string"
            ) {

                return res.status(
                    400
                ).json({

                    success:
                        false,

                    error:
                        "Text is required."

                });

            }


            const aiResult =
                analyzeText(
                    text,
                    context
                );


            const assessment =
                buildAssessment(
                    aiResult
                );


            return res.json({

                success:
                    true,

                type:
                    "text",

                result:
                    assessment

            });


        } catch (error) {

            console.error(
                "CyberGuard AI analysis error:",
                error
            );


            return res.status(
                500
            ).json({

                success:
                    false,

                error:
                    "AI analysis failed.",

                details:
                    process.env.NODE_ENV ===
                    "development"
                        ? error.message
                        : undefined

            });

        }

    }
);


// ============================================
// DIGITAL IMPERSONATION ANALYZER
// ============================================

app.post(
    "/api/analyze-impersonation",
    async (req, res) => {

        try {

            const {

                text = "",

                sender = "",

                claimedIdentity = ""

            } =
                req.body || {};


            const combinedText = [

                text,

                sender,

                claimedIdentity

            ]
                .filter(
                    Boolean
                )
                .join(" ");


            if (!combinedText) {

                return res.status(
                    400
                ).json({

                    success:
                        false,

                    error:
                        "Text, sender, or claimed identity is required."

                });

            }


            const aiResult =
                analyzeText(
                    combinedText
                );


            const assessment =
                buildAssessment({

                    ...aiResult,

                    category:
                        aiResult.category ===
                        "SUSPICIOUS_COMMUNICATION"
                            ? "DIGITAL_IMPERSONATION"
                            : aiResult.category

                });


            return res.json({

                success:
                    true,

                result:
                    assessment

            });


        } catch (error) {

            console.error(
                "Impersonation analysis error:",
                error
            );


            return res.status(
                500
            ).json({

                success:
                    false,

                error:
                    "Impersonation analysis failed."

            });

        }

    }
);


// ============================================
// LOGIN BEHAVIOR ANALYZER
// ============================================

app.post(
    "/api/analyze-login",
    async (req, res) => {

        try {

            const {

                logs = []

            } =
                req.body || {};


            if (
                !Array.isArray(
                    logs
                )
            ) {

                return res.status(
                    400
                ).json({

                    success:
                        false,

                    error:
                        "logs must be an array."

                });

            }


            const result =
                analyzeLoginBehavior(
                    logs
                );


            const assessment =
                buildAssessment(
                    result
                );


            return res.json({

                success:
                    true,

                result:
                    assessment

            });


        } catch (error) {

            console.error(
                "Login behavior analysis error:",
                error
            );


            return res.status(
                500
            ).json({

                success:
                    false,

                error:
                    "Login behavior analysis failed."

            });

        }

    }
);


// ============================================
// AI FEATURE EXTRACTION
// ============================================

app.post(
    "/api/ai/features",
    async (req, res) => {

        try {

            const {

                url,

                text,

                context = {}

            } =
                req.body || {};


            if (
                url &&
                typeof url ===
                "string"
            ) {

                return res.json({

                    success:
                        true,

                    type:
                        "url",

                    features:
                        extractURLFeatures(
                            url
                        )

                });

            }


            if (
                text &&
                typeof text ===
                "string"
            ) {

                return res.json({

                    success:
                        true,

                    type:
                        "text",

                    result:
                        analyzeText(
                            text,
                            context
                        )

                });

            }


            return res.status(
                400
            ).json({

                success:
                    false,

                error:
                    "Provide either url or text."

            });


        } catch (error) {

            console.error(
                "AI feature extraction error:",
                error
            );


            return res.status(
                500
            ).json({

                success:
                    false,

                error:
                    "AI feature extraction failed."

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


            // --------------------------------
            // Categorize using BOTH the
            // numeric score (0-100) and the
            // textual verdict/level produced
            // by the risk engine. Different
            // engines use different casing,
            // so normalize everything here.
            // --------------------------------

            const threats =
                history.filter(
                    item =>
                        Number(item.score) >= 70 ||
                        item.verdict ===
                            "dangerous" ||
                        item.verdict ===
                            "THREAT_DETECTED" ||
                        item.status ===
                            "Dangerous" ||
                        item.status ===
                            "THREAT_DETECTED" ||
                        item.level ===
                            "HIGH" ||
                        item.level ===
                            "CRITICAL" ||
                        item.level ===
                            "High Risk"
                ).length;


            const safe =
                history.filter(
                    item =>
                        item.verdict ===
                            "low-risk" ||
                        item.verdict ===
                            "LOW_RISK" ||
                        item.status ===
                            "Safe" ||
                        item.status ===
                            "Low Risk" ||
                        item.level ===
                            "SAFE" ||
                        item.level ===
                            "Low Risk" ||
                        Number(item.score) < 20
                ).length;


            const suspicious =
                history.filter(
                    item =>
                        Number(item.score) >= 40 &&
                        Number(item.score) < 70 ||
                        item.verdict ===
                            "suspicious" ||
                        item.verdict ===
                            "SUSPICIOUS" ||
                        item.verdict ===
                            "caution" ||
                        item.status ===
                            "Suspicious" ||
                        item.status ===
                            "Caution" ||
                        item.level ===
                            "MEDIUM" ||
                        item.level ===
                            "Medium Risk"
                ).length;


            const protection =
                totalScans > 0
                    ? Math.round(
                        (
                            (
                                totalScans -
                                threats
                            ) /
                            totalScans
                        ) *
                        100
                    )
                    : 100;


            return res.json({

                success:
                    true,

                stats: {

                    totalScans,

                    threats,

                    safe,

                    suspicious,

                    protection,

                    // Aliases so the dashboard
                    // can read either naming
                    // convention.

                    threatsDetected:
                        threats,

                    safeScans:
                        safe,

                    protectionRate:
                        protection

                }

            });


        } catch (error) {

            console.error(
                "Statistics error:",
                error
            );


            return res.status(
                500
            ).json({

                success:
                    false,

                error:
                    "Could not calculate statistics."

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


            return res.json({

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


            return res.status(
                500
            ).json({

                success:
                    false,

                error:
                    "Could not read history."

            });

        }

    }
);

// ============================================
// AUTHENTICATION
// ============================================

// --------------------------------------------
// JWT TOKEN GENERATOR
// --------------------------------------------

function generateToken(user) {

    return jwt.sign(
        {
            id:
                user.id,

            email:
                user.email,

            name:
                user.name
        },

        JWT_SECRET,

        {
            expiresIn:
                "7d"
        }
    );

}


// --------------------------------------------
// AUTH MIDDLEWARE
// --------------------------------------------

function authenticateToken(
    req,
    res,
    next
) {

    const authHeader =
        req.headers.authorization;


    if (
        !authHeader ||
        !authHeader.startsWith(
            "Bearer "
        )
    ) {

        return res.status(
            401
        ).json({

            success:
                false,

            error:
                "Authentication required."

        });

    }


    const token =
        authHeader.substring(
            7
        );


    try {

        const decoded =
            jwt.verify(
                token,
                JWT_SECRET
            );


        req.user =
            decoded;


        next();


    } catch (error) {

        return res.status(
            401
        ).json({

            success:
                false,

            error:
                "Invalid or expired token."

        });

    }

}


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

            } =
                req.body || {};


            // --------------------------------
            // Validation
            // --------------------------------

            if (
                !name ||
                !email ||
                !password
            ) {

                return res.status(
                    400
                ).json({

                    success:
                        false,

                    error:
                        "Name, email and password are required."

                });

            }


            if (
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


            const normalizedEmail =
                String(
                    email
                )
                    .trim()
                    .toLowerCase();


            // --------------------------------
            // Check existing user
            // --------------------------------

            let existingUser = null;


            try {

                if (
                    typeof db.getUserByEmail ===
                    "function"
                ) {

                    existingUser =
                        await db.getUserByEmail(
                            normalizedEmail
                        );

                }

            } catch (dbError) {

                console.error(
                    "User lookup error:",
                    dbError
                );

            }


            if (existingUser) {

                return res.status(
                    409
                ).json({

                    success:
                        false,

                    error:
                        "An account with this email already exists."

                });

            }


            // --------------------------------
            // Hash password
            // --------------------------------

            const passwordHash =
                await bcrypt.hash(
                    password,
                    10
                );


            // --------------------------------
            // Create user
            // --------------------------------

            let user;


            if (
                typeof db.createUser ===
                "function"
            ) {

                user =
                    await db.createUser({

                        name:
                            String(
                                name
                            ).trim(),

                        email:
                            normalizedEmail,

                        password:
                            passwordHash

                    });

            } else {

                // Fallback in case the database
                // module uses a synchronous API.

                user = {

                    id:
                        Date.now(),

                    name:
                        String(
                            name
                        ).trim(),

                    email:
                        normalizedEmail,

                    password:
                        passwordHash

                };

            }


            const token =
                generateToken(
                    user
                );


            return res.status(
                201
            ).json({

                success:
                    true,

                message:
                    "Account created successfully.",

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
                "Registration error:",
                error
            );


            return res.status(
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

            } =
                req.body || {};


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
                String(
                    email
                )
                    .trim()
                    .toLowerCase();


            // --------------------------------
            // Find user
            // --------------------------------

            let user = null;


            if (
                typeof db.getUserByEmail ===
                "function"
            ) {

                user =
                    await db.getUserByEmail(
                        normalizedEmail
                    );

            }


            if (!user) {

                return res.status(
                    401
                ).json({

                    success:
                        false,

                    error:
                        "Invalid email or password."

                });

            }


            // --------------------------------
            // Verify password
            // --------------------------------

            const passwordValid =
                await bcrypt.compare(
                    password,
                    user.password ||
                    user.passwordHash ||
                    ""
                );


            if (!passwordValid) {

                return res.status(
                    401
                ).json({

                    success:
                        false,

                    error:
                        "Invalid email or password."

                });

            }


            // --------------------------------
            // Generate token
            // --------------------------------

            const token =
                generateToken(
                    user
                );


            return res.json({

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


            return res.status(
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
// CURRENT USER
// ============================================

app.get(
    "/api/auth/me",
    authenticateToken,
    async (req, res) => {

        try {

            let user = null;


            if (
                typeof db.getUserById ===
                "function"
            ) {

                user =
                    await db.getUserById(
                        req.user.id
                    );

            }


            if (!user) {

                return res.json({

                    success:
                        true,

                    user:
                        req.user

                });

            }


            return res.json({

                success:
                    true,

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
                "Auth/me error:",
                error
            );


            return res.status(
                500
            ).json({

                success:
                    false,

                error:
                    "Could not retrieve user."

            });

        }

    }
);


// ============================================
// LOGOUT
// ============================================
//
// JWT authentication is stateless.
// The frontend should remove the token.
// This endpoint exists for API compatibility.
// ============================================

app.post(
    "/api/auth/logout",
    authenticateToken,
    (req, res) => {

        return res.json({

            success:
                true,

            message:
                "Logged out successfully."

        });

    }
);


// ============================================
// PROTECTED PROFILE
// ============================================

app.get(
    "/api/profile",
    authenticateToken,
    async (req, res) => {

        try {

            let user = null;


            if (
                typeof db.getUserById ===
                "function"
            ) {

                user =
                    await db.getUserById(
                        req.user.id
                    );

            }


            if (!user) {

                return res.json({

                    success:
                        true,

                    user:
                        req.user

                });

            }


            return res.json({

                success:
                    true,

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
                "Profile error:",
                error
            );


            return res.status(
                500
            ).json({

                success:
                    false,

                error:
                    "Could not retrieve profile."

            });

        }

    }
);


// ============================================
// HEALTH CHECK
// ============================================

app.get(
    "/api/health",
    (req, res) => {

        return res.json({

            success:
                true,

            status:
                "healthy",

            service:
                "CYBERGUARD",

            version:
                "4.0.0",

            timestamp:
                new Date().toISOString()

        });

    }
);


// ============================================
// DATABASE HEALTH
// ============================================

app.get(
    "/api/database-status",
    async (req, res) => {

        try {

            let connected = false;


            if (
                db &&
                typeof db.getDatabaseStatus ===
                "function"
            ) {

                const result =
                    await db.getDatabaseStatus();


                connected =
                    Boolean(
                        result
                    );

            } else {

                connected =
                    Boolean(
                        db
                    );

            }


            return res.json({

                success:
                    true,

                database:
                    connected
                        ? "connected"
                        : "unknown"

            });


        } catch (error) {

            console.error(
                "Database status error:",
                error
            );


            return res.status(
                500
            ).json({

                success:
                    false,

                database:
                    "error",

                error:
                    error.message

            });

        }

    }
);


// ============================================
// SCAN HISTORY FOR LOGGED-IN USER
// ============================================

app.get(
    "/api/user/history",
    authenticateToken,
    (req, res) => {

        try {

            const history =
                readHistory();


            const userHistory =
                history.filter(
                    item =>
                        String(
                            item.userId || ""
                        ) ===
                        String(
                            req.user.id
                        )
                );


            return res.json({

                success:
                    true,

                count:
                    userHistory.length,

                history:
                    userHistory

            });


        } catch (error) {

            console.error(
                "User history error:",
                error
            );


            return res.status(
                500
            ).json({

                success:
                    false,

                error:
                    "Could not retrieve user history."

            });

        }

    }
);


// ============================================
// SAVE USER SCAN
// ============================================

app.post(
    "/api/user/save-scan",
    authenticateToken,
    (req, res) => {

        try {

            const scan =
                req.body || {};


            const record = {

                ...scan,

                id:
                    Date.now().toString(),

                userId:
                    req.user.id,

                timestamp:
                    new Date().toISOString()

            };


            addHistory(
                record
            );


            return res.json({

                success:
                    true,

                message:
                    "Scan saved successfully.",

                record

            });


        } catch (error) {

            console.error(
                "Save scan error:",
                error
            );


            return res.status(
                500
            ).json({

                success:
                    false,

                error:
                    "Could not save scan."

            });

        }

    }
);


// ============================================
// DASHBOARD SUMMARY
// ============================================

app.get(
    "/api/dashboard",
    async (req, res) => {

        try {

            const history =
                readHistory();


            const total =
                history.length;


            // Categorize by numeric score so that
            // both the risk-engine ("High Risk")
            // and AI-engine ("HIGH") outputs are
            // handled consistently.

            const critical =
                history.filter(
                    item =>
                        Number(item.score) >= 80
                ).length;


            const high =
                history.filter(
                    item =>
                        Number(item.score) >= 60 &&
                        Number(item.score) < 80
                ).length;


            const medium =
                history.filter(
                    item =>
                        Number(item.score) >= 35 &&
                        Number(item.score) < 60
                ).length;


            const low =
                history.filter(
                    item =>
                        Number(item.score) >= 15 &&
                        Number(item.score) < 35
                ).length;


            const safe =
                history.filter(
                    item =>
                        Number(item.score) < 15
                ).length;


            const totalScore =
                history.reduce(
                    (
                        sum,
                        item
                    ) =>
                        sum +
                        (
                            Number(
                                item.score
                            ) || 0
                        ),
                    0
                );


            const averageScore =
                total
                    ? Math.round(
                        totalScore /
                        total
                    )
                    : 0;


            return res.json({

                success:
                    true,

                summary: {

                    total,

                    critical,

                    high,

                    medium,

                    low,

                    safe,

                    averageScore

                }

            });


        } catch (error) {

            console.error(
                "Dashboard error:",
                error
            );


            return res.status(
                500
            ).json({

                success:
                    false,

                error:
                    "Could not load dashboard."

            });

        }

    }
);


// ============================================
// THREAT SUMMARY
// ============================================

app.get(
    "/api/threats",
    (req, res) => {

        try {

            const history =
                readHistory();


            const threats =
                history.filter(
                    item =>
                        Number(item.score) >= 70 ||
                        item.verdict ===
                            "dangerous" ||
                        item.verdict ===
                            "THREAT_DETECTED" ||
                        item.status ===
                            "Dangerous" ||
                        item.level ===
                            "HIGH" ||
                        item.level ===
                            "CRITICAL" ||
                        item.level ===
                            "High Risk"
                );


            return res.json({

                success:
                    true,

                count:
                    threats.length,

                threats:
                    threats.slice(
                        0,
                        100
                    )

            });


        } catch (error) {

            console.error(
                "Threat list error:",
                error
            );


            return res.status(
                500
            ).json({

                success:
                    false,

                error:
                    "Could not retrieve threats."

            });

        }

    }
);


// ============================================
// AI MODEL INFORMATION
// ============================================

app.get(
    "/api/ai/status",
    (req, res) => {

        return res.json({

            success:
                true,

            ai: {

                status:
                    "online",

                model:
                    "cyberguard-feature-engine-v1",

                modelType:
                    "feature-engineering + weighted classifier",

                capabilities: [

                    "URL feature extraction",

                    "Phishing detection",

                    "Social engineering detection",

                    "Digital impersonation detection",

                    "Financial fraud detection",

                    "Login anomaly detection",

                    "Behavioral anomaly scoring",

                    "Explainable risk scoring"

                ],

                mlReady:
                    true

            }

        });

    }
);


// ============================================
// TEST AI ENDPOINT
// ============================================

app.post(
    "/api/ai/test",
    (req, res) => {

        try {

            const {

                text = ""

            } =
                req.body || {};


            if (!text) {

                return res.status(
                    400
                ).json({

                    success:
                        false,

                    error:
                        "Text is required."

                });

            }


            const result =
                analyzeText(
                    text
                );


            const assessment =
                buildAssessment(
                    result
                );


            return res.json({

                success:
                    true,

                result:
                    assessment

            });


        } catch (error) {

            console.error(
                "AI test error:",
                error
            );


            return res.status(
                500
            ).json({

                success:
                    false,

                error:
                    "AI test failed."

            });

        }

    }
);


// ============================================
// URL FEATURE TEST
// ============================================

app.post(
    "/api/ai/url-features",
    (req, res) => {

        try {

            const {

                url

            } =
                req.body || {};


            if (
                !url ||
                typeof url !==
                "string"
            ) {

                return res.status(
                    400
                ).json({

                    success:
                        false,

                    error:
                        "URL is required."

                });

            }


            const features =
                extractURLFeatures(
                    url.trim()
                );


            return res.json({

                success:
                    true,

                url:
                    url.trim(),

                features

            });


        } catch (error) {

            console.error(
                "URL feature test error:",
                error
            );


            return res.status(
                500
            ).json({

                success:
                    false,

                error:
                    "Could not extract URL features."

            });

        }

    }
);


// ============================================
// ROOT API INFORMATION
// ============================================

app.get(
    "/api",
    (req, res) => {

        return res.json({

            service:
                "CYBERGUARD API",

            version:
                "4.0.0",

            status:
                "online",

            endpoints: {

                status:
                    "GET /api/status",

                health:
                    "GET /api/health",

                scanURL:
                    "POST /api/scan-url",

                analyzePage:
                    "POST /api/analyze-page",

                analyzeEmail:
                    "POST /api/analyze-email",

                cyberguardAI:
                    "POST /api/cyberguard/analyze",

                impersonation:
                    "POST /api/analyze-impersonation",

                loginAnalysis:
                    "POST /api/analyze-login",

                aiFeatures:
                    "POST /api/ai/features",

                aiStatus:
                    "GET /api/ai/status",

                statistics:
                    "GET /api/stats",

                history:
                    "GET /api/history",

                dashboard:
                    "GET /api/dashboard",

                threats:
                    "GET /api/threats",

                register:
                    "POST /api/auth/register",

                login:
                    "POST /api/auth/login",

                me:
                    "GET /api/auth/me"

            }

        });

    }
);


// ============================================
// NOTE:
// The API 404 handler and the global error
// handler are registered at the very end of
// this file, AFTER every route has been
// declared. Registering them here would make
// all subsequently declared routes
// unreachable.
// ============================================


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
            "        CYBERGUARD API SERVER"
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
            `Page Analyzer: POST /api/analyze-page`
        );

        console.log(
            `Email Analyzer: POST /api/analyze-email`
        );

        console.log(
            `CyberGuard AI: POST /api/cyberguard/analyze`
        );

        console.log(
            `AI Status: GET /api/ai/status`
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


// ============================================
// EXPORT APP
// ============================================

module.exports = app;

// ============================================
// ADDITIONAL CYBERGUARD ANALYSIS ROUTES
// ============================================


// ============================================
// BATCH URL SCANNING
// ============================================

app.post(
    "/api/scan-urls",
    async (req, res) => {

        try {

            const {
                urls = []
            } = req.body || {};


            if (!Array.isArray(urls)) {

                return res.status(400).json({

                    success: false,

                    error:
                        "urls must be an array."

                });

            }


            if (urls.length === 0) {

                return res.status(400).json({

                    success: false,

                    error:
                        "At least one URL is required."

                });

            }


            // Prevent extremely large requests.

            const limitedUrls =
                urls.slice(0, 20);


            const results = [];


            for (
                const originalUrl
                of limitedUrls
            ) {

                if (
                    typeof originalUrl !==
                    "string"
                ) {

                    continue;

                }


                const cleanUrl =
                    originalUrl.trim();


                if (
                    !/^https?:\/\//i.test(
                        cleanUrl
                    )
                ) {

                    results.push({

                        url:
                            cleanUrl,

                        success:
                            false,

                        error:
                            "Invalid URL format."

                    });

                    continue;

                }


                try {

                    const {

                        heuristicResult,

                        threatResult

                    } =
                        await analyzeURLWithIntelligence(
                            cleanUrl
                        );


                    const urlFeatures =
                        extractURLFeatures(
                            cleanUrl
                        );


                    const aiResult =
                        analyzeText(
                            cleanUrl,
                            {
                                url:
                                    cleanUrl
                            }
                        );


                    const flags = [

                        ...(heuristicResult?.flags || []),

                        ...(threatResult?.evidence || []),

                        ...(aiResult?.evidence || []),

                        ...(urlFeatures?.reasons || [])

                    ];


                    const categories =
                        Array.from(
                            new Set([

                                ...(heuristicResult?.categories || []),

                                ...(aiResult?.category
                                    ? [
                                        aiResult.category
                                    ]
                                    : [])

                            ])
                        );


                    const riskInput = {

                        ...heuristicResult,

                        score:
                            Number(
                                heuristicResult?.score
                            ) || 0,

                        heuristicScore:
                            Number(
                                heuristicResult?.score
                            ) || 0,

                        aiScore:
                            Number(
                                aiResult?.score
                            ) ||
                            Number(
                                urlFeatures?.featureScore
                            ) ||
                            0,

                        threatIntelScore:
                            Number(
                                threatResult?.score
                            ) || 0,

                        flags,

                        categories,

                        features:
                            urlFeatures,

                        ai:
                            aiResult,

                        threatIntel:
                            threatResult

                    };


                    const riskResult =
                        evaluateRisk(
                            riskInput,
                            aiResult
                        );


                    const score =
                        Math.round(
                            Number(
                                riskResult?.riskScore ??
                                riskResult?.score ??
                                0
                            )
                        );


                    const level =
                        riskResult?.riskLevel ||
                        riskResult?.level ||
                        (
                            score >= 80
                                ? "CRITICAL"
                                : score >= 60
                                    ? "HIGH"
                                    : score >= 35
                                        ? "MEDIUM"
                                        : score >= 15
                                            ? "LOW"
                                            : "SAFE"
                        );


                    results.push({

                        success:
                            true,

                        url:
                            cleanUrl,

                        score,

                        level,

                        verdict:
                            riskResult?.verdict ||
                            (
                                score >= 70
                                    ? "THREAT_DETECTED"
                                    : score >= 35
                                        ? "SUSPICIOUS"
                                        : "LOW_RISK"
                            ),

                        flags:
                            Array.from(
                                new Set(
                                    flags
                                )
                            ),

                        categories,

                        ai: {

                            score:
                                Number(
                                    aiResult?.score
                                ) || 0,

                            category:
                                aiResult?.category ||
                                "UNKNOWN"

                        },

                        threatIntelligence: {

                            reputation:
                                threatResult?.reputation ||
                                "unknown",

                            score:
                                Number(
                                    threatResult?.score
                                ) || 0

                        }

                    });

                } catch (scanError) {

                    results.push({

                        success:
                            false,

                        url:
                            cleanUrl,

                        error:
                            scanError.message

                    });

                }

            }


            return res.json({

                success:
                    true,

                count:
                    results.length,

                results

            });


        } catch (error) {

            console.error(
                "Batch URL scan error:",
                error
            );


            return res.status(500).json({

                success:
                    false,

                error:
                    "Batch URL scanning failed."

            });

        }

    }
);


// ============================================
// URL REPUTATION CHECK
// ============================================

app.post(
    "/api/domain-reputation",
    async (req, res) => {

        try {

            const {
                domain,
                url
            } =
                req.body || {};


            let target =
                domain ||
                url;


            if (
                !target ||
                typeof target !==
                "string"
            ) {

                return res.status(400).json({

                    success:
                        false,

                    error:
                        "Domain or URL is required."

                });

            }


            target =
                target.trim();


            // If a full URL was provided,
            // extract the hostname.

            try {

                if (
                    /^https?:\/\//i.test(
                        target
                    )
                ) {

                    target =
                        new URL(
                            target
                        ).hostname;

                }

            } catch (urlError) {

                return res.status(400).json({

                    success:
                        false,

                    error:
                        "Invalid URL or domain."

                });

            }


            const result =
                await checkDomainReputation(
                    target
                );


            return res.json({

                success:
                    true,

                domain:
                    target,

                result

            });


        } catch (error) {

            console.error(
                "Domain reputation error:",
                error
            );


            return res.status(500).json({

                success:
                    false,

                error:
                    "Domain reputation check failed."

            });

        }

    }
);


// ============================================
// BEHAVIOR ANALYSIS
// ============================================

app.post(
    "/api/behavior/analyze",
    async (req, res) => {

        try {

            const pageData =
                req.body || {};


            if (
                !pageData ||
                typeof pageData !==
                "object"
            ) {

                return res.status(400).json({

                    success:
                        false,

                    error:
                        "Page data is required."

                });

            }


            const result =
                analyzePage(
                    pageData
                );


            return res.json({

                success:
                    true,

                result

            });


        } catch (error) {

            console.error(
                "Behavior analysis error:",
                error
            );


            return res.status(500).json({

                success:
                    false,

                error:
                    "Behavior analysis failed."

            });

        }

    }
);


// ============================================
// AI TEXT CLASSIFICATION
// ============================================

app.post(
    "/api/ai/classify-text",
    async (req, res) => {

        try {

            const {

                text = "",

                context = {}

            } =
                req.body || {};


            if (
                !text ||
                typeof text !==
                "string"
            ) {

                return res.status(400).json({

                    success:
                        false,

                    error:
                        "Text is required."

                });

            }


            const result =
                analyzeText(
                    text,
                    context
                );


            const assessment =
                buildAssessment(
                    result
                );


            return res.json({

                success:
                    true,

                result:
                    assessment

            });


        } catch (error) {

            console.error(
                "Text classification error:",
                error
            );


            return res.status(500).json({

                success:
                    false,

                error:
                    "Text classification failed."

            });

        }

    }
);


// ============================================
// AI URL CLASSIFICATION
// ============================================

app.post(
    "/api/ai/classify-url",
    async (req, res) => {

        try {

            const {
                url = ""
            } =
                req.body || {};


            if (
                !url ||
                typeof url !==
                "string"
            ) {

                return res.status(400).json({

                    success:
                        false,

                    error:
                        "URL is required."

                });

            }


            const cleanUrl =
                url.trim();


            const features =
                extractURLFeatures(
                    cleanUrl
                );


            const aiResult =
                analyzeText(
                    cleanUrl,
                    {
                        url:
                            cleanUrl
                    }
                );


            const assessment =
                buildAssessment({

                    ...aiResult,

                    score:
                        Math.max(
                            Number(
                                aiResult?.score
                            ) || 0,

                            Number(
                                features?.featureScore
                            ) || 0
                        ),

                    evidence:
                        Array.from(
                            new Set([

                                ...(aiResult?.evidence || []),

                                ...(features?.reasons || [])

                            ])
                        )

                });


            return res.json({

                success:
                    true,

                url:
                    cleanUrl,

                features,

                result:
                    assessment

            });


        } catch (error) {

            console.error(
                "URL classification error:",
                error
            );


            return res.status(500).json({

                success:
                    false,

                error:
                    "URL classification failed."

            });

        }

    }
);


// ============================================
// SECURITY RECOMMENDATIONS
// ============================================

app.post(
    "/api/security/recommendations",
    (req, res) => {

        try {

            const {

                score = 0,

                category = "",

                flags = []

            } =
                req.body || {};


            const numericScore =
                Math.max(
                    0,
                    Math.min(
                        100,
                        Number(score) || 0
                    )
                );


            const recommendations = [];


            // --------------------------------
            // General recommendations
            // --------------------------------

            if (
                numericScore >= 70
            ) {

                recommendations.push(
                    "Block or quarantine the suspicious resource."
                );

                recommendations.push(
                    "Create a security incident for investigation."
                );

                recommendations.push(
                    "Do not enter credentials or financial information."
                );

            } else if (
                numericScore >= 40
            ) {

                recommendations.push(
                    "Treat the resource with caution."
                );

                recommendations.push(
                    "Verify the source through an independent channel."
                );

                recommendations.push(
                    "Avoid entering sensitive information."
                );

            } else {

                recommendations.push(
                    "No major threat indicators detected."
                );

                recommendations.push(
                    "Continue normal security monitoring."
                );

            }


            // --------------------------------
            // Category-specific
            // --------------------------------

            if (
                String(
                    category
                ).includes(
                    "PHISHING"
                )
            ) {

                recommendations.push(
                    "Do not submit passwords, OTPs or credentials."
                );

            }


            if (
                String(
                    category
                ).includes(
                    "IMPERSONATION"
                )
            ) {

                recommendations.push(
                    "Verify the sender's identity using a trusted contact method."
                );

            }


            if (
                String(
                    category
                ).includes(
                    "FINANCIAL"
                )
            ) {

                recommendations.push(
                    "Never transfer money based only on an unexpected message."
                );

            }


            if (
                String(
                    category
                ).includes(
                    "ACCOUNT_TAKEOVER"
                )
            ) {

                recommendations.push(
                    "Revoke suspicious sessions and enable MFA."
                );

            }


            // --------------------------------
            // Flag-specific
            // --------------------------------

            const flagText =
                Array.isArray(flags)
                    ? flags.join(" ").toLowerCase()
                    : "";


            if (
                flagText.includes(
                    "ip address"
                )
            ) {

                recommendations.push(
                    "Verify the destination because the resource uses an IP address instead of a normal domain."
                );

            }


            if (
                flagText.includes(
                    "https"
                )
            ) {

                recommendations.push(
                    "Check the site's certificate and domain carefully; HTTPS alone does not prove legitimacy."
                );

            }


            return res.json({

                success:
                    true,

                score:
                    numericScore,

                category,

                recommendations:
                    Array.from(
                        new Set(
                            recommendations
                        )
                    )

            });


        } catch (error) {

            console.error(
                "Recommendation error:",
                error
            );


            return res.status(500).json({

                success:
                    false,

                error:
                    "Could not generate recommendations."

            });

        }

    }
);


// ============================================
// SECURITY ALERT GENERATOR
// ============================================

app.post(
    "/api/security/alert",
    (req, res) => {

        try {

            const {

                target = "",

                score = 0,

                level = "SAFE",

                verdict = "LOW_RISK",

                category = ""

            } =
                req.body || {};


            const numericScore =
                Math.round(
                    Number(score) || 0
                );


            let severity =
                "INFO";


            if (
                numericScore >= 80
            ) {

                severity =
                    "CRITICAL";

            } else if (
                numericScore >= 60
            ) {

                severity =
                    "HIGH";

            } else if (
                numericScore >= 35
            ) {

                severity =
                    "MEDIUM";

            } else if (
                numericScore >= 15
            ) {

                severity =
                    "LOW";

            }


            const alert = {

                severity,

                title:
                    severity === "CRITICAL"
                        ? "Critical Cyber Threat Detected"
                        : severity === "HIGH"
                            ? "High Risk Activity Detected"
                            : severity === "MEDIUM"
                                ? "Suspicious Activity Detected"
                                : severity === "LOW"
                                    ? "Potential Security Concern"
                                    : "Security Check Completed",

                target:
                    target || "Unknown resource",

                score:
                    numericScore,

                level,

                verdict,

                category,

                timestamp:
                    new Date().toISOString()

            };


            return res.json({

                success:
                    true,

                alert

            });


        } catch (error) {

            console.error(
                "Alert generation error:",
                error
            );


            return res.status(500).json({

                success:
                    false,

                error:
                    "Could not generate alert."

            });

        }

    }
);


// ============================================
// RECENT SCANS
// ============================================

app.get(
    "/api/recent-scans",
    (req, res) => {

        try {

            const history =
                readHistory();


            const limit =
                Math.min(
                    Number(
                        req.query.limit
                    ) || 10,
                    50
                );


            const scans =
                history
                    .slice(
                        0,
                        limit
                    )
                    .map(
                        item => ({

                            id:
                                item.id,

                            type:
                                item.type,

                            target:
                                item.target,

                            score:
                                item.score,

                            level:
                                item.level,

                            verdict:
                                item.verdict,

                            timestamp:
                                item.timestamp

                        })
                    );


            return res.json({

                success:
                    true,

                count:
                    scans.length,

                scans

            });


        } catch (error) {

            console.error(
                "Recent scans error:",
                error
            );


            return res.status(500).json({

                success:
                    false,

                error:
                    "Could not retrieve recent scans."

            });

        }

    }
);


// ============================================
// CLEAR HISTORY
// ============================================
//
// This route is intentionally protected.
// ============================================

app.delete(
    "/api/history",
    authenticateToken,
    (req, res) => {

        try {

            saveHistory(
                []
            );


            return res.json({

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


            return res.status(500).json({

                success:
                    false,

                error:
                    "Could not clear history."

            });

        }

    }
);


// ============================================
// DELETE SINGLE HISTORY ITEM
// ============================================

app.delete(
    "/api/history/:id",
    authenticateToken,
    (req, res) => {

        try {

            const history =
                readHistory();


            const id =
                String(
                    req.params.id
                );


            const newHistory =
                history.filter(
                    item =>
                        String(
                            item.id
                        ) !== id
                );


            if (
                newHistory.length ===
                history.length
            ) {

                return res.status(
                    404
                ).json({

                    success:
                        false,

                    error:
                        "Scan record not found."

                });

            }


            saveHistory(
                newHistory
            );


            return res.json({

                success:
                    true,

                message:
                    "Scan record deleted."

            });


        } catch (error) {

            console.error(
                "Delete history item error:",
                error
            );


            return res.status(500).json({

                success:
                    false,

                error:
                    "Could not delete scan record."

            });

        }

    }
);


// ============================================
// EXPORT ERROR INFORMATION
// ============================================

app.get(
    "/api/debug",
    (req, res) => {

        return res.json({

            success:
                true,

            nodeVersion:
                process.version,

            platform:
                process.platform,

            architecture:
                process.arch,

            environment:
                process.env.NODE_ENV ||
                "development",

            port:
                PORT,

            timestamp:
                new Date().toISOString()

        });

    }
);

// ============================================
// FRONTEND FALLBACK
// ============================================
//
// Any normal browser request that is not an API
// request will be sent to the frontend.
//
// ============================================

app.get(
    /.*/,
    (req, res, next) => {

        // Never interfere with API routes.

        if (
            req.path.startsWith(
                "/api/"
            )
        ) {

            return next();

        }


        const frontendPath =
            path.join(
                __dirname,
                "../frontend/index.html"
            );


        if (
            fs.existsSync(
                frontendPath
            )
        ) {

            return res.sendFile(
                frontendPath
            );

        }


        return res.status(
            404
        ).send(
            "CYBERGUARD frontend not found."
        );

    }
);


// ============================================
// 404 API HANDLER
// ============================================
//
// Registered last so that every /api route
// declared above is matched first.
// ============================================

app.use(
    "/api",
    (req, res) => {

        return res.status(
            404
        ).json({

            success:
                false,

            error:
                "API endpoint not found.",

            path:
                req.originalUrl

        });

    }
);


// ============================================
// GLOBAL ERROR HANDLER
// ============================================

app.use(
    (error, req, res, next) => {

        console.error(
            "Unhandled server error:",
            error
        );


        if (
            res.headersSent
        ) {

            return next(
                error
            );

        }


        return res.status(
            500
        ).json({

            success:
                false,

            error:
                "Internal server error."

        });

    }
);


// ============================================
// SERVER ERROR HANDLER
// ============================================

process.on(
    "uncaughtException",
    error => {

        console.error(
            "UNCAUGHT EXCEPTION:",
            error
        );

    }
);


process.on(
    "unhandledRejection",
    error => {

        console.error(
            "UNHANDLED PROMISE REJECTION:",
            error
        );

    }
);


// ============================================
// GRACEFUL SHUTDOWN
// ============================================

function shutdown(
    signal
) {

    console.log(
        `\n${signal} received.`
    );

    console.log(
        "Shutting down CYBERGUARD..."
    );


    process.exit(
        0
    );

}


process.on(
    "SIGINT",
    () => {

        shutdown(
            "SIGINT"
        );

    }
);


process.on(
    "SIGTERM",
    () => {

        shutdown(
            "SIGTERM"
        );

    }
);


// ============================================
// SERVER INFORMATION
// ============================================

console.log(
    "CYBERGUARD security engine loaded."
);


// ============================================
// END OF SERVER.JS
// ============================================