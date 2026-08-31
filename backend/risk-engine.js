// ============================================
// PHISHGUARD RISK ENGINE
// ============================================
//
// Combines signals from the heuristic analyzer
// into one normalized risk assessment.
//
// IMPORTANT:
// This engine does NOT claim that a website is
// malicious just because it contains words such
// as "download", "movie", "apk", etc.
// Those are only signals.
// ============================================


// ============================================
// RISK WEIGHTS
// ============================================

const CATEGORY_WEIGHTS = {

    PHISHING: 1.25,

    OBFUSCATION: 1.20,

    DOMAIN: 1.10,

    REDIRECT: 1.10,

    DOWNLOAD_RISK: 1.00,

    TRANSPORT: 0.80,

    GENERAL: 1.00

};


// ============================================
// MAXIMUM SCORE
// ============================================

const MAX_SCORE = 100;


// ============================================
// NORMALIZE NUMBER
// ============================================

function normalizeNumber(value) {

    const number =
        Number(value);

    if (
        !Number.isFinite(number)
    ) {

        return 0;

    }

    return Math.max(
        0,
        Math.min(
            MAX_SCORE,
            number
        )
    );

}


// ============================================
// CALCULATE WEIGHTED RISK
// ============================================

function calculateWeightedRisk(
    heuristicResult
) {

    if (
        !heuristicResult ||
        typeof heuristicResult !== "object"
    ) {

        return {

            score: 0,

            weightedScore: 0,

            evidenceCount: 0

        };

    }


    const baseScore =
        normalizeNumber(
            heuristicResult.score
        );


    const flags =
        Array.isArray(
            heuristicResult.flags
        )
            ? heuristicResult.flags
            : [];


    if (
        flags.length === 0
    ) {

        return {

            score: baseScore,

            weightedScore: baseScore,

            evidenceCount: 0

        };

    }


    let weightedPoints = 0;


    for (
        const flag of flags
    ) {

        const points =
            normalizeNumber(
                flag.points
            );


        const category =
            String(
                flag.category ||
                findCategoryFromFlag(
                    flag.type
                ) ||
                "GENERAL"
            ).toUpperCase();


        const weight =
            CATEGORY_WEIGHTS[
                category
            ] ||
            CATEGORY_WEIGHTS.GENERAL;


        weightedPoints +=
            points * weight;

    }


    // Do not blindly replace the heuristic
    // score. Blend both measurements.

    const blendedScore =
        (
            baseScore * 0.55
        ) +
        (
            weightedPoints * 0.45
        );


    return {

        score:
            normalizeNumber(
                blendedScore
            ),

        weightedScore:
            weightedPoints,

        evidenceCount:
            flags.length

    };

}


// ============================================
// MAP FLAG TYPES TO CATEGORIES
// ============================================

function findCategoryFromFlag(
    type
) {

    const value =
        String(
            type || ""
        ).toUpperCase();


    if (
        value.includes("PHISH") ||
        value.includes("BRAND") ||
        value.includes("CREDENTIAL") ||
        value.includes("TYPOSQUAT")
    ) {

        return "PHISHING";

    }


    if (
        value.includes("OBFUS") ||
        value.includes("ENCOD")
    ) {

        return "OBFUSCATION";

    }


    if (
        value.includes("DOMAIN") ||
        value.includes("IP_") ||
        value.includes("TLD") ||
        value.includes("HYPHEN") ||
        value.includes("DIGIT")
    ) {

        return "DOMAIN";

    }


    if (
        value.includes("REDIRECT") ||
        value.includes("SHORTENER")
    ) {

        return "REDIRECT";

    }


    if (
        value.includes("DOWNLOAD") ||
        value.includes("APK") ||
        value.includes("CRACK")
    ) {

        return "DOWNLOAD_RISK";

    }


    if (
        value.includes("HTTPS") ||
        value.includes("TRANSPORT")
    ) {

        return "TRANSPORT";

    }


    return "GENERAL";

}


// ============================================
// DETERMINE VERDICT
// ============================================

function determineVerdict(
    score,
    heuristicResult
) {

    const categories =
        Array.isArray(
            heuristicResult?.categories
        )
            ? heuristicResult.categories
            : [];


    const flags =
        Array.isArray(
            heuristicResult?.flags
        )
            ? heuristicResult.flags
            : [];


    // ----------------------------------------
    // HIGH-CONFIDENCE DANGEROUS SIGNALS
    // ----------------------------------------

    const hasStrongPhishing =
        flags.some(
            flag =>

                flag.severity === "HIGH" &&

                (
                    flag.type ===
                        "TYPOSQUATTING" ||

                    flag.type ===
                        "BRAND_IMPERSONATION" ||

                    flag.type ===
                        "URL_AT_OBFUSCATION"
                )
        );


    if (
        hasStrongPhishing &&
        score >= 55
    ) {

        return {

            verdict: "dangerous",

            level: "High Risk",

            status: "Dangerous",

            confidence: "high"

        };

    }


    // ----------------------------------------
    // NORMAL SCORE THRESHOLDS
    // ----------------------------------------

    if (
        score >= 70
    ) {

        return {

            verdict: "dangerous",

            level: "High Risk",

            status: "Dangerous",

            confidence:
                score >= 85
                    ? "high"
                    : "medium"

        };

    }


    if (
        score >= 40
    ) {

        return {

            verdict: "suspicious",

            level: "Medium Risk",

            status: "Suspicious",

            confidence: "medium"

        };

    }


    if (
        score >= 20
    ) {

        return {

            verdict: "caution",

            level: "Low Risk",

            status: "Caution",

            confidence: "low"

        };

    }


    // ----------------------------------------
    // LOW RISK
    // ----------------------------------------

    return {

        verdict: "low-risk",

        level: "Low Risk",

        status: "Low Risk",

        confidence: "low"

    };

}


// ============================================
// GENERATE SUMMARY
// ============================================

function generateSummary(
    result,
    risk
) {

    const flags =
        Array.isArray(
            result?.flags
        )
            ? result.flags
            : [];


    if (
        flags.length === 0
    ) {

        return "No significant risk indicators detected.";

    }


    if (
        risk.verdict === "dangerous"
    ) {

        return "Multiple high-risk indicators were detected. Avoid interacting with this website.";

    }


    if (
        risk.verdict === "suspicious"
    ) {

        return "Several suspicious indicators were detected. Proceed with caution.";

    }


    if (
        risk.verdict === "caution"
    ) {

        return "Some risk indicators were detected. Additional verification is recommended.";

    }


    return "No major risk indicators were detected.";

}


// ============================================
// MAIN RISK ENGINE
// ============================================

function evaluateRisk(
    heuristicResult
) {

    if (
        !heuristicResult ||
        typeof heuristicResult !== "object"
    ) {

        return {

            score: 0,

            verdict: "unknown",

            level: "Unknown",

            status: "Unknown",

            confidence: "low",

            summary:
                "Unable to evaluate the website.",

            categories: [],

            evidence: []

        };

    }


    const weighted =
        calculateWeightedRisk(
            heuristicResult
        );


    const finalScore =
        Math.round(
            normalizeNumber(
                weighted.score
            )
        );


    const risk =
        determineVerdict(
            finalScore,
            heuristicResult
        );


    const categories =
        Array.isArray(
            heuristicResult.categories
        )
            ? heuristicResult.categories
            : [];


    const flags =
        Array.isArray(
            heuristicResult.flags
        )
            ? heuristicResult.flags
            : [];


    return {

        // ------------------------------------
        // FINAL RESULT
        // ------------------------------------

        score:
            finalScore,

        verdict:
            risk.verdict,

        level:
            risk.level,

        status:
            risk.status,

        confidence:
            risk.confidence,


        // ------------------------------------
        // EXPLANATION
        // ------------------------------------

        summary:
            generateSummary(
                heuristicResult,
                risk
            ),


        // ------------------------------------
        // ORIGINAL INFORMATION
        // ------------------------------------

        domain:
            heuristicResult.domain ||
            null,

        hostname:
            heuristicResult.hostname ||
            null,

        isTrustedDomain:
            Boolean(
                heuristicResult.isTrustedDomain
            ),


        // ------------------------------------
        // CATEGORIES
        // ------------------------------------

        categories,


        // ------------------------------------
        // EVIDENCE
        // ------------------------------------

        evidence:
            flags,


        // ------------------------------------
        // ENGINE METADATA
        // ------------------------------------

        engine: {

            version:
                "2.0.0",

            heuristicScore:
                normalizeNumber(
                    heuristicResult.score
                ),

            weightedScore:
                Math.round(
                    weighted.weightedScore
                ),

            evidenceCount:
                weighted.evidenceCount

        }

    };

}


// ============================================
// EXPORT
// ============================================

module.exports = {

    evaluateRisk,

    calculateWeightedRisk,

    determineVerdict

};