// ============================================
// PHISHGUARD THREAT INTELLIGENCE ENGINE
// ============================================
//
// Purpose:
// Provides external and local reputation signals
// for PhishGuard.
//
// IMPORTANT:
// An unknown domain is NOT automatically malicious.
//
// This module is designed to work together with:
//     heuristics.js
//     risk-engine.js
//
// Current capabilities:
//     1. Local malicious-domain list
//     2. Local suspicious-domain list
//     3. Domain reputation checks
//     4. Optional VirusTotal integration
//     5. Safe timeout handling
//     6. Graceful API failure handling
//
// ============================================

const https = require("https");


// ============================================
// CONFIGURATION
// ============================================

const THREAT_INTEL_VERSION = "1.0.0";


// Optional VirusTotal API key.
//
// Add to .env later:
//
// VIRUSTOTAL_API_KEY=your_api_key_here
//
// If the key is missing, VirusTotal is simply
// skipped.

const VIRUSTOTAL_API_KEY =
    process.env.VIRUSTOTAL_API_KEY ||
    "";


// Request timeout

const REQUEST_TIMEOUT =
    5000;


// ============================================
// LOCAL THREAT DATABASE
// ============================================
//
// Keep this list small and evidence-based.
// Do NOT put random websites here.
//
// These are examples for development/testing.
// Replace/extend them with domains from trusted
// threat-intelligence feeds.
//

const LOCAL_MALICIOUS_DOMAINS = [

    // Development/test domain examples.
    //
    // DO NOT treat these as a real-world
    // comprehensive threat feed.

    "malware.test",
    "phishing.test"

];


const LOCAL_SUSPICIOUS_DOMAINS = [

    "suspicious.test",
    "dangerous.test"

];


// ============================================
// HIGH-RISK DOMAIN PATTERNS
// ============================================
//
// These are NOT proof of maliciousness.
// They are only additional intelligence signals.
//
// We deliberately avoid broad rules such as:
//     "movie" = malicious
//
// because that would create false positives.
//

const HIGH_RISK_DOMAIN_PATTERNS = [

    /(^|\.)login-[a-z0-9-]+/i,

    /(^|\.)secure-[a-z0-9-]+/i,

    /(^|\.)verify-[a-z0-9-]+/i,

    /(^|\.)account-[a-z0-9-]+/i,

    /(^|\.)update-[a-z0-9-]+/i

];


// ============================================
// NORMALIZE DOMAIN
// ============================================

function normalizeDomain(domain) {

    if (
        typeof domain !== "string"
    ) {

        return "";

    }


    return domain
        .trim()
        .toLowerCase()
        .replace(
            /^https?:\/\//,
            ""
        )
        .split("/")[0]
        .split(":")[0];

}


// ============================================
// CHECK DOMAIN IN LIST
// ============================================

function domainMatchesList(
    domain,
    list
) {

    const normalized =
        normalizeDomain(
            domain
        );


    return list.some(
        item => {

            const entry =
                normalizeDomain(
                    item
                );


            return (
                normalized === entry ||
                normalized.endsWith(
                    `.${entry}`
                )
            );

        }
    );

}


// ============================================
// LOCAL THREAT DATABASE
// ============================================

function checkLocalThreatDatabase(
    domain
) {

    const normalized =
        normalizeDomain(
            domain
        );


    // ----------------------------------------
    // Malicious
    // ----------------------------------------

    if (
        domainMatchesList(
            normalized,
            LOCAL_MALICIOUS_DOMAINS
        )
    ) {

        return {

            source:
                "local-threat-database",

            reputation:
                "malicious",

            confidence:
                "high",

            score:
                90,

            reason:
                "Domain is present in the local malicious-domain database."

        };

    }


    // ----------------------------------------
    // Suspicious
    // ----------------------------------------

    if (
        domainMatchesList(
            normalized,
            LOCAL_SUSPICIOUS_DOMAINS
        )
    ) {

        return {

            source:
                "local-threat-database",

            reputation:
                "suspicious",

            confidence:
                "medium",

            score:
                60,

            reason:
                "Domain is present in the local suspicious-domain database."

        };

    }


    // ----------------------------------------
    // Unknown
    // ----------------------------------------

    return {

        source:
            "local-threat-database",

        reputation:
            "unknown",

        confidence:
            "low",

        score:
            0,

        reason:
            "Domain was not found in the local threat database."

    };

}


// ============================================
// DOMAIN PATTERN INTELLIGENCE
// ============================================

function checkDomainPatterns(
    domain
) {

    const normalized =
        normalizeDomain(
            domain
        );


    const matches = [];


    for (
        const pattern of
        HIGH_RISK_DOMAIN_PATTERNS
    ) {

        if (
            pattern.test(
                normalized
            )
        ) {

            matches.push(
                pattern.toString()
            );

        }

    }


    if (
        matches.length === 0
    ) {

        return {

            reputation:
                "unknown",

            confidence:
                "low",

            score:
                0,

            matches: [],

            reason:
                "No high-risk domain patterns detected."

        };

    }


    return {

        reputation:
            "suspicious",

        confidence:
            "low",

        score:
            Math.min(
                30,
                matches.length * 10
            ),

        matches,

        reason:
            "Domain structure contains patterns commonly associated with deceptive domains."

    };

}


// ============================================
// HTTP REQUEST HELPER
// ============================================

function httpsRequest(
    options
) {

    return new Promise(
        (resolve, reject) => {

            const request =
                https.request(
                    options,
                    response => {

                        let body = "";


                        response.on(
                            "data",
                            chunk => {

                                body +=
                                    chunk.toString();

                            }
                        );


                        response.on(
                            "end",
                            () => {

                                resolve({

                                    statusCode:
                                        response.statusCode,

                                    headers:
                                        response.headers,

                                    body

                                });

                            }
                        );

                    }
                );


            request.setTimeout(

                REQUEST_TIMEOUT,

                () => {

                    request.destroy();

                    reject(
                        new Error(
                            "Threat intelligence request timed out."
                        )
                    );

                }

            );


            request.on(
                "error",
                error => {

                    reject(
                        error
                    );

                }
            );


            request.end();

        }
    );

}


// ============================================
// VIRUSTOTAL DOMAIN CHECK
// ============================================
//
// VirusTotal uses the domain identifier
// encoded as a URL-safe base64 string
// without trailing "=".
//
// This function is optional.
//
// If no API key is configured, it returns
// "not_configured".
//

async function checkVirusTotal(
    domain
) {

    if (
        !VIRUSTOTAL_API_KEY
    ) {

        return {

            source:
                "virustotal",

            status:
                "not_configured",

            reputation:
                "unknown",

            confidence:
                "low",

            score:
                0,

            reason:
                "VirusTotal API key is not configured."

        };

    }


    const normalized =
        normalizeDomain(
            domain
        );


    if (
        !normalized
    ) {

        return {

            source:
                "virustotal",

            status:
                "invalid",

            reputation:
                "unknown",

            confidence:
                "low",

            score:
                0,

            reason:
                "Domain is invalid."

        };

    }


    // ----------------------------------------
    // VirusTotal domain identifier
    // ----------------------------------------

    const domainId =
        Buffer
            .from(
                normalized
            )
            .toString(
                "base64"
            )
            .replace(
                /=+$/,
                ""
            )
            .replace(
                /\+/g,
                "-"
            )
            .replace(
                /\//g,
                "_"
            );


    try {

        const response =
            await httpsRequest({

                hostname:
                    "www.virustotal.com",

                port:
                    443,

                path:
                    `/api/v3/domains/${encodeURIComponent(domainId)}`,

                method:
                    "GET",

                headers: {

                    "x-apikey":
                        VIRUSTOTAL_API_KEY,

                    "Accept":
                        "application/json",

                    "User-Agent":
                        "PhishGuard/1.0"

                }

            });


        // ------------------------------------
        // Rate limit
        // ------------------------------------

        if (
            response.statusCode ===
                429
        ) {

            return {

                source:
                    "virustotal",

                status:
                    "rate_limited",

                reputation:
                    "unknown",

                confidence:
                    "low",

                score:
                    0,

                reason:
                    "VirusTotal rate limit was reached."

            };

        }


        // ------------------------------------
        // Domain not found
        // ------------------------------------

        if (
            response.statusCode ===
                404
        ) {

            return {

                source:
                    "virustotal",

                status:
                    "not_found",

                reputation:
                    "unknown",

                confidence:
                    "low",

                score:
                    0,

                reason:
                    "VirusTotal has no reputation record for this domain."

            };

        }


        // ------------------------------------
        // Other HTTP errors
        // ------------------------------------

        if (
            response.statusCode < 200 ||
            response.statusCode >= 300
        ) {

            return {

                source:
                    "virustotal",

                status:
                    "error",

                reputation:
                    "unknown",

                confidence:
                    "low",

                score:
                    0,

                reason:
                    `VirusTotal returned HTTP ${response.statusCode}.`

            };

        }


        // ------------------------------------
        // Parse response
        // ------------------------------------

        let data;


        try {

            data =
                JSON.parse(
                    response.body
                );

        } catch (error) {

            return {

                source:
                    "virustotal",

                status:
                    "invalid_response",

                reputation:
                    "unknown",

                confidence:
                    "low",

                score:
                    0,

                reason:
                    "VirusTotal returned an invalid response."

            };

        }


        const attributes =
            data?.data?.attributes ||
            {};


        const stats =
            attributes.last_analysis_stats ||
            {};


        const malicious =
            Number(
                stats.malicious
            ) || 0;


        const suspicious =
            Number(
                stats.suspicious
            ) || 0;


        const harmless =
            Number(
                stats.harmless
            ) || 0;


        const undetected =
            Number(
                stats.undetected
            ) || 0;


        const total =
            malicious +
            suspicious +
            harmless +
            undetected;


        // ------------------------------------
        // Malicious detections
        // ------------------------------------

        if (
            malicious >= 3
        ) {

            return {

                source:
                    "virustotal",

                status:
                    "checked",

                reputation:
                    "malicious",

                confidence:
                    malicious >= 5
                        ? "high"
                        : "medium",

                score:
                    Math.min(
                        90,
                        50 +
                        malicious * 5
                    ),

                malicious,

                suspicious,

                harmless,

                undetected,

                total,

                reason:
                    `VirusTotal reports ${malicious} malicious security-engine detections.`

            };

        }


        // ------------------------------------
        // Suspicious detections
        // ------------------------------------

        if (
            suspicious >= 2
        ) {

            return {

                source:
                    "virustotal",

                status:
                    "checked",

                reputation:
                    "suspicious",

                confidence:
                    "medium",

                score:
                    Math.min(
                        60,
                        25 +
                        suspicious * 5
                    ),

                malicious,

                suspicious,

                harmless,

                undetected,

                total,

                reason:
                    `VirusTotal reports ${suspicious} suspicious security-engine detections.`

            };

        }


        // ------------------------------------
        // No significant detections
        // ------------------------------------

        return {

            source:
                "virustotal",

            status:
                "checked",

            reputation:
                "clean",

            confidence:
                "medium",

            score:
                0,

            malicious,

            suspicious,

            harmless,

            undetected,

            total,

            reason:
                "VirusTotal did not report significant malicious or suspicious detections."

        };

    } catch (error) {

        // ------------------------------------
        // Never break PhishGuard if an
        // external service fails.
        // ------------------------------------

        return {

            source:
                "virustotal",

            status:
                "unavailable",

            reputation:
                "unknown",

            confidence:
                "low",

            score:
                0,

            reason:
                "VirusTotal could not be reached. Local detection remains available.",

            error:
                error.message

        };

    }

}


// ============================================
// COMBINE INTELLIGENCE SOURCES
// ============================================

function combineResults(
    localResult,
    patternResult,
    virusTotalResult
) {

    const sources = [

        localResult,

        patternResult,

        virusTotalResult

    ];


    // ----------------------------------------
    // Find malicious evidence
    // ----------------------------------------

    const maliciousSources =
        sources.filter(
            source =>
                source.reputation ===
                "malicious"
        );


    if (
        maliciousSources.length
    ) {

        const highestScore =
            Math.max(
                ...maliciousSources.map(
                    source =>
                        Number(
                            source.score
                        ) || 0
                )
            );


        return {

            reputation:
                "malicious",

            confidence:
                maliciousSources.some(
                    source =>
                        source.confidence ===
                        "high"
                )
                    ? "high"
                    : "medium",

            score:
                Math.min(
                    95,
                    highestScore
                ),

            sources

        };

    }


    // ----------------------------------------
    // Suspicious evidence
    // ----------------------------------------

    const suspiciousSources =
        sources.filter(
            source =>
                source.reputation ===
                "suspicious"
        );


    if (
        suspiciousSources.length
    ) {

        const totalScore =
            suspiciousSources.reduce(
                (
                    total,
                    source
                ) =>
                    total +
                    (
                        Number(
                            source.score
                        ) || 0
                    ),
                0
            );


        return {

            reputation:
                "suspicious",

            confidence:
                suspiciousSources.some(
                    source =>
                        source.confidence ===
                        "medium"
                )
                    ? "medium"
                    : "low",

            score:
                Math.min(
                    70,
                    totalScore
                ),

            sources

        };

    }


    // ----------------------------------------
    // Clean / unknown
    // ----------------------------------------

    const cleanSource =
        sources.find(
            source =>
                source.reputation ===
                "clean"
        );


    if (
        cleanSource
    ) {

        return {

            reputation:
                "clean",

            confidence:
                cleanSource.confidence ||
                "medium",

            score:
                0,

            sources

        };

    }


    // ----------------------------------------
    // Unknown
    // ----------------------------------------

    return {

        reputation:
            "unknown",

        confidence:
            "low",

        score:
            0,

        sources

    };

}


// ============================================
// MAIN THREAT INTELLIGENCE FUNCTION
// ============================================

async function checkDomainReputation(
    domain
) {

    const normalized =
        normalizeDomain(
            domain
        );


    if (
        !normalized
    ) {

        return {

            success:
                false,

            domain:
                null,

            reputation:
                "unknown",

            confidence:
                "low",

            score:
                0,

            sources: [],

            error:
                "A valid domain is required."

        };

    }


    // ----------------------------------------
    // Run local intelligence first
    // ----------------------------------------

    const localResult =
        checkLocalThreatDatabase(
            normalized
        );


    // ----------------------------------------
    // Domain pattern analysis
    // ----------------------------------------

    const patternResult =
        checkDomainPatterns(
            normalized
        );


    // ----------------------------------------
    // External intelligence
    // ----------------------------------------

    const virusTotalResult =
        await checkVirusTotal(
            normalized
        );


    // ----------------------------------------
    // Combine results
    // ----------------------------------------

    const combined =
        combineResults(

            localResult,

            patternResult,

            virusTotalResult

        );


    // ----------------------------------------
    // Build evidence
    // ----------------------------------------

    const evidence = [];


    for (
        const source of
        combined.sources
    ) {

        if (
            source.reputation ===
            "malicious"
        ) {

            evidence.push({

                type:
                    "THREAT_INTELLIGENCE",

                severity:
                    "HIGH",

                source:
                    source.source,

                points:
                    source.score,

                message:
                    source.reason

            });

        }

        else if (
            source.reputation ===
            "suspicious"
        ) {

            evidence.push({

                type:
                    "THREAT_INTELLIGENCE",

                severity:
                    "MEDIUM",

                source:
                    source.source,

                points:
                    source.score,

                message:
                    source.reason

            });

        }

    }


    return {

        success:
            true,

        domain:
            normalized,

        reputation:
            combined.reputation,

        confidence:
            combined.confidence,

        score:
            combined.score,

        evidence,

        sources:
            combined.sources,

        engine: {

            name:
                "PhishGuard Threat Intelligence",

            version:
                THREAT_INTEL_VERSION

        }

    };

}


// ============================================
// ADD DOMAIN TO LOCAL MALICIOUS LIST
// ============================================
//
// Useful later for:
//     - user reports
//     - admin blocklists
//     - imported threat feeds
//
// This function does not modify the file.
// It only provides an in-memory helper.
//

function isLocallyBlocked(
    domain
) {

    return domainMatchesList(

        domain,

        LOCAL_MALICIOUS_DOMAINS

    );

}


// ============================================
// EXPORTS
// ============================================

module.exports = {

    checkDomainReputation,

    checkLocalThreatDatabase,

    checkDomainPatterns,

    isLocallyBlocked,

    normalizeDomain

};