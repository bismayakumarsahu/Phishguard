// ============================================
// PHISHGUARD - MULTI-LAYER HEURISTICS ENGINE
// ============================================

function levenshteinDistance(a, b) {
    const matrix = Array.from(
        { length: b.length + 1 },
        (_, i) => [i]
    );

    for (let j = 0; j <= a.length; j++) {
        matrix[0][j] = j;
    }

    for (let i = 1; i <= b.length; i++) {
        for (let j = 1; j <= a.length; j++) {

            matrix[i][j] =
                b[i - 1] === a[j - 1]
                    ? matrix[i - 1][j - 1]
                    : Math.min(
                        matrix[i - 1][j - 1] + 1,
                        matrix[i][j - 1] + 1,
                        matrix[i - 1][j] + 1
                    );
        }
    }

    return matrix[b.length][a.length];
}


// ============================================
// TRUSTED DOMAINS
// ============================================

const TRUSTED_DOMAINS = [
    "chatgpt.com",
    "openai.com",
    "google.com",
    "youtube.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "paypal.com",
    "facebook.com",
    "instagram.com",
    "linkedin.com"
];


// ============================================
// TRUSTED BRANDS
// ============================================

const TRUSTED_BRANDS = [
    "paypal",
    "amazon",
    "google",
    "microsoft",
    "apple",
    "facebook",
    "instagram",
    "netflix",
    "sbi",
    "hdfc",
    "icici"
];


// ============================================
// URL SHORTENERS
// ============================================

const SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "cutt.ly",
    "rb.gy"
];


// ============================================
// HIGH-RISK TLDs
// ============================================

const SUSPICIOUS_TLDS = [
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".top",
    ".xyz",
    ".click"
];


// ============================================
// HIGH-RISK CONTENT INDICATORS
// ============================================
// These are risk indicators.
// They do NOT automatically mean malware.

const HIGH_RISK_CONTENT_TERMS = [
    "crack",
    "cracked",
    "keygen",
    "serial-key",
    "serialkey",
    "mod-apk",
    "modapk",
    "patched-apk",
    "nulled",
    "warez",
    "torrent",
    "magnet",
    "free-download",
    "freedownload",
    "free-movie",
    "freemovie",
    "movie-download",
    "moviedownload",
    "apk-download",
    "apkdownload"
];


// ============================================
// DOWNLOAD INDICATORS
// ============================================

const DOWNLOAD_TERMS = [
    "download",
    "download-now",
    "direct-download",
    "get-file",
    "apk",
    "exe",
    "msi",
    "dmg",
    "scr",
    "zip",
    "rar",
    "7z"
];


// ============================================
// REDIRECT INDICATORS
// ============================================

const REDIRECT_TERMS = [
    "redirect",
    "redir",
    "click.php",
    "go.php",
    "out.php",
    "exit.php",
    "continue=",
    "target=",
    "dest=",
    "destination="
];


// ============================================
// OBFUSCATION INDICATORS
// ============================================

const OBFUSCATION_TERMS = [
    "base64",
    "eval(",
    "javascript:",
    "data:text/html",
    "%2f%2f",
    "%40"
];


// ============================================
// URL NORMALIZATION
// ============================================

function normalizeURL(url) {

    if (
        typeof url !== "string" ||
        !url.trim()
    ) {
        throw new Error("URL is required.");
    }

    const value = url.trim();

    const parsed = new URL(
        /^https?:\/\//i.test(value)
            ? value
            : `https://${value}`
    );

    if (
        !/^https?:$/.test(
            parsed.protocol
        )
    ) {
        throw new Error(
            "Only HTTP and HTTPS URLs are supported."
        );
    }

    return parsed;
}


// ============================================
// GET REGISTRABLE DOMAIN
// ============================================

function getRegistrableDomain(hostname) {

    const parts =
        hostname
            .split(".")
            .filter(Boolean);

    if (parts.length < 2) {
        return hostname;
    }

    return parts
        .slice(-2)
        .join(".");
}


// ============================================
// TRUSTED DOMAIN CHECK
// ============================================

function isTrustedDomain(hostname) {

    return TRUSTED_DOMAINS.some(
        domain =>
            hostname === domain ||
            hostname.endsWith(`.${domain}`)
    );
}


// ============================================
// URL / WEBSITE RISK ANALYZER
// ============================================

function analyzeURL(url) {

    let parsed;

    // ----------------------------------------
    // Validate URL
    // ----------------------------------------

    try {

        parsed =
            normalizeURL(url);

    } catch (error) {

        return {

            score: 100,

            level: "High Risk",

            status: "Dangerous",

            verdict: "dangerous",

            confidence: "high",

            categories: [
                "INVALID_URL"
            ],

            flags: [

                {
                    type: "INVALID_URL",

                    severity: "HIGH",

                    points: 100,

                    message:
                        "The supplied value is not a valid HTTP/HTTPS URL."
                }

            ]

        };
    }


    let score = 0;

    const flags = [];

    const categories =
        new Set();


    const href =
        parsed.href.toLowerCase();

    const hostname =
        parsed.hostname.toLowerCase();

    const pathname =
        parsed.pathname.toLowerCase();

    const search =
        parsed.search.toLowerCase();

    const registrableDomain =
        getRegistrableDomain(hostname);

    const domainName =
        registrableDomain
            .split(".")[0];

    const trusted =
        isTrustedDomain(hostname);


    // ----------------------------------------
    // ADD RISK HELPER
    // ----------------------------------------

    function addRisk(
        points,
        type,
        message,
        category = "GENERAL",
        severity = "MEDIUM"
    ) {

        score += points;

        categories.add(category);

        flags.push({

            type,

            severity,

            points,

            message

        });

    }


    // ========================================
    // 1. HTTPS
    // ========================================

    if (
        parsed.protocol !== "https:"
    ) {

        addRisk(

            8,

            "NO_HTTPS",

            "Website does not use HTTPS.",

            "TRANSPORT",

            "LOW"

        );

    }


    // ========================================
    // 2. @ URL OBFUSCATION
    // ========================================

    if (
        href.includes("@")
    ) {

        addRisk(

            25,

            "URL_AT_OBFUSCATION",

            "URL contains '@', which can hide the actual destination.",

            "OBFUSCATION",

            "HIGH"

        );

    }


    // ========================================
    // 3. IP ADDRESS
    // ========================================

    const ipv4 =
        /^(?:\d{1,3}\.){3}\d{1,3}$/;

    if (
        ipv4.test(hostname) ||
        hostname.includes(":")
    ) {

        addRisk(

            30,

            "IP_ADDRESS",

            "URL uses an IP address instead of a normal domain.",

            "DOMAIN",

            "HIGH"

        );

    }


    // ========================================
    // 4. URL SHORTENER
    // ========================================

    if (
        SHORTENERS.some(
            domain =>
                hostname === domain ||
                hostname.endsWith(
                    `.${domain}`
                )
        )
    ) {

        addRisk(

            15,

            "URL_SHORTENER",

            "URL uses a shortening service, hiding the final destination.",

            "REDIRECT",

            "MEDIUM"

        );

    }


    // ========================================
    // 5. SUSPICIOUS TLD
    // ========================================

    const matchedTLD =
        SUSPICIOUS_TLDS.find(
            tld =>
                hostname.endsWith(tld)
        );

    if (matchedTLD) {

        addRisk(

            15,

            "SUSPICIOUS_TLD",

            `Domain uses a higher-risk TLD: ${matchedTLD}`,

            "DOMAIN",

            "MEDIUM"

        );

    }


    // ========================================
    // 6. DOMAIN STRUCTURE
    // ========================================

    const hyphens =
        (
            domainName.match(/-/g) ||
            []
        ).length;

    const digits =
        (
            domainName.match(/\d/g) ||
            []
        ).length;

    const subdomains =
        Math.max(
            0,
            hostname.split(".").length - 2
        );


    if (hyphens >= 3) {

        addRisk(

            12,

            "EXCESSIVE_HYPHENS",

            "Domain contains many hyphens.",

            "DOMAIN",

            "MEDIUM"

        );

    }


    if (digits >= 4) {

        addRisk(

            8,

            "EXCESSIVE_DIGITS",

            "Domain contains many digits.",

            "DOMAIN",

            "LOW"

        );

    }


    if (hostname.length > 60) {

        addRisk(

            10,

            "LONG_HOSTNAME",

            "Hostname is unusually long.",

            "DOMAIN",

            "LOW"

        );

    }


    if (subdomains >= 4) {

        addRisk(

            10,

            "DEEP_SUBDOMAIN",

            "Domain has an unusually deep subdomain structure.",

            "DOMAIN",

            "LOW"

        );

    }


    // ========================================
    // 7. TYPOSQUATTING
    // ========================================

    for (
        const brand of TRUSTED_BRANDS
    ) {

        const distance =
            levenshteinDistance(
                domainName,
                brand
            );

        if (
            distance > 0 &&
            distance <= 2
        ) {

            addRisk(

                35,

                "TYPOSQUATTING",

                `Possible ${brand} impersonation detected.`,

                "PHISHING",

                "HIGH"

            );

            break;

        }

    }


    // ========================================
    // 8. BRAND IMPERSONATION
    // ========================================

    for (
        const brand of TRUSTED_BRANDS
    ) {

        const impersonation =

            href.includes(
                `${brand}-`
            ) ||

            href.includes(
                `${brand}login`
            ) ||

            href.includes(
                `secure-${brand}`
            ) ||

            href.includes(
                `${brand}verify`
            );


        if (
            impersonation &&
            !trusted
        ) {

            addRisk(

                25,

                "BRAND_IMPERSONATION",

                `Possible ${brand} impersonation detected.`,

                "PHISHING",

                "HIGH"

            );

            break;

        }

    }


    // ========================================
    // 9. PHISHING KEYWORDS
    // ========================================

    const phishingKeywords = [

        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "password",
        "update",
        "confirm",
        "signin",
        "banking",
        "wallet",
        "recover",
        "authenticate",
        "unlock",
        "suspended"

    ];


    const keywordMatches =
        phishingKeywords.filter(
            keyword =>
                href.includes(keyword)
        );


    if (
        !trusted &&
        keywordMatches.length >= 2
    ) {

        addRisk(

            20,

            "PHISHING_KEYWORDS",

            `Multiple phishing keywords detected: ${keywordMatches.join(", ")}.`,

            "PHISHING",

            "HIGH"

        );

    }


    // ========================================
    // 10. CREDENTIAL PATH
    // ========================================

    if (
        !trusted &&
        /(login|signin|verify|account|authenticate|password)/i.test(
            pathname
        )
    ) {

        addRisk(

            8,

            "CREDENTIAL_PATH",

            "Untrusted site contains an account or credential-related path.",

            "PHISHING",

            "MEDIUM"

        );

    }


    // ========================================
    // 11. HIGH-RISK CONTENT
    // ========================================

    const highRiskMatches =
        HIGH_RISK_CONTENT_TERMS.filter(
            term =>
                href.includes(term)
        );


    if (
        highRiskMatches.length
    ) {

        addRisk(

            Math.min(
                25,
                highRiskMatches.length * 8
            ),

            "HIGH_RISK_CONTENT",

            `URL contains elevated-risk download/content indicators: ${highRiskMatches
                .slice(0, 5)
                .join(", ")}.`,

            "DOWNLOAD_RISK",

            "MEDIUM"

        );

    }


    // ========================================
    // 12. DOWNLOAD PATH
    // ========================================

    const downloadMatches =
        DOWNLOAD_TERMS.filter(
            term =>
                pathname.includes(term) ||
                search.includes(term)
        );


    if (
        downloadMatches.length >= 2
    ) {

        addRisk(

            12,

            "SUSPICIOUS_DOWNLOAD_PATH",

            `URL contains multiple download-related indicators: ${downloadMatches
                .slice(0, 5)
                .join(", ")}.`,

            "DOWNLOAD_RISK",

            "MEDIUM"

        );

    }


    // ========================================
    // 13. REDIRECT INDICATORS
    // ========================================

    const redirectMatches =
        REDIRECT_TERMS.filter(
            term =>
                href.includes(term)
        );


    if (
        redirectMatches.length >= 2
    ) {

        addRisk(

            12,

            "REDIRECT_INDICATORS",

            "URL contains multiple redirect-style indicators.",

            "REDIRECT",

            "MEDIUM"

        );

    }


    // ========================================
    // 14. OBFUSCATION
    // ========================================

    const obfuscationMatches =
        OBFUSCATION_TERMS.filter(
            term =>
                href.includes(term)
        );


    if (
        obfuscationMatches.length >= 2
    ) {

        addRisk(

            15,

            "URL_OBFUSCATION",

            "URL contains multiple encoding or script-like indicators.",

            "OBFUSCATION",

            "HIGH"

        );

    }


    // ========================================
    // 15. MANY QUERY PARAMETERS
    // ========================================

    if (
        parsed.searchParams.size >= 8
    ) {

        addRisk(

            8,

            "MANY_PARAMETERS",

            "URL contains many query parameters.",

            "OBFUSCATION",

            "LOW"

        );

    }


    // ========================================
    // 16. VERY LONG URL
    // ========================================

    if (
        href.length > 250
    ) {

        addRisk(

            8,

            "LONG_URL",

            "URL is unusually long and may contain encoded data.",

            "OBFUSCATION",

            "LOW"

        );

    }


    // ========================================
    // 17. FINAL SCORE
    // ========================================

    score =
        Math.min(
            100,
            Math.max(
                0,
                score
            )
        );


    // ========================================
    // 18. FINAL VERDICT
    // ========================================

    let level;
    let status;
    let verdict;
    let confidence;


    if (
        score >= 70
    ) {

        level = "High Risk";

        status = "Dangerous";

        verdict = "dangerous";

        confidence =
            score >= 85
                ? "high"
                : "medium";

    }

    else if (
        score >= 40
    ) {

        level = "Medium Risk";

        status = "Suspicious";

        verdict = "suspicious";

        confidence = "medium";

    }

    else if (
        score >= 20
    ) {

        level = "Low Risk";

        status = "Caution";

        verdict = "caution";

        confidence = "low";

    }

    else {

        level = "Low Risk";

        status = "Low Risk";

        verdict = "low-risk";

        confidence = "low";

    }


    // ========================================
    // RESULT
    // ========================================

    return {

        score,

        level,

        status,

        verdict,

        confidence,

        categories:
            Array.from(
                categories
            ),

        domain:
            registrableDomain,

        hostname,

        isTrustedDomain:
            trusted,

        flags

    };

}


// ============================================
// EMAIL PHISHING ANALYZER
// ============================================

function analyzeEmail({

    senderName = "",
    senderEmail = "",
    replyTo = "",
    subject = "",
    body = ""

}) {

    let score = 0;

    const flags = [];


    const name =
        String(senderName)
            .toLowerCase()
            .trim();

    const email =
        String(senderEmail)
            .toLowerCase()
            .trim();

    const reply =
        String(replyTo)
            .toLowerCase()
            .trim();

    const fullText =
        `${subject} ${body}`
            .toLowerCase();


    // ========================================
    // 1. SENDER NAME VS EMAIL
    // ========================================

    const trustedBrands = [

        "paypal",
        "amazon",
        "microsoft",
        "google",
        "apple",
        "facebook",
        "instagram",
        "netflix",
        "sbi",
        "hdfc",
        "icici"

    ];


    const suspiciousBrand =
        trustedBrands.find(
            brand =>
                name.includes(brand)
        );


    if (
        suspiciousBrand &&
        email
    ) {

        const emailDomain =
            email.split("@")[1] ||
            "";


        const trustedDomains = {

            paypal: [
                "paypal.com"
            ],

            amazon: [
                "amazon.com",
                "amazon.in"
            ],

            microsoft: [
                "microsoft.com"
            ],

            google: [
                "google.com"
            ],

            apple: [
                "apple.com"
            ],

            facebook: [
                "facebook.com"
            ],

            instagram: [
                "instagram.com"
            ],

            netflix: [
                "netflix.com"
            ],

            sbi: [
                "sbi.co.in"
            ],

            hdfc: [
                "hdfcbank.com"
            ],

            icici: [
                "icicibank.com"
            ]

        };


        const allowed =
            trustedDomains[
                suspiciousBrand
            ] || [];


        if (
            !allowed.some(
                domain =>
                    emailDomain === domain ||
                    emailDomain.endsWith(
                        `.${domain}`
                    )
            )
        ) {

            score += 30;


            flags.push({

                type:
                    "SENDER_MISMATCH",

                message:
                    `Sender claims to represent ${suspiciousBrand}, but the email domain is "${emailDomain}".`

            });

        }

    }


    // ========================================
    // 2. REPLY-TO SPOOFING
    // ========================================

    if (
        reply &&
        email
    ) {

        const senderDomain =
            email.split("@")[1] ||
            "";

        const replyDomain =
            reply.split("@")[1] ||
            "";


        if (
            senderDomain &&
            replyDomain &&
            senderDomain !== replyDomain
        ) {

            score += 25;


            flags.push({

                type:
                    "REPLY_TO_SPOOFING",

                message:
                    `Reply-To domain "${replyDomain}" differs from sender domain "${senderDomain}".`

            });

        }

    }


    // ========================================
    // 3. URGENCY
    // ========================================

    const urgencyWords = [

        "urgent",
        "immediately",
        "immediate action",
        "act now",
        "within 24 hours",
        "within 48 hours",
        "suspended",
        "will be closed",
        "final warning",
        "last warning",
        "expires today",
        "limited time",
        "action required"

    ];


    const urgencyMatches =
        urgencyWords.filter(
            word =>
                fullText.includes(word)
        );


    if (
        urgencyMatches.length
    ) {

        score += Math.min(
            urgencyMatches.length * 10,
            25
        );


        flags.push({

            type:
                "URGENCY",

            message:
                `Urgency language detected: ${urgencyMatches.join(", ")}.`

        });

    }


    // ========================================
    // 4. CREDENTIAL HARVESTING
    // ========================================

    const credentialWords = [

        "password",
        "username",
        "login",
        "sign in",
        "signin",
        "verify your account",
        "confirm your identity",
        "security verification",
        "bank details",
        "card number",
        "credit card",
        "debit card",
        "otp",
        "one time password"

    ];


    const credentialMatches =
        credentialWords.filter(
            word =>
                fullText.includes(word)
        );


    if (
        credentialMatches.length >= 2
    ) {

        score += 25;


        flags.push({

            type:
                "CREDENTIAL_HARVESTING",

            message:
                "Email requests or references multiple sensitive credentials."

        });

    }


    // ========================================
    // 5. EMAIL LINKS
    // ========================================

    const urls =
        fullText.match(
            /https?:\/\/[^\s<>"']+/gi
        ) || [];


    const suspiciousLinks = [];


    for (
        const url of urls
    ) {

        const result =
            analyzeURL(url);


        if (
            result.score >= 35
        ) {

            suspiciousLinks.push({

                url,

                score:
                    result.score

            });

        }

    }


    if (
        suspiciousLinks.length
    ) {

        score += 30;


        flags.push({

            type:
                "MALICIOUS_LINK",

            message:
                `${suspiciousLinks.length} suspicious link(s) detected in the email.`

        });

    }


    // ========================================
    // 6. THREAT LANGUAGE
    // ========================================

    const threateningPhrases = [

        "account will be locked",
        "account will be suspended",
        "unauthorized access",
        "security breach",
        "unusual activity",
        "verify immediately",
        "failure to verify"

    ];


    if (
        threateningPhrases.some(
            phrase =>
                fullText.includes(phrase)
        )
    ) {

        score += 15;


        flags.push({

            type:
                "THREAT_LANGUAGE",

            message:
                "Email uses threatening or fear-based security language."

        });

    }


    // ========================================
    // 7. LIMIT SCORE
    // ========================================

    score =
        Math.min(
            score,
            100
        );


    // ========================================
    // 8. EMAIL RISK LEVEL
    // ========================================

    let level;
    let status;


    if (
        score >= 70
    ) {

        level =
            "High Risk";

        status =
            "Dangerous";

    }

    else if (
        score >= 35
    ) {

        level =
            "Medium Risk";

        status =
            "Suspicious";

    }

    else {

        level =
            "Low Risk";

        status =
            "Safe";

    }


    // ========================================
    // 9. ATTACK CHAIN
    // ========================================

    const attackChain = [

        {

            stage: 1,

            name:
                "Suspicious Sender",

            detected:
                flags.some(
                    flag =>
                        flag.type ===
                            "SENDER_MISMATCH" ||

                        flag.type ===
                            "REPLY_TO_SPOOFING"
                )

        },


        {

            stage: 2,

            name:
                "Urgency",

            detected:
                flags.some(
                    flag =>
                        flag.type ===
                            "URGENCY" ||

                        flag.type ===
                            "THREAT_LANGUAGE"
                )

        },


        {

            stage: 3,

            name:
                "Malicious Link",

            detected:
                flags.some(
                    flag =>
                        flag.type ===
                            "MALICIOUS_LINK"
                )

        },


        {

            stage: 4,

            name:
                "Credential Harvesting",

            detected:
                flags.some(
                    flag =>
                        flag.type ===
                            "CREDENTIAL_HARVESTING"
                )

        }

    ];


    // ========================================
    // 10. EMAIL RESULT
    // ========================================

    return {

        score,

        level,

        status,

        flags,

        attackChain,

        suspiciousLinks

    };

}


// ============================================
// EXPORTS
// ============================================

module.exports = {

    analyzeURL,

    analyzeEmail

};