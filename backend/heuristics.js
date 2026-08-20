// ============================================
// LEVENSHTEIN DISTANCE
// ============================================

function levenshteinDistance(a, b) {

    const matrix = [];

    for (let i = 0; i <= b.length; i++) {
        matrix[i] = [i];
    }

    for (let j = 0; j <= a.length; j++) {
        matrix[0][j] = j;
    }

    for (let i = 1; i <= b.length; i++) {

        for (let j = 1; j <= a.length; j++) {

            if (b.charAt(i - 1) === a.charAt(j - 1)) {

                matrix[i][j] =
                    matrix[i - 1][j - 1];

            } else {

                matrix[i][j] = Math.min(
                    matrix[i - 1][j - 1] + 1,
                    matrix[i][j - 1] + 1,
                    matrix[i - 1][j] + 1
                );

            }
        }
    }

    return matrix[b.length][a.length];
}


// ============================================
// URL ANALYZER
// ============================================

function analyzeURL(url) {

    let score = 0;
    const flags = [];

    const lowerURL = url.toLowerCase();


// ============================================
// TYPOSQUATTING DETECTION
// ============================================

    const trustedBrands = [
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

    try {

        const normalizedURL =
            lowerURL.startsWith("http")
                ? lowerURL
                : "https://" + lowerURL;

        const hostname =
            new URL(normalizedURL).hostname;

        const domainParts =
            hostname.split(".");

        const domain =
            domainParts.length >= 2
                ? domainParts[domainParts.length - 2]
                : hostname;

        for (const brand of trustedBrands) {

            const distance =
                levenshteinDistance(domain, brand);

            if (domain === brand) {
                continue;
            }

            if (
                distance > 0 &&
                distance <= 2
            ) {

                score += 35;

                flags.push({
                    type: "TYPOSQUATTING",
                    message:
                        `Possible ${brand} impersonation detected. Domain "${domain}" is very similar to "${brand}".`
                });

                break;
            }
        }

    } catch (error) {

        // URL validation is handled below.

    }


// ============================================
// IP-BASED URL
// ============================================

    const ipPattern =
        /^(https?:\/\/)?(\d{1,3}\.){3}\d{1,3}/;

    if (ipPattern.test(lowerURL)) {

        score += 30;

        flags.push({
            type: "IP_ADDRESS",
            message:
                "URL uses an IP address instead of a normal domain."
        });
    }


// ============================================
// @ OBFUSCATION
// ============================================

    if (lowerURL.includes("@")) {

        score += 25;

        flags.push({
            type: "OBFUSCATION",
            message:
                "URL contains '@', which can be used for URL obfuscation."
        });
    }


// ============================================
// URL SHORTENERS
// ============================================

    const shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "cutt.ly",
        "rb.gy"
    ];

    for (const shortener of shorteners) {

        if (lowerURL.includes(shortener)) {

            score += 20;

            flags.push({
                type: "URL_SHORTENER",
                message:
                    "URL uses a URL shortening service."
            });

            break;
        }
    }

// ============================================
// TRUSTED DOMAINS
// ============================================

const trustedDomains = [
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

let isTrustedDomain = false;

try {

    const parsedURL =
        new URL(
            lowerURL.startsWith("http")
                ? lowerURL
                : "https://" + lowerURL
        );

    const hostname =
        parsedURL.hostname.toLowerCase();

    isTrustedDomain =
        trustedDomains.some(domain =>
            hostname === domain ||
            hostname.endsWith("." + domain)
        );

} catch (error) {

    isTrustedDomain = false;

}

// ============================================
// SUSPICIOUS TLD
// ============================================

    const suspiciousTLDs = [
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".gq",
        ".top",
        ".xyz",
        ".click"
    ];

    for (const tld of suspiciousTLDs) {

        if (lowerURL.includes(tld)) {

            score += 20;

            flags.push({
                type: "SUSPICIOUS_TLD",
                message:
                    `Suspicious top-level domain detected: ${tld}`
            });

            break;
        }
    }


//// ============================================
// EXCESSIVE HYPHENS
// ============================================

// Only count hyphens in the domain.
// Do NOT count hyphens inside the URL path.

let domainHyphenCount = 0;

try {

    const parsed =
        new URL(
            lowerURL.startsWith("http")
                ? lowerURL
                : "https://" + lowerURL
        );

    domainHyphenCount =
        (parsed.hostname.match(/-/g) || []).length;

} catch (error) {

    domainHyphenCount = 0;

}


if (domainHyphenCount >= 3) {

    score += 15;

    flags.push({

        type: "EXCESSIVE_HYPHENS",

        message:
            "Domain contains an unusually high number of hyphens."

    });

}

// ============================================
// PHISHING KEYWORDS
// ============================================

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
        "recover"
    ];

    const keywordMatches = [];

    phishingKeywords.forEach(keyword => {
if (
    !isTrustedDomain &&
    lowerURL.includes(keyword)
) {
    keywordMatches.push(keyword);
}

    });

    if (keywordMatches.length >= 2) {

        score += 20;

        flags.push({
            type: "PHISHING_KEYWORDS",
            message:
                `Multiple phishing-related keywords detected: ${keywordMatches.join(", ")}`
        });
    }


// ============================================
// BRAND IMPERSONATION
// ============================================

    const brands = [
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

    for (const brand of brands) {

        if (
            lowerURL.includes(brand + "-") ||
            lowerURL.includes(brand + "login") ||
            lowerURL.includes("secure-" + brand) ||
            lowerURL.includes(brand + "verify")
        ) {

            score += 25;

            flags.push({
                type: "BRAND_IMPERSONATION",
                message:
                    `Possible ${brand} impersonation detected.`
            });

            break;
        }
    }


// ============================================
// MAXIMUM RISK SCORE
// ============================================

    score = Math.min(score, 100);


// ============================================
// RISK LEVEL
// ============================================

    let level;
    let status;

    if (score >= 70) {

        level = "High Risk";
        status = "Dangerous";

    } else if (score >= 35) {

        level = "Medium Risk";
        status = "Suspicious";

    } else {

        level = "Low Risk";
        status = "Safe";
    }


// ============================================
// URL RESULT
// ============================================

    return {
        score,
        level,
        status,
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
        senderName.toLowerCase().trim();

    const email =
        senderEmail.toLowerCase().trim();

    const reply =
        replyTo.toLowerCase().trim();

    const fullText =
        `${subject} ${body}`.toLowerCase();


// ============================================
// 1. SENDER DISPLAY NAME VS EMAIL
// ============================================

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
        trustedBrands.find(brand =>
            name.includes(brand)
        );

    if (suspiciousBrand && email) {

        const emailDomain =
            email.split("@")[1] || "";

        const trustedDomains = {

            paypal: ["paypal.com"],

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

        const allowedDomains =
            trustedDomains[suspiciousBrand] || [];

        if (
            !allowedDomains.some(domain =>
                emailDomain === domain ||
                emailDomain.endsWith("." + domain)
            )
        ) {

            score += 30;

            flags.push({
                type: "SENDER_MISMATCH",
                message:
                    `Sender claims to represent ${suspiciousBrand}, but the email domain is "${emailDomain}".`
            });
        }
    }


// ============================================
// 2. REPLY-TO SPOOFING
// ============================================

    if (reply && email) {

        const senderDomain =
            email.split("@")[1] || "";

        const replyDomain =
            reply.split("@")[1] || "";

        if (
            senderDomain &&
            replyDomain &&
            senderDomain !== replyDomain
        ) {

            score += 25;

            flags.push({
                type: "REPLY_TO_SPOOFING",
                message:
                    `Reply-To domain "${replyDomain}" differs from sender domain "${senderDomain}".`
            });
        }
    }


// ============================================
// 3. URGENCY LANGUAGE
// ============================================

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
        urgencyWords.filter(word =>
            fullText.includes(word)
        );

    if (urgencyMatches.length > 0) {

        score += Math.min(
            urgencyMatches.length * 10,
            25
        );

        flags.push({
            type: "URGENCY",
            message:
                `Urgency language detected: ${urgencyMatches.join(", ")}.`
        });
    }


// ============================================
// 4. CREDENTIAL HARVESTING
// ============================================

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
        credentialWords.filter(word =>
            fullText.includes(word)
        );

    if (credentialMatches.length >= 2) {

        score += 25;

        flags.push({
            type: "CREDENTIAL_HARVESTING",
            message:
                "Email requests or references multiple sensitive credentials."
        });
    }


// ============================================
// 5. SUSPICIOUS LINKS
// ============================================

    const urls =
        fullText.match(
            /https?:\/\/[^\s<>"']+/gi
        ) || [];

    const suspiciousLinks = [];

    for (const url of urls) {

        const result =
            analyzeURL(url);

        if (result.score >= 35) {

            suspiciousLinks.push({
                url,
                score: result.score
            });
        }
    }

    if (suspiciousLinks.length > 0) {

        score += 30;

        flags.push({
            type: "MALICIOUS_LINK",
            message:
                `${suspiciousLinks.length} suspicious link(s) detected in the email.`
        });
    }


// ============================================
// 6. THREAT LANGUAGE
// ============================================

    const threateningPhrases = [
        "account will be locked",
        "account will be suspended",
        "unauthorized access",
        "security breach",
        "unusual activity",
        "verify immediately",
        "failure to verify"
    ];

    const threatMatch =
        threateningPhrases.some(phrase =>
            fullText.includes(phrase)
        );

    if (threatMatch) {

        score += 15;

        flags.push({
            type: "THREAT_LANGUAGE",
            message:
                "Email uses threatening or fear-based security language."
        });
    }


// ============================================
// LIMIT SCORE
// ============================================

    score = Math.min(score, 100);


// ============================================
// EMAIL RISK LEVEL
// ============================================

    let level;
    let status;

    if (score >= 70) {

        level = "High Risk";
        status = "Dangerous";

    } else if (score >= 35) {

        level = "Medium Risk";
        status = "Suspicious";

    } else {

        level = "Low Risk";
        status = "Safe";
    }


// ============================================
// ATTACK CHAIN
// ============================================

    const attackChain = [

        {
            stage: 1,
            name: "Suspicious Sender",
            detected:
                flags.some(flag =>
                    flag.type === "SENDER_MISMATCH" ||
                    flag.type === "REPLY_TO_SPOOFING"
                )
        },

        {
            stage: 2,
            name: "Urgency",
            detected:
                flags.some(flag =>
                    flag.type === "URGENCY" ||
                    flag.type === "THREAT_LANGUAGE"
                )
        },

        {
            stage: 3,
            name: "Malicious Link",
            detected:
                flags.some(flag =>
                    flag.type === "MALICIOUS_LINK"
                )
        },

        {
            stage: 4,
            name: "Credential Harvesting",
            detected:
                flags.some(flag =>
                    flag.type === "CREDENTIAL_HARVESTING"
                )
        }

    ];


// ============================================
// EMAIL RESULT
// ============================================

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
// EXPORT FUNCTIONS
// ============================================

module.exports = {

    analyzeURL,
    analyzeEmail

};