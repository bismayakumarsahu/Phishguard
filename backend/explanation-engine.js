const ENGINE_NAME = "PhishGuard Explainable AI (offline)";

const SEVERITY_RANK = {
    LOW: 1,
    MEDIUM: 2,
    HIGH: 3,
    CRITICAL: 4
};

const TYPE_TITLES = {
    NO_HTTPS: "Unencrypted connection",
    INVALID_URL: "Malformed URL",
    IP_ADDRESS: "Raw IP address",
    URL_AT_OBFUSCATION: "Obfuscated URL (@ symbol)",
    URL_OBFUSCATION: "Obfuscated URL",
    URL_SHORTENER: "Shortened URL",
    SUSPICIOUS_TLD: "High-risk top-level domain",
    TYPOSQUATTING: "Possible typosquatting",
    LOOKALIKE_DOMAIN: "Look-alike domain",
    PUNYCODE: "Unicode/punycode domain",
    DEEP_SUBDOMAIN: "Deep subdomain chain",
    EXCESSIVE_SUBDOMAINS: "Excessive subdomains",
    LONG_HOSTNAME: "Unusually long hostname",
    LONG_URL: "Unusually long URL",
    EXCESSIVE_HYPHENS: "Excessive hyphens in domain",
    EXCESSIVE_DIGITS: "Excessive digits in domain",
    MANY_PARAMETERS: "Unusually many URL parameters",
    REDIRECT: "Redirect detected",
    REDIRECT_CHAIN: "Redirect chain detected",
    LONG_REDIRECT_CHAIN: "Long redirect chain",
    REDIRECT_INDICATORS: "Redirect indicators",
    CREDENTIAL_FORM: "Credential form detected",
    CREDENTIAL_HARVESTING: "Credential harvesting pattern",
    CREDENTIAL_PATH: "Credential-related path",
    LOGIN_FORM: "Login form detected",
    PASSWORD_FIELD: "Password field detected",
    SENSITIVE_DATA_REQUEST: "Sensitive data requested",
    URGENCY: "Urgency pressure",
    URGENT_PAGE_LANGUAGE: "Urgent page language",
    PHISHING_KEYWORDS: "Phishing keywords",
    THREAT_LANGUAGE: "Threatening language",
    BRAND_IMPERSONATION: "Brand impersonation",
    SPOOFED_BRAND: "Spoofed brand",
    DEEPFAKE_INDICATORS: "Deepfake indicators",
    PAYMENT_REQUEST: "Payment request",
    FINANCIAL_REQUEST: "Financial request",
    DOWNLOAD_RISK: "Risky download",
    SUSPICIOUS_DOWNLOAD_PATH: "Suspicious download path",
    FILE_DOWNLOAD_LINK: "File download link",
    MALICIOUS_LINK: "Malicious link",
    HIGH_RISK_CONTENT: "High-risk content",
    DATA_URI_HTML: "Embedded HTML payload",
    EXCESSIVE_IFRAMES: "Excessive iframes",
    EXCESSIVE_SCRIPT_TAGS: "Excessive scripts",
    MANY_HIDDEN_ELEMENTS: "Hidden page elements",
    MANY_EXTERNAL_DOMAINS: "Many external domains",
    EXCESSIVE_EXTERNAL_LINKS: "Excessive external links",
    PAGE_BEHAVIOR: "Suspicious page behavior",
    THREAT_INTELLIGENCE: "Threat intelligence match",
    VIRUSTOTAL: "VirusTotal detection",
    SENDER_MISMATCH: "Sender mismatch",
    REPLY_TO_SPOOFING: "Reply-To spoofing",
    EMAIL_AUTH: "Email authentication failure",
    ATTACHMENT_RISK: "Risky attachment",
    ATTACHMENT: "Attachment detected",
    PHISHING: "Phishing indicators",
    IMPERSONATION: "Impersonation indicators",
    MALICIOUS: "Malicious indicators",
    SUSPICIOUS_ACTIVITY: "Suspicious activity",
    GENERAL: "Suspicious indicator"
};

const TYPE_ADVICE = [
    {
        test: /NO_HTTPS|TRANSPORT/,
        advice: "Avoid entering passwords, OTPs, or payment details on this unencrypted (HTTP) page."
    },
    {
        test: /URL_SHORTENER/,
        advice: "Preview or expand the shortened link before opening it so you can see the real destination."
    },
    {
        test: /IP_ADDRESS/,
        advice: "Treat a raw IP address on a login or payment page as unusual and verify the service independently."
    },
    {
        test: /PUNYCODE|UNICODE|IDN/,
        advice: "Check the domain character by character; Unicode look-alike domains are a common spoofing trick."
    },
    {
        test: /TYPOSQUATTING|LOOKALIKE|LOOK_LIKE|SPOOFED_BRAND|BRAND_IMPERSONATION/,
        advice: "Compare the domain letter by letter with the official site and navigate there manually."
    },
    {
        test: /CREDENTIAL|LOGIN_FORM|PASSWORD|SENSITIVE_DATA|PHISHING_KEYWORDS/,
        advice: "Never enter credentials unless you typed the address yourself or used a trusted bookmark."
    },
    {
        test: /URGENCY|URGENT|THREAT_LANGUAGE/,
        advice: "Ignore pressure tactics such as “act now”, “account closed”, or threats of a fine."
    },
    {
        test: /PAYMENT|FINANCIAL|MONEY|CRYPTO/,
        advice: "Do not send money, gift cards, or cryptocurrency based on this message."
    },
    {
        test: /DOWNLOAD|ATTACHMENT|FILE_|HIGH_RISK_CONTENT|MALWARE/,
        advice: "Do not open the attachment or run the download; verify the file with the sender first."
    },
    {
        test: /THREAT_INTELLIGENCE|VIRUSTOTAL|MALICIOUS_LINK/,
        advice: "This destination was flagged as malicious by the analysis engines; block it and report it."
    },
    {
        test: /SENDER_MISMATCH|REPLY_TO|EMAIL_AUTH/,
        advice: "The sender details are inconsistent; verify the real address through a separate, trusted channel."
    },
    {
        test: /OBFUSCATION|HIDDEN|DATA_URI|IFRAME|SCRIPT_TAGS/,
        advice: "Hidden or obfuscated content can bypass filters; do not interact with the page."
    },
    {
        test: /REDIRECT/,
        advice: "Check the final destination after redirects; do not assume the visible link is the real target."
    },
    {
        test: /SUSPICIOUS_TLD/,
        advice: "Be skeptical of unusual top-level domains and confirm the brand's real website address."
    },
    {
        test: /DEEP_SUBDOMAIN|LONG_HOSTNAME|EXCESSIVE_HYPHENS|EXCESSIVE_DIGITS/,
        advice: "Unusual hostname structure is often used to imitate trusted brands; verify the exact domain."
    }
];

function clamp(value, min = 0, max = 100) {
    const number = Number(value);
    if (!Number.isFinite(number)) {
        return min;
    }
    return Math.min(Math.max(number, min), max);
}

function normalizeSeverity(value) {
    const severity = String(value || "").toUpperCase();
    if (SEVERITY_RANK[severity]) {
        return severity;
    }
    if (severity === "DANGEROUS" || severity === "CRITICAL") {
        return "HIGH";
    }
    if (severity === "INFO" || severity === "NONE") {
        return "LOW";
    }
    return "MEDIUM";
}

function severityRank(value) {
    return SEVERITY_RANK[normalizeSeverity(value)] || 0;
}

function humanizeType(type) {
    if (TYPE_TITLES[type]) {
        return TYPE_TITLES[type];
    }
    return String(type || "Indicator")
        .toLowerCase()
        .replace(/_/g, " ")
        .replace(/\b\w/g, character => character.toUpperCase());
}

function normalizeFlag(flag, index) {
    if (typeof flag === "string") {
        return {
            type: "GENERAL",
            title: "Suspicious indicator",
            detail: flag,
            message: flag,
            severity: "MEDIUM",
            points: 0,
            key: `general-${index}`
        };
    }

    if (!flag || typeof flag !== "object") {
        return null;
    }

    const type = String(
        flag.type ||
        flag.category ||
        flag.code ||
        flag.name ||
        "INDICATOR"
    ).toUpperCase();

    const message = String(
        flag.message ||
        flag.detail ||
        flag.description ||
        flag.reason ||
        flag.summary ||
        "Suspicious indicator detected."
    );

    return {
        type,
        title: flag.title ? String(flag.title) : humanizeType(type),
        detail: message,
        message,
        severity: normalizeSeverity(flag.severity || flag.risk || flag.level),
        points: clamp(Number(flag.points) || 0, 0, 100),
        key: `${type}-${message}`
    };
}

function uniqueFlags(flags) {
    const seen = new Set();
    const result = [];

    flags.forEach(flag => {
        const normalized = normalizeFlag(flag, result.length);
        if (!normalized || seen.has(normalized.key)) {
            return;
        }
        seen.add(normalized.key);
        result.push(normalized);
    });

    return result;
}

function getLevel(score) {
    if (score >= 80) return "CRITICAL";
    if (score >= 60) return "HIGH";
    if (score >= 35) return "MEDIUM";
    if (score >= 15) return "LOW";
    return "SAFE";
}

function getNoun(type) {
    if (type === "email") return "email";
    if (type === "page") return "web page";
    if (type === "sms") return "message";
    return "URL";
}

function buildHeadline(score, level, noun) {
    if (score >= 80) return `Dangerous ${noun} detected`;
    if (score >= 60) return `High-risk ${noun}`;
    if (score >= 35) return `Suspicious ${noun}`;
    if (score >= 15) return `Low-risk ${noun}`;
    return `No major threat detected in this ${noun}`;
}

function buildSummary({ score, level, noun, flags, categories, type }) {
    const highSeverity = flags.filter(flag => severityRank(flag.severity) >= 3);

    if (score >= 80) {
        const driver = highSeverity[0] || flags[0];
        return `PhishGuard found strong evidence that this ${noun} is dangerous. ` +
            (driver
                ? `The main driver is: ${driver.message} `
                : "") +
            "Do not interact with it until you have verified it through an independent, official channel.";
    }

    if (score >= 60) {
        return `Multiple high-risk signals were found in this ${noun}. ` +
            "The combination is consistent with phishing, credential theft, or malicious content. " +
            "Avoid signing in, downloading files, or sending any information.";
    }

    if (score >= 35) {
        const categoryText = categories.length
            ? ` Categories involved: ${categories.slice(0, 3).join(", ")}.`
            : "";
        return `This ${noun} shows several suspicious characteristics and should be treated with caution.${categoryText} ` +
            "Verify the sender or website independently before taking any action.";
    }

    if (score >= 15) {
        return `Only minor risk indicators were found in this ${noun}. ` +
            "There is no strong phishing pattern, but a quick independent check is still recommended before sharing sensitive data.";
    }

    const categoryText = categories.length
        ? ` Categories reviewed: ${categories.slice(0, 3).join(", ")}.`
        : "";
    return `No significant phishing, malware, or impersonation indicators were found in this ${noun}.${categoryText} ` +
        "The local analysis engines rated the content as low risk.";
}

function buildReasons({
    score,
    level,
    flags,
    heuristicScore,
    aiScore,
    threatIntelScore,
    threatReputation,
    categories,
    urlFeatures,
    type
}) {
    const reasons = [];

    reasons.push(`Overall risk score is ${score}/100 (${level}).`);
    reasons.push("The final score is a weighted fusion of the heuristic, AI, and threat-intelligence engines.");

    if (heuristicScore > 0) {
        reasons.push(`Traditional security heuristics contributed ${Math.round(heuristicScore)} risk points.`);
    }

    if (aiScore > 0) {
        reasons.push(`The AI feature engine scored the content at ${Math.round(aiScore)}/100.`);
    }

    if (threatIntelScore > 0) {
        reasons.push(`Threat-intelligence signals contributed ${Math.round(threatIntelScore)} risk points.`);
    }

    if (threatReputation === "malicious") {
        reasons.push("Threat-intelligence sources classify this destination as malicious.");
    } else if (threatReputation === "suspicious") {
        reasons.push("Threat-intelligence sources returned suspicious indicators for this destination.");
    }

    if (urlFeatures) {
        const featureReasons = [];

        if (urlFeatures.lookalikeDomain) {
            featureReasons.push("the domain resembles a trusted brand");
        }
        if (urlFeatures.ipHost || urlFeatures.hasIPAddress) {
            featureReasons.push("the URL uses a raw IP address");
        }
        if (urlFeatures.suspiciousTld) {
            featureReasons.push("the top-level domain is high risk");
        }
        if (urlFeatures.hasPunycode) {
            featureReasons.push("the domain uses Unicode/punycode encoding");
        }
        if (urlFeatures.urlShortener) {
            featureReasons.push("a URL shortener hides the destination");
        }
        if (urlFeatures.tooManySubdomains || urlFeatures.deepSubdomain) {
            featureReasons.push("the hostname has an unusual subdomain structure");
        }

        if (featureReasons.length) {
            reasons.push(`URL analysis found that ${featureReasons.slice(0, 3).join(", ")}.`);
        }
    }

    if (flags.length === 0) {
        reasons.push("No phishing, malware, or impersonation indicators were found by the local analysis engines.");
    } else {
        const topFlags = flags
            .slice()
            .sort((a, b) => severityRank(b.severity) - severityRank(a.severity))
            .slice(0, 3);

        topFlags.forEach(flag => {
            reasons.push(`${flag.title}: ${flag.detail}`);
        });
    }

    if (categories.length) {
        reasons.push(`Categories matched: ${categories.slice(0, 4).join(", ")}.`);
    }

    return reasons;
}

function buildRecommendations({ score, flags, type }) {
    const recommendations = [];

    flags.forEach(flag => {
        TYPE_ADVICE.forEach(rule => {
            if (rule.test.test(flag.type)) {
                recommendations.push(rule.advice);
            }
        });
    });

    if (score >= 80) {
        recommendations.push("Do not open the link, attachment, or sign-in page.");
        recommendations.push("Close the page and delete the message if it arrived unexpectedly.");
        recommendations.push("If you already entered credentials, change the password immediately and enable two-factor authentication.");
        recommendations.push("Verify the account through the official app or by typing the known address yourself.");
    } else if (score >= 60) {
        recommendations.push("Avoid signing in, entering payment details, or downloading files.");
        recommendations.push("Verify the sender or website through an independent, official channel.");
        recommendations.push("Report the message or domain to your security team or email provider.");
    } else if (score >= 35) {
        recommendations.push("Treat the content as suspicious until you verify it independently.");
        recommendations.push("Do not enter credentials, OTPs, or payment information.");
        recommendations.push("Open the official website manually instead of using the supplied link.");
    } else if (score >= 15) {
        recommendations.push("No strong attack pattern was found, but confirm unexpected requests through a separate channel.");
        recommendations.push("Keep two-factor authentication enabled on important accounts.");
    } else {
        recommendations.push("No significant phishing indicators were found.");
        recommendations.push("Continue to verify unexpected requests through a separate channel.");
        recommendations.push("Keep your browser, operating system, and security extensions up to date.");
    }

    if (type === "email") {
        recommendations.push("Check the full sender address, not just the display name.");
    }

    return Array.from(new Set(recommendations)).slice(0, 8);
}

function buildIndicators(flags) {
    return flags
        .slice()
        .sort((a, b) => severityRank(b.severity) - severityRank(a.severity))
        .slice(0, 8)
        .map(flag => ({
            type: flag.type,
            title: flag.title,
            detail: flag.detail,
            severity: flag.severity
        }));
}

function buildScanExplanation(scanResult = {}, context = {}) {
    const score = Math.round(clamp(
        scanResult.score ??
        scanResult.riskScore ??
        0
    ));

    const level = String(
        scanResult.level ||
        scanResult.riskLevel ||
        getLevel(score)
    ).toUpperCase();

    const verdict = String(
        scanResult.verdict ||
        scanResult.status ||
        (score >= 70 ? "THREAT_DETECTED" : score >= 35 ? "SUSPICIOUS" : "LOW_RISK")
    ).toUpperCase();

    const type = String(context.type || scanResult.type || "url").toLowerCase();
    const noun = getNoun(type);

    const flags = uniqueFlags(
        Array.isArray(scanResult.flags)
            ? scanResult.flags
            : Array.isArray(scanResult.evidence)
                ? scanResult.evidence
                : []
    );

    const categories = Array.from(new Set(
        (Array.isArray(scanResult.categories) ? scanResult.categories : [])
            .map(category => String(category || "").toUpperCase())
            .filter(Boolean)
    ));

    const heuristicScore = Number(
        scanResult.heuristicScore ??
        scanResult.engine?.heuristicScore ??
        scanResult.ai?.heuristicScore ??
        0
    ) || 0;

    const aiScore = Number(
        scanResult.ai?.score ??
        scanResult.aiScore ??
        0
    ) || 0;

    const threatIntelScore = Number(
        scanResult.threatIntelligence?.score ??
        scanResult.threatIntelScore ??
        0
    ) || 0;

    const threatReputation = String(
        scanResult.threatIntelligence?.reputation ??
        scanResult.threatIntel?.reputation ??
        "unknown"
    ).toLowerCase();

    const confidence = String(
        scanResult.confidence ||
        (score >= 60 ? "high" : score >= 35 ? "medium" : "low")
    ).toLowerCase();

    return {
        engine: ENGINE_NAME,
        headline: buildHeadline(score, level, noun),
        summary: buildSummary({
            score,
            level,
            noun,
            flags,
            categories,
            type
        }),
        score,
        level,
        verdict,
        confidence,
        reasons: buildReasons({
            score,
            level,
            flags,
            heuristicScore,
            aiScore,
            threatIntelScore,
            threatReputation,
            categories,
            urlFeatures: scanResult.urlFeatures,
            type
        }),
        indicators: buildIndicators(flags),
        recommendations: buildRecommendations({
            score,
            flags,
            type
        }),
        generatedAt: new Date().toISOString()
    };
}

module.exports = {
    buildScanExplanation,
    getLevel,
    humanizeType,
    normalizeSeverity
};