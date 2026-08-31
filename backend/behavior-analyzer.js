// ============================================
// PHISHGUARD PAGE BEHAVIOR ANALYZER
// ============================================
//
// Safely analyzes page-level signals.
//
// IMPORTANT:
// - Does NOT execute page JavaScript.
// - Does NOT download files.
// - Does NOT visit external URLs.
// - Does NOT assume that one signal means
//   a website is malicious.
//
// Input can contain:
//
// {
//     url,
//     title,
//     text,
//     html,
//     links,
//     forms,
//     iframes,
//     downloads,
//     redirects
// }
//
// ============================================


const BEHAVIOR_ENGINE_VERSION = "1.0.0";


// ============================================
// LIMITS
// ============================================

const MAX_TEXT_LENGTH = 50000;
const MAX_HTML_LENGTH = 100000;
const MAX_LINKS = 500;
const MAX_FORMS = 100;
const MAX_IFRAMES = 100;
const MAX_DOWNLOADS = 100;
const MAX_REDIRECTS = 50;


// ============================================
// NORMALIZE STRING
// ============================================

function safeString(value, maxLength = 10000) {

    if (
        typeof value !== "string"
    ) {
        return "";
    }

    return value
        .slice(0, maxLength)
        .trim();

}


// ============================================
// NORMALIZE ARRAY
// ============================================

function safeArray(
    value,
    maxLength
) {

    if (
        !Array.isArray(value)
    ) {
        return [];
    }

    return value
        .slice(0, maxLength);


}


// ============================================
// URL CHECK
// ============================================

function isHTTPURL(url) {

    return /^https?:\/\//i.test(
        String(url || "")
    );

}


// ============================================
// GET DOMAIN
// ============================================

function getDomain(url) {

    try {

        const parsed =
            new URL(url);

        return parsed.hostname
            .toLowerCase();

    } catch {

        return "";

    }

}


// ============================================
// GET ROOT DOMAIN
// ============================================

function getRootDomain(
    hostname
) {

    const parts =
        String(hostname || "")
            .split(".")
            .filter(Boolean);

    if (
        parts.length < 2
    ) {

        return hostname;

    }

    return parts
        .slice(-2)
        .join(".");

}


// ============================================
// CHECK EXTERNAL DOMAIN
// ============================================

function isExternalDomain(
    pageDomain,
    targetURL
) {

    if (
        !isHTTPURL(targetURL)
    ) {

        return false;

    }

    const targetDomain =
        getDomain(
            targetURL
        );

    if (
        !targetDomain ||
        !pageDomain
    ) {

        return false;

    }

    return (
        getRootDomain(
            targetDomain
        ) !==
        getRootDomain(
            pageDomain
        )
    );

}


// ============================================
// ADD SIGNAL
// ============================================

function addSignal(
    signals,
    type,
    severity,
    points,
    message,
    category
) {

    signals.push({

        type,

        severity,

        points,

        message,

        category

    });

}


// ============================================
// CREDENTIAL FORM DETECTION
// ============================================

function analyzeCredentialForms(
    forms,
    signals
) {

    let credentialForms = 0;


    for (
        const form of forms
    ) {

        const formText =
            JSON.stringify(
                form || {}
            )
            .toLowerCase();


        const hasPassword =
            formText.includes(
                "password"
            );


        const hasUsername =
            formText.includes(
                "username"
            ) ||
            formText.includes(
                "email"
            ) ||
            formText.includes(
                "login"
            );


        if (
            hasPassword &&
            hasUsername
        ) {

            credentialForms++;


            addSignal(

                signals,

                "CREDENTIAL_FORM",

                "MEDIUM",

                12,

                "Page contains a form requesting credential-related information.",

                "PHISHING"

            );

        }

    }


    return credentialForms;

}


// ============================================
// DOWNLOAD ANALYSIS
// ============================================

function analyzeDownloads(
    downloads,
    links,
    signals
) {

    let downloadCount = 0;


    const fileExtensions = [

        ".exe",
        ".msi",
        ".scr",
        ".bat",
        ".cmd",
        ".ps1",
        ".jar",
        ".apk",
        ".dmg",
        ".pkg",
        ".zip",
        ".rar",
        ".7z"

    ];


    for (
        const item of downloads
    ) {

        const value =
            typeof item === "string"
                ? item
                : JSON.stringify(item || {});


        const lower =
            value.toLowerCase();


        if (
            fileExtensions.some(
                extension =>
                    lower.includes(
                        extension
                    )
            )
        ) {

            downloadCount++;

        }

    }


    // Also inspect links supplied by
    // the content script.

    for (
        const link of links
    ) {

        const href =
            typeof link === "string"
                ? link
                : link?.href || "";

        const lower =
            href.toLowerCase();


        if (
            fileExtensions.some(
                extension =>
                    lower.includes(
                        extension
                    )
            )
        ) {

            downloadCount++;

        }

    }


    if (
        downloadCount >= 1
    ) {

        addSignal(

            signals,

            "FILE_DOWNLOAD_LINK",

            "MEDIUM",

            Math.min(
                15,
                downloadCount * 4
            ),

            `${downloadCount} potentially downloadable file link(s) detected.`,

            "DOWNLOAD_RISK"

        );

    }


    return downloadCount;

}


// ============================================
// FAKE DOWNLOAD INDICATORS
// ============================================

function analyzeFakeDownloadSignals(
    text,
    html,
    links,
    signals
) {

    const combined =
        `${text} ${html}`
            .toLowerCase();


    const downloadWords = [

        "download now",
        "free download",
        "download movie",
        "download apk",
        "click to download",
        "direct download",
        "watch and download",
        "download file"

    ];


    const matches =
        downloadWords.filter(
            word =>
                combined.includes(word)
        );


    if (
        matches.length >= 2
    ) {

        addSignal(

            signals,

            "MULTIPLE_DOWNLOAD_PROMPTS",

            "MEDIUM",

            10,

            "Page contains multiple download-oriented prompts.",

            "DOWNLOAD_RISK"

        );

    }


    // Many links containing download language
    // can indicate aggressive download pages.

    const downloadLinks =
        links.filter(
            link => {

                const href =
                    typeof link === "string"
                        ? link
                        : link?.href || "";

                const label =
                    typeof link === "string"
                        ? ""
                        : link?.text || "";

                const value =
                    `${href} ${label}`
                        .toLowerCase();

                return (
                    value.includes(
                        "download"
                    ) ||
                    value.includes(
                        "apk"
                    )
                );

            }
        );


    if (
        downloadLinks.length >= 5
    ) {

        addSignal(

            signals,

            "EXCESSIVE_DOWNLOAD_LINKS",

            "MEDIUM",

            12,

            "Page contains many download-related links.",

            "DOWNLOAD_RISK"

        );

    }

}


// ============================================
// POPUP / IFRAME ANALYSIS
// ============================================

function analyzeFrames(
    iframes,
    signals
) {

    if (
        iframes.length >= 10
    ) {

        addSignal(

            signals,

            "EXCESSIVE_IFRAMES",

            "LOW",

            8,

            "Page contains an unusually large number of iframes.",

            "PAGE_BEHAVIOR"

        );

    }


    return iframes.length;

}


// ============================================
// EXTERNAL LINK ANALYSIS
// ============================================

function analyzeExternalLinks(
    pageDomain,
    links,
    signals
) {

    let externalCount = 0;

    const externalDomains =
        new Set();


    for (
        const link of links
    ) {

        const href =
            typeof link === "string"
                ? link
                : link?.href || "";


        if (
            isExternalDomain(
                pageDomain,
                href
            )
        ) {

            externalCount++;


            const domain =
                getDomain(
                    href
                );


            if (
                domain
            ) {

                externalDomains.add(
                    domain
                );

            }

        }

    }


    if (
        externalCount >= 30
    ) {

        addSignal(

            signals,

            "EXCESSIVE_EXTERNAL_LINKS",

            "LOW",

            6,

            "Page contains a large number of external-domain links.",

            "PAGE_BEHAVIOR"

        );

    }


    if (
        externalDomains.size >= 20
    ) {

        addSignal(

            signals,

            "MANY_EXTERNAL_DOMAINS",

            "MEDIUM",

            10,

            "Page references many different external domains.",

            "PAGE_BEHAVIOR"

        );

    }


    return {

        externalCount,

        externalDomains:
            Array.from(
                externalDomains
            )

    };

}


// ============================================
// REDIRECT ANALYSIS
// ============================================

function analyzeRedirects(
    redirects,
    signals
) {

    const count =
        redirects.length;


    if (
        count >= 2
    ) {

        addSignal(

            signals,

            "REDIRECT_CHAIN",

            "MEDIUM",

            Math.min(
                20,
                count * 5
            ),

            `Page involved ${count} redirect step(s).`,

            "REDIRECT"

        );

    }


    if (
        count >= 5
    ) {

        addSignal(

            signals,

            "LONG_REDIRECT_CHAIN",

            "HIGH",

            20,

            "Page involved an unusually long redirect chain.",

            "REDIRECT"

        );

    }


    return count;

}


// ============================================
// SUSPICIOUS PAGE TEXT
// ============================================

function analyzeSuspiciousText(
    text,
    signals
) {

    const lower =
        text.toLowerCase();


    const credentialPatterns = [

        "enter your password",
        "confirm your password",
        "verify your account",
        "enter otp",
        "enter one time password",
        "enter card number",
        "enter cvv",
        "verify your identity"

    ];


    const matches =
        credentialPatterns.filter(
            phrase =>
                lower.includes(
                    phrase
                )
        );


    if (
        matches.length >= 2
    ) {

        addSignal(

            signals,

            "SENSITIVE_DATA_REQUEST",

            "HIGH",

            20,

            "Page contains multiple requests for sensitive account or payment information.",

            "PHISHING"

        );

    }


    const urgencyPatterns = [

        "act now",
        "verify immediately",
        "account suspended",
        "account will be closed",
        "last warning",
        "final warning",
        "expires today"

    ];


    const urgencyMatches =
        urgencyPatterns.filter(
            phrase =>
                lower.includes(
                    phrase
                )
        );


    if (
        urgencyMatches.length >= 2
    ) {

        addSignal(

            signals,

            "URGENT_PAGE_LANGUAGE",

            "MEDIUM",

            10,

            "Page uses multiple urgency or threat phrases.",

            "PHISHING"

        );

    }

}


// ============================================
// SUSPICIOUS HTML INDICATORS
// ============================================

function analyzeHTML(
    html,
    signals
) {

    const lower =
        html.toLowerCase();


    // ----------------------------------------
    // Data URI
    // ----------------------------------------

    const dataURIs =
        (
            lower.match(
                /data:text\/html/g
            ) ||
            []
        ).length;


    if (
        dataURIs >= 2
    ) {

        addSignal(

            signals,

            "DATA_URI_HTML",

            "HIGH",

            18,

            "Page contains multiple HTML data-URI indicators.",

            "OBFUSCATION"

        );

    }


    // ----------------------------------------
    // Inline JavaScript volume
    // ----------------------------------------

    const scriptTags =
        (
            lower.match(
                /<script\b/g
            ) ||
            []
        ).length;


    if (
        scriptTags >= 30
    ) {

        addSignal(

            signals,

            "EXCESSIVE_SCRIPT_TAGS",

            "LOW",

            6,

            "Page contains an unusually large number of script tags.",

            "PAGE_BEHAVIOR"

        );

    }


    // ----------------------------------------
    // Hidden elements
    // ----------------------------------------

    const hiddenElements =
        (
            lower.match(
                /(display\s*:\s*none|visibility\s*:\s*hidden|type\s*=\s*["']hidden["'])/g
            ) ||
            []
        ).length;


    if (
        hiddenElements >= 10
    ) {

        addSignal(

            signals,

            "MANY_HIDDEN_ELEMENTS",

            "LOW",

            6,

            "Page contains many hidden elements.",

            "OBFUSCATION"

        );

    }


    return {

        scriptTags,

        hiddenElements,

        dataURIs

    };

}


// ============================================
// MAIN PAGE ANALYZER
// ============================================

function analyzePage(
    pageData = {}
) {

    const url =
        safeString(
            pageData.url,
            2000
        );


    const title =
        safeString(
            pageData.title,
            1000
        );


    const text =
        safeString(
            pageData.text,
            MAX_TEXT_LENGTH
        );


    const html =
        safeString(
            pageData.html,
            MAX_HTML_LENGTH
        );


    const links =
        safeArray(
            pageData.links,
            MAX_LINKS
        );


    const forms =
        safeArray(
            pageData.forms,
            MAX_FORMS
        );


    const iframes =
        safeArray(
            pageData.iframes,
            MAX_IFRAMES
        );


    const downloads =
        safeArray(
            pageData.downloads,
            MAX_DOWNLOADS
        );


    const redirects =
        safeArray(
            pageData.redirects,
            MAX_REDIRECTS
        );


    const pageDomain =
        getDomain(
            url
        );


    const signals = [];


    // ========================================
    // ANALYZE PAGE
    // ========================================

    const credentialForms =
        analyzeCredentialForms(
            forms,
            signals
        );


    const downloadCount =
        analyzeDownloads(
            downloads,
            links,
            signals
        );


    analyzeFakeDownloadSignals(

        text,

        html,

        links,

        signals

    );


    const iframeCount =
        analyzeFrames(
            iframes,
            signals
        );


    const external =
        analyzeExternalLinks(

            pageDomain,

            links,

            signals

        );


    const redirectCount =
        analyzeRedirects(

            redirects,

            signals

        );


    analyzeSuspiciousText(

        text,

        signals

    );


    const htmlAnalysis =
        analyzeHTML(

            html,

            signals

        );


    // ========================================
    // CALCULATE SCORE
    // ========================================

    let score = 0;


    for (
        const signal of signals
    ) {

        score +=
            Number(
                signal.points
            ) || 0;

    }


    score =
        Math.min(
            100,
            Math.max(
                0,
                score
            )
        );


    // ========================================
    // VERDICT
    // ========================================

    let verdict;
    let level;
    let confidence;


    if (
        score >= 70
    ) {

        verdict =
            "dangerous";

        level =
            "High Risk";

        confidence =
            "high";

    }

    else if (
        score >= 40
    ) {

        verdict =
            "suspicious";

        level =
            "Medium Risk";

        confidence =
            "medium";

    }

    else if (
        score >= 20
    ) {

        verdict =
            "caution";

        level =
            "Low Risk";

        confidence =
            "low";

    }

    else {

        verdict =
            "low-risk";

        level =
            "Low Risk";

        confidence =
            "low";

    }


    // ========================================
    // CATEGORIES
    // ========================================

    const categories =
        Array.from(
            new Set(
                signals
                    .map(
                        signal =>
                            signal.category
                    )
                    .filter(Boolean)
            )
        );


    // ========================================
    // SUMMARY
    // ========================================

    let summary;


    if (
        signals.length === 0
    ) {

        summary =
            "No significant page behavior indicators detected.";

    }

    else if (
        verdict === "dangerous"
    ) {

        summary =
            "Multiple potentially dangerous page behavior indicators were detected.";

    }

    else if (
        verdict === "suspicious"
    ) {

        summary =
            "Several suspicious page behavior indicators were detected.";

    }

    else {

        summary =
            "Some page behavior indicators require caution.";

    }


    // ========================================
    // RESULT
    // ========================================

    return {

        success:
            true,

        score,

        verdict,

        level,

        confidence,

        summary,

        domain:
            pageDomain,

        title,

        categories,

        signals,

        metrics: {

            linkCount:
                links.length,

            externalLinkCount:
                external.externalCount,

            externalDomainCount:
                external.externalDomains.length,

            credentialFormCount:
                credentialForms,

            downloadCount,

            iframeCount,

            redirectCount,

            scriptTagCount:
                htmlAnalysis.scriptTags,

            hiddenElementCount:
                htmlAnalysis.hiddenElements,

            dataURICount:
                htmlAnalysis.dataURIs

        },

        engine: {

            name:
                "PhishGuard Page Behavior Analyzer",

            version:
                BEHAVIOR_ENGINE_VERSION

        }

    };

}


// ============================================
// EXPORTS
// ============================================

module.exports = {

    analyzePage,

    analyzeCredentialForms,

    analyzeDownloads,

    analyzeRedirects,

    analyzeExternalLinks,

    analyzeSuspiciousText,

    analyzeHTML

};