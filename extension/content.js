// ============================================
// PHISHGUARD CONTENT SCRIPT
// ============================================

let currentTooltip = null;
let scanTimeout = null;

let currentPageScanURL = null;
let currentPageScanResult = null;

let pageAnalysisInProgress = false;


// ============================================
// CREATE RISK BADGE
// ============================================

function createRiskBadge() {

    if (currentTooltip) {
        currentTooltip.remove();
    }

    const badge =
        document.createElement("div");

    badge.id =
        "phishguard-risk-badge";

    badge.style.position =
        "fixed";

    badge.style.zIndex =
        "2147483647";

    badge.style.padding =
        "8px 12px";

    badge.style.borderRadius =
        "8px";

    badge.style.fontFamily =
        "Arial, sans-serif";

    badge.style.fontSize =
        "12px";

    badge.style.fontWeight =
        "600";

    badge.style.color =
        "#ffffff";

    badge.style.background =
        "#111827";

    badge.style.boxShadow =
        "0 4px 15px rgba(0,0,0,0.3)";

    badge.style.pointerEvents =
        "none";

    badge.style.display =
        "none";

    document.body.appendChild(
        badge
    );

    currentTooltip =
        badge;

    return badge;

}


// ============================================
// GET RISK INFORMATION
// ============================================

function getRiskDisplay(result) {

    const score =
        Number(result?.score) || 0;


    if (
        result?.verdict === "dangerous" ||
        score >= 70
    ) {

        return {

            icon: "🔴",

            color: "#ef4444",

            label: "HIGH RISK"

        };

    }


    if (
        result?.verdict === "suspicious" ||
        score >= 40
    ) {

        return {

            icon: "🟡",

            color: "#f59e0b",

            label: "SUSPICIOUS"

        };

    }


    if (
        result?.verdict === "caution" ||
        score >= 20
    ) {

        return {

            icon: "🟠",

            color: "#fb923c",

            label: "CAUTION"

        };

    }


    return {

        icon: "🟢",

        color: "#22c55e",

        label: "LOW RISK"

    };

}


// ============================================
// SHOW LINK BADGE
// ============================================

function showBadge(
    result,
    x,
    y
) {

    if (!currentTooltip) {
        createRiskBadge();
    }


    const display =
        getRiskDisplay(result);


    currentTooltip.innerHTML = `

        <div style="
            display:flex;
            align-items:center;
            gap:7px;
        ">

            <span>
                ${display.icon}
            </span>

            <span>
                PhishGuard:
                ${display.label}
            </span>

        </div>

        <div style="
            margin-top:4px;
            font-size:10px;
            opacity:0.8;
        ">

            Risk Score:
            ${result.score}/100

        </div>

    `;


    currentTooltip.style.left =
        `${x + 12}px`;

    currentTooltip.style.top =
        `${y + 12}px`;

    currentTooltip.style.background =
        display.color;

    currentTooltip.style.display =
        "block";

}


// ============================================
// SHOW PAGE WARNING
// ============================================

function showPageWarning(result) {

    const display =
        getRiskDisplay(result);


    if (
        display.label === "LOW RISK"
    ) {

        return;

    }


    const warningId =
        "phishguard-page-warning";


    const existing =
        document.getElementById(
            warningId
        );


    if (existing) {
        existing.remove();
    }


    const warning =
        document.createElement("div");


    warning.id =
        warningId;


    warning.style.position =
        "fixed";

    warning.style.top =
        "16px";

    warning.style.right =
        "16px";

    warning.style.width =
        "340px";

    warning.style.maxWidth =
        "calc(100vw - 32px)";

    warning.style.zIndex =
        "2147483647";

    warning.style.padding =
        "16px";

    warning.style.borderRadius =
        "12px";

    warning.style.background =
        "#111827";

    warning.style.color =
        "#ffffff";

    warning.style.border =
        `2px solid ${display.color}`;

    warning.style.boxShadow =
        "0 10px 30px rgba(0,0,0,0.45)";

    warning.style.fontFamily =
        "Arial, sans-serif";


    const reasons =
        Array.isArray(result.flags)
            ? result.flags.slice(0, 5)
            : Array.isArray(result.evidence)
                ? result.evidence.slice(0, 5)
                : [];


    let reasonHTML = "";


    reasons.forEach(
        flag => {

            if (!flag) {
                return;
            }


            reasonHTML += `

                <div style="
                    margin-top:7px;
                    font-size:11px;
                    opacity:0.9;
                ">

                    ⚠
                    ${escapeHTML(
                        flag.message ||
                        flag.reason ||
                        "Suspicious indicator detected."
                    )}

                </div>

            `;

        }
    );


    warning.innerHTML = `

        <div style="
            display:flex;
            align-items:center;
            justify-content:space-between;
            gap:10px;
        ">

            <div style="
                font-size:15px;
                font-weight:700;
            ">

                ${display.icon}
                PhishGuard:
                ${display.label}

            </div>

            <button
                id="phishguard-close-warning"
                style="
                    border:none;
                    background:transparent;
                    color:#ffffff;
                    font-size:18px;
                    cursor:pointer;
                "
            >
                ×
            </button>

        </div>


        <div style="
            margin-top:8px;
            font-size:13px;
            font-weight:600;
        ">

            Risk Score:
            ${result.score}/100

        </div>


        <div style="
            margin-top:10px;
            font-size:11px;
            opacity:0.75;
        ">

            PhishGuard detected
            potentially risky indicators
            on this website.

        </div>


        ${reasonHTML}

    `;


    document.body.appendChild(
        warning
    );


    const closeButton =
        document.getElementById(
            "phishguard-close-warning"
        );


    if (closeButton) {

        closeButton.addEventListener(
            "click",
            () => {

                warning.remove();

            }
        );

    }

}


// ============================================
// HTML ESCAPE
// ============================================

function escapeHTML(value) {

    const div =
        document.createElement(
            "div"
        );


    div.textContent =
        String(value || "");


    return div.innerHTML;

}


// ============================================
// SHOW LOADING BADGE
// ============================================

function showLoadingBadge(
    x,
    y
) {

    if (!currentTooltip) {
        createRiskBadge();
    }


    currentTooltip.innerHTML = `

        <div>
            🔍 PhishGuard scanning...
        </div>

    `;


    currentTooltip.style.left =
        `${x + 12}px`;

    currentTooltip.style.top =
        `${y + 12}px`;

    currentTooltip.style.background =
        "#111827";

    currentTooltip.style.display =
        "block";

}


// ============================================
// HIDE BADGE
// ============================================

function hideBadge() {

    if (currentTooltip) {

        currentTooltip.style.display =
            "none";

    }

}


// ============================================
// SEND MESSAGE TO BACKGROUND
// ============================================

function sendBackgroundMessage(
    message
) {

    return new Promise(
        (resolve, reject) => {

            chrome.runtime.sendMessage(

                message,

                response => {

                    if (
                        chrome.runtime.lastError
                    ) {

                        reject(
                            new Error(
                                chrome.runtime
                                    .lastError
                                    .message
                            )
                        );

                        return;

                    }


                    if (
                        !response ||
                        !response.success
                    ) {

                        reject(
                            new Error(
                                response?.error ||
                                "PhishGuard request failed."
                            )
                        );

                        return;

                    }


                    resolve(
                        response.result
                    );

                }

            );

        }
    );

}


// ============================================
// SCAN URL
// ============================================

function requestURLScan(
    url,
    action = "scanURL"
) {

    return sendBackgroundMessage({

        action,

        url

    });

}


// ============================================
// COLLECT PAGE LINKS
// ============================================

function collectPageLinks() {

    const links = [];


    const elements =
        Array.from(
            document.querySelectorAll(
                "a[href]"
            )
        );


    for (
        const element of
        elements.slice(0, 500)
    ) {

        const href =
            element.href;


        if (
            !href ||
            !/^https?:\/\//i.test(
                href
            )
        ) {

            continue;

        }


        links.push({

            href,

            text:
                (
                    element.innerText ||
                    element.textContent ||
                    ""
                )
                .trim()
                .slice(
                    0,
                    200
                )

        });

    }


    return links;

}


// ============================================
// COLLECT FORMS
// ============================================

function collectPageForms() {

    const forms = [];


    const elements =
        Array.from(
            document.forms
        );


    for (
        const form of
        elements.slice(0, 100)
    ) {

        const fields = [];


        const inputs =
            Array.from(
                form.querySelectorAll(
                    "input, textarea, select"
                )
            );


        for (
            const input of
            inputs.slice(0, 50)
        ) {

            fields.push({

                type:
                    input.type ||
                    input.tagName
                        .toLowerCase(),

                name:
                    input.name ||
                    "",

                autocomplete:
                    input.autocomplete ||
                    ""

            });

        }


        forms.push({

            action:
                form.action ||
                "",

            method:
                form.method ||
                "get",

            fields

        });

    }


    return forms;

}


// ============================================
// COLLECT IFRAMES
// ============================================

function collectIframes() {

    const iframes = [];


    const elements =
        Array.from(
            document.querySelectorAll(
                "iframe"
            )
        );


    for (
        const iframe of
        elements.slice(0, 100)
    ) {

        iframes.push({

            src:
                iframe.src ||
                "",

            title:
                iframe.title ||
                ""

        });

    }


    return iframes;

}


// ============================================
// COLLECT DOWNLOAD LINKS
// ============================================

function collectDownloadLinks(
    links
) {

    const downloads = [];


    const extensions = [

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
        const link of
        links
    ) {

        const value =
            String(
                link.href || ""
            )
            .toLowerCase();


        if (
            extensions.some(
                extension =>
                    value.includes(
                        extension
                    )
            )
        ) {

            downloads.push(
                link.href
            );

        }

    }


    return downloads.slice(
        0,
        100
    );

}


// ============================================
// COLLECT PAGE METADATA
// ============================================

function collectPageData() {

    const links =
        collectPageLinks();


    const forms =
        collectPageForms();


    const iframes =
        collectIframes();


    const downloads =
        collectDownloadLinks(
            links
        );


    // Visible text only.
    //
    // Limit size to avoid sending huge pages.

    const text =
        (
            document.body?.innerText ||
            ""
        )
        .slice(
            0,
            50000
        );


    // HTML is limited because pages can be
    // extremely large.

    const html =
        (
            document.documentElement?.outerHTML ||
            ""
        )
        .slice(
            0,
            100000
        );


    return {

        url:
            window.location.href,

        title:
            document.title ||
            "",

        text,

        html,

        links,

        forms,

        iframes,

        downloads,

        // Redirect history will be added
        // later when we implement actual
        // redirect tracking.

        redirects: []

    };

}


// ============================================
// FULL PAGE ANALYSIS
// ============================================

async function analyzeCurrentPage() {

    const url =
        window.location.href;


    if (
        !/^https?:\/\//i.test(
            url
        )
    ) {

        return null;

    }


    if (
        pageAnalysisInProgress
    ) {

        return null;

    }


    if (
        currentPageScanURL === url &&
        currentPageScanResult
    ) {

        return currentPageScanResult;

    }


    pageAnalysisInProgress =
        true;


    currentPageScanURL =
        url;


    console.log(
        "🛡️ PhishGuard: collecting page signals..."
    );


    try {

        const pageData =
            collectPageData();


        console.log(
            "📄 PhishGuard page metadata:",
            {

                links:
                    pageData.links.length,

                forms:
                    pageData.forms.length,

                iframes:
                    pageData.iframes.length,

                downloads:
                    pageData.downloads.length,

                textLength:
                    pageData.text.length

            }
        );


        const result =
            await sendBackgroundMessage({

                action:
                    "analyzePage",

                pageData

            });


        currentPageScanResult =
            result;


        console.log(
            "🛡️ PhishGuard full page analysis:",
            result
        );


        showPageWarning(
            result
        );


        return result;

    } catch (error) {

        console.error(
            "❌ PhishGuard page analysis failed:",
            error
        );


        // ------------------------------------
        // FALLBACK
        // ------------------------------------
        //
        // If full page analysis fails, perform
        // the existing URL-only scan so that
        // protection does not disappear.

        try {

            console.log(
                "🔄 PhishGuard falling back to URL scan..."
            );


            const fallbackResult =
                await requestURLScan(
                    url,
                    "scanCurrentPage"
                );


            currentPageScanResult =
                fallbackResult;


            showPageWarning(
                fallbackResult
            );


            return fallbackResult;

        } catch (fallbackError) {

            console.error(
                "❌ PhishGuard URL fallback failed:",
                fallbackError
            );

        }

    } finally {

        pageAnalysisInProgress =
            false;

    }

}


// ============================================
// LINK HOVER SCAN
// ============================================

function scanURL(
    url,
    x,
    y
) {

    showLoadingBadge(
        x,
        y
    );


    requestURLScan(
        url,
        "scanURL"
    )

        .then(
            result => {

                showBadge(
                    result,
                    x,
                    y
                );

            }
        )

        .catch(
            error => {

                console.error(
                    "PhishGuard link scan failed:",
                    error
                );


                hideBadge();

            }
        );

}


// ============================================
// LINK HOVER
// ============================================

document.addEventListener(

    "mouseover",

    event => {

        const link =
            event.target.closest("a");


        if (!link) {
            return;
        }


        const url =
            link.href;


        if (
            !url ||
            !/^https?:\/\//i.test(
                url
            )
        ) {

            return;

        }


        clearTimeout(
            scanTimeout
        );


        scanTimeout =
            setTimeout(

                () => {

                    scanURL(

                        url,

                        event.clientX,

                        event.clientY

                    );

                },

                400

            );

    }

);


// ============================================
// LINK MOUSE OUT
// ============================================

document.addEventListener(

    "mouseout",

    event => {

        const link =
            event.target.closest("a");


        if (!link) {
            return;
        }


        clearTimeout(
            scanTimeout
        );


        hideBadge();

    }

);


// ============================================
// PAGE INITIALIZATION
// ============================================

function initializePhishGuard() {

    console.log(
        "🛡️ PhishGuard initializing..."
    );


    createRiskBadge();


    setTimeout(

        () => {

            analyzeCurrentPage();

        },

        1000

    );

}


initializePhishGuard();


console.log(
    "PhishGuard content script loaded."
);