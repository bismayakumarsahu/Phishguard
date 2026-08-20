// ============================================
// PHISHGUARD CONTENT SCRIPT
// ============================================

let currentTooltip = null;
let scanTimeout = null;


// ============================================
// CREATE RISK BADGE
// ============================================

function createRiskBadge() {

    if (currentTooltip) {
        currentTooltip.remove();
    }

    const badge = document.createElement("div");

    badge.id = "phishguard-risk-badge";

    badge.style.position = "fixed";
    badge.style.zIndex = "2147483647";
    badge.style.padding = "8px 12px";
    badge.style.borderRadius = "8px";
    badge.style.fontFamily =
        "Arial, sans-serif";
    badge.style.fontSize = "12px";
    badge.style.fontWeight = "600";
    badge.style.color = "#ffffff";
    badge.style.background = "#111827";
    badge.style.boxShadow =
        "0 4px 15px rgba(0,0,0,0.3)";
    badge.style.pointerEvents = "none";
    badge.style.display = "none";

    document.body.appendChild(badge);

    currentTooltip = badge;

    return badge;
}


// ============================================
// SHOW BADGE
// ============================================

function showBadge(
    result,
    x,
    y
) {

    if (!currentTooltip) {
        createRiskBadge();
    }

    let icon;
    let color;

    if (result.score >= 70) {

        icon = "🔴";
        color = "#ef4444";

    } else if (result.score >= 35) {

        icon = "🟡";
        color = "#f59e0b";

    } else {

        icon = "🟢";
        color = "#22c55e";
    }


    currentTooltip.innerHTML = `
        <div style="
            display:flex;
            align-items:center;
            gap:7px;
        ">
            <span>${icon}</span>

            <span>
                PhishGuard:
                ${result.status}
            </span>
        </div>

        <div style="
            margin-top:4px;
            font-size:10px;
            opacity:0.8;
        ">
            Risk Score: ${result.score}/100
        </div>
    `;


    currentTooltip.style.left =
        `${x + 12}px`;

    currentTooltip.style.top =
        `${y + 12}px`;

    currentTooltip.style.display =
        "block";
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
// SCAN URL
// ============================================

function scanURL(
    url,
    x,
    y
) {

    showLoadingBadge(x, y);


    chrome.runtime.sendMessage(
        {
            action: "scanURL",
            url: url
        },

        response => {

            if (
                chrome.runtime.lastError
            ) {

                console.error(
                    "PhishGuard:",
                    chrome.runtime.lastError
                );

                hideBadge();

                return;
            }


            if (
                !response ||
                !response.success
            ) {

                console.error(
                    "PhishGuard scan failed:",
                    response
                );

                hideBadge();

                return;
            }


            showBadge(
                response.result,
                x,
                y
            );

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
            !url.startsWith("http")
        ) {
            return;
        }


        clearTimeout(scanTimeout);


        scanTimeout =
            setTimeout(() => {

                scanURL(
                    url,
                    event.clientX,
                    event.clientY
                );

            }, 400);

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


        clearTimeout(scanTimeout);

        hideBadge();

    }
);


// ============================================
// INITIALIZE
// ============================================

createRiskBadge();

console.log(
    "PhishGuard content script loaded."
);