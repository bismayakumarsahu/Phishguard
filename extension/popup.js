// ============================================
// PHISHGUARD EXTENSION POPUP
// ============================================

const scanPageBtn =
    document.getElementById("scanPageBtn");

const currentPage =
    document.getElementById("currentPage");

const result =
    document.getElementById("result");

const status =
    document.getElementById("status");

const score =
    document.getElementById("score");

const riskBar =
    document.getElementById("riskBar");

const flags =
    document.getElementById("flags");


// ============================================
// GET CURRENT TAB
// ============================================

async function getCurrentTab() {

    const tabs =
        await chrome.tabs.query({
            active: true,
            currentWindow: true
        });

    return tabs[0];
}


// ============================================
// DISPLAY CURRENT PAGE
// ============================================

async function loadCurrentPage() {

    try {

        const tab =
            await getCurrentTab();

        if (!tab || !tab.url) {

            currentPage.textContent =
                "Unable to determine page.";

            return;
        }

        currentPage.textContent =
            tab.url;

    } catch (error) {

        console.error(
            "Unable to get current page:",
            error
        );

        currentPage.textContent =
            "Unable to determine page.";
    }

}


// ============================================
// SCAN CURRENT PAGE
// ============================================

scanPageBtn.addEventListener(
    "click",
    scanCurrentPage
);


async function scanCurrentPage() {

    scanPageBtn.disabled = true;

    scanPageBtn.textContent =
        "🔍 Scanning...";


    try {

        const tab =
            await getCurrentTab();


        if (!tab || !tab.url) {

            throw new Error(
                "Unable to determine current page."
            );
        }


        const url =
            tab.url;


        // Chrome internal pages cannot be scanned

        if (
            !url.startsWith("http://") &&
            !url.startsWith("https://")
        ) {

            throw new Error(
                "This type of page cannot be scanned."
            );
        }


        chrome.runtime.sendMessage(
            {
                action: "scanURL",
                url: url
            },

            response => {

                if (
                    chrome.runtime.lastError
                ) {

                    showError(
                        chrome.runtime.lastError.message
                    );

                    return;
                }


                if (
                    !response ||
                    !response.success
                ) {

                    showError(
                        response?.error ||
                        "URL scan failed."
                    );

                    return;
                }


                displayResult(
                    response.result
                );

            }
        );

    } catch (error) {

        showError(
            error.message
        );

    } finally {

        setTimeout(() => {

            scanPageBtn.disabled = false;

            scanPageBtn.textContent =
                "🔍 Scan Current Page";

        }, 500);

    }

}


// ============================================
// DISPLAY RESULT
// ============================================

function displayResult(scanResult) {

    result.classList.add("show");


    score.textContent =
        scanResult.score;


    status.textContent =
        scanResult.status;


    // ========================================
    // RISK COLOR
    // ========================================

    if (scanResult.score >= 70) {

        status.style.color =
            "#ff4d67";

        riskBar.style.background =
            "#ff4d67";

    } else if (scanResult.score >= 35) {

        status.style.color =
            "#ffae42";

        riskBar.style.background =
            "#ffae42";

    } else {

        status.style.color =
            "#26d07c";

        riskBar.style.background =
            "#26d07c";
    }


    riskBar.style.width =
        `${scanResult.score}%`;


    // ========================================
    // FLAGS
    // ========================================

    flags.innerHTML = "";


    if (
        !scanResult.flags ||
        scanResult.flags.length === 0
    ) {

        const safeMessage =
            document.createElement("div");

        safeMessage.className =
            "no-threats";

        safeMessage.textContent =
            "✓ No major phishing indicators detected.";

        flags.appendChild(
            safeMessage
        );

        return;
    }


    scanResult.flags.forEach(flag => {

        const flagElement =
            document.createElement("div");

        flagElement.className =
            "flag";


        const title =
            document.createElement("strong");

        title.textContent =
            flag.type.replace(
                /_/g,
                " "
            );


        const message =
            document.createElement("span");

        message.textContent =
            flag.message;


        flagElement.appendChild(
            title
        );

        flagElement.appendChild(
            message
        );


        flags.appendChild(
            flagElement
        );

    });

}


// ============================================
// ERROR DISPLAY
// ============================================

function showError(message) {

    result.classList.add("show");

    status.textContent =
        "Error";

    status.style.color =
        "#ff4d67";

    score.textContent =
        "—";

    riskBar.style.width =
        "0%";

    flags.innerHTML = "";


    const errorElement =
        document.createElement("div");

    errorElement.className =
        "flag";

    errorElement.style.borderLeftColor =
        "#ff4d67";


    const title =
        document.createElement("strong");

    title.textContent =
        "SCAN ERROR";


    const description =
        document.createElement("span");

    description.textContent =
        message;


    errorElement.appendChild(
        title
    );

    errorElement.appendChild(
        description
    );

    flags.appendChild(
        errorElement
    );

}


// ============================================
// INITIALIZE
// ============================================

loadCurrentPage();