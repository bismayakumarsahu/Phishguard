// ============================================
// PHISHGUARD BACKGROUND SERVICE WORKER
// ============================================

const API_URL = "http://localhost:3001";


// ============================================
// EXTENSION INSTALLED
// ============================================

chrome.runtime.onInstalled.addListener(() => {

    console.log("PhishGuard extension installed.");

});


// ============================================
// MESSAGE HANDLER
// ============================================

chrome.runtime.onMessage.addListener(
    (message, sender, sendResponse) => {

        if (message.action === "scanURL") {

            scanURL(message.url)
                .then(result => {

                    sendResponse({
                        success: true,
                        result: result
                    });

                })
                .catch(error => {

                    console.error(
                        "PhishGuard API error:",
                        error
                    );

                    sendResponse({
                        success: false,
                        error:
                            "Unable to connect to PhishGuard API."
                    });

                });

            // Keep the message channel open
            return true;
        }

    }
);


// ============================================
// SCAN URL
// ============================================

async function scanURL(url) {

    const response = await fetch(
        `${API_URL}/api/scan-url`,
        {
            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                url: url
            })
        }
    );


    if (!response.ok) {

        throw new Error(
            `API returned status ${response.status}`
        );

    }


    const data =
        await response.json();


    if (!data.success) {

        throw new Error(
            data.error ||
            "URL scan failed."
        );

    }


    return data.result;
}