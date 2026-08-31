// ============================================
// PHISHGUARD BACKGROUND SERVICE WORKER
// ============================================

const API_URL = "http://localhost:3001";

console.log(
    "🛡️ PhishGuard background service worker loaded."
);


// ============================================
// EXTENSION INSTALLED
// ============================================

chrome.runtime.onInstalled.addListener(() => {

    console.log(
        "🛡️ PhishGuard extension installed."
    );

});


// ============================================
// MESSAGE LISTENER
// ============================================

chrome.runtime.onMessage.addListener(
    (message, sender, sendResponse) => {

        console.log(
            "📩 PhishGuard message received:",
            message
        );


        // ========================================
        // URL SCAN
        // ========================================

        if (
            message.action === "scanURL" ||
            message.action === "scanCurrentPage"
        ) {

            console.log(
                "🔍 Starting URL scan:",
                message.url
            );


            scanURL(
                message.url
            )

                .then(
                    result => {

                        console.log(
                            "✅ URL scan completed:",
                            result
                        );


                        sendResponse({

                            success: true,

                            result

                        });

                    }
                )

                .catch(
                    error => {

                        console.error(
                            "❌ URL scan failed:",
                            error
                        );


                        sendResponse({

                            success: false,

                            error:
                                error.message ||
                                "Unable to scan URL."

                        });

                    }
                );


            return true;

        }


        // ========================================
        // FULL PAGE ANALYSIS
        // ========================================

        if (
            message.action === "analyzePage"
        ) {

            console.log(
                "📄 Starting full page analysis:",
                message.pageData?.url
            );


            analyzePage(
                message.pageData
            )

                .then(
                    result => {

                        console.log(
                            "✅ Full page analysis completed:",
                            result
                        );


                        sendResponse({

                            success: true,

                            result

                        });

                    }
                )

                .catch(
                    error => {

                        console.error(
                            "❌ Full page analysis failed:",
                            error
                        );


                        sendResponse({

                            success: false,

                            error:
                                error.message ||
                                "Unable to analyze page."

                        });

                    }
                );


            return true;

        }


        // ========================================
        // UNKNOWN ACTION
        // ========================================

        console.log(
            "⚠️ Unknown message action:",
            message.action
        );


        sendResponse({

            success: false,

            error:
                "Unknown PhishGuard action."

        });


        return false;

    }
);


// ============================================
// SCAN URL
// ============================================

async function scanURL(
    url
) {

    console.log(
        "🌐 Sending URL to API:",
        url
    );


    // ----------------------------------------
    // Validate URL
    // ----------------------------------------

    if (
        typeof url !== "string" ||
        !url.trim()
    ) {

        throw new Error(
            "Invalid URL."
        );

    }


    if (
        !/^https?:\/\//i.test(
            url
        )
    ) {

        throw new Error(
            "Only HTTP and HTTPS URLs can be scanned."
        );

    }


    // ----------------------------------------
    // API REQUEST
    // ----------------------------------------

    const response =
        await fetch(

            `${API_URL}/api/scan-url`,

            {

                method:
                    "POST",

                headers: {

                    "Content-Type":
                        "application/json"

                },

                body:
                    JSON.stringify({

                        url:
                            url

                    })

            }

        );


    console.log(
        "📡 URL API response status:",
        response.status
    );


    if (
        !response.ok
    ) {

        throw new Error(
            `API returned HTTP ${response.status}`
        );

    }


    const data =
        await response.json();


    console.log(
        "📊 URL API result:",
        data
    );


    if (
        !data.success
    ) {

        throw new Error(

            data.error ||
            "URL scan failed."

        );

    }


    return data.result;

}


// ============================================
// FULL PAGE ANALYSIS
// ============================================

async function analyzePage(
    pageData
) {

    console.log(
        "🌐 Sending page data to API:",
        pageData?.url
    );


    // ----------------------------------------
    // Validate page data
    // ----------------------------------------

    if (
        !pageData ||
        typeof pageData !== "object"
    ) {

        throw new Error(
            "Invalid page data."
        );

    }


    if (
        typeof pageData.url !== "string" ||
        !pageData.url.trim()
    ) {

        throw new Error(
            "Page URL is required."
        );

    }


    if (
        !/^https?:\/\//i.test(
            pageData.url
        )
    ) {

        throw new Error(
            "Only HTTP and HTTPS pages can be analyzed."
        );

    }


    // ----------------------------------------
    // Limit payload size
    //
    // This prevents accidentally sending
    // extremely large page contents.
    // ----------------------------------------

    const safePageData = {

        url:
            pageData.url,

        title:
            String(
                pageData.title || ""
            ).slice(
                0,
                2000
            ),

        text:
            String(
                pageData.text || ""
            ).slice(
                0,
                50000
            ),

        html:
            String(
                pageData.html || ""
            ).slice(
                0,
                100000
            ),

        links:
            Array.isArray(
                pageData.links
            )
                ? pageData.links.slice(
                    0,
                    500
                )
                : [],

        forms:
            Array.isArray(
                pageData.forms
            )
                ? pageData.forms.slice(
                    0,
                    100
                )
                : [],

        iframes:
            Array.isArray(
                pageData.iframes
            )
                ? pageData.iframes.slice(
                    0,
                    100
                )
                : [],

        downloads:
            Array.isArray(
                pageData.downloads
            )
                ? pageData.downloads.slice(
                    0,
                    100
                )
                : [],

        redirects:
            Array.isArray(
                pageData.redirects
            )
                ? pageData.redirects.slice(
                    0,
                    50
                )
                : []

    };


    // ----------------------------------------
    // API REQUEST
    // ----------------------------------------

    const response =
        await fetch(

            `${API_URL}/api/analyze-page`,

            {

                method:
                    "POST",

                headers: {

                    "Content-Type":
                        "application/json"

                },

                body:
                    JSON.stringify(
                        safePageData
                    )

            }

        );


    console.log(
        "📡 Page analysis API status:",
        response.status
    );


    // ----------------------------------------
    // API ERROR
    // ----------------------------------------

    if (
        !response.ok
    ) {

        throw new Error(
            `Page analysis API returned HTTP ${response.status}`
        );

    }


    // ----------------------------------------
    // PARSE RESPONSE
    // ----------------------------------------

    const data =
        await response.json();


    console.log(
        "📊 Full page API result:",
        data
    );


    if (
        !data.success
    ) {

        throw new Error(

            data.error ||
            "Page analysis failed."

        );

    }


    return data.result;

}