// ============================================
// PHISHGUARD FRONTEND
// ============================================

const API_URL = "http://localhost:3001";


// ============================================
// ELEMENTS
// ============================================

const urlInput = document.getElementById("urlInput");
const scanBtn = document.getElementById("scanBtn");

const scanResult = document.getElementById("scanResult");
const riskStatus = document.getElementById("riskStatus");
const riskScore = document.getElementById("riskScore");
const riskBar = document.getElementById("riskBar");
const riskLevel = document.getElementById("riskLevel");
const threatCount = document.getElementById("threatCount");
const flagList = document.getElementById("flagList");

const totalScans = document.getElementById("totalScans");
const threatsDetected = document.getElementById("threatsDetected");
const safeUrls = document.getElementById("safeUrls");
const protectionRate = document.getElementById("protectionRate");

const recentActivity =
    document.getElementById("recentActivity");


// ============================================
// INITIAL LOAD
// ============================================

document.addEventListener(
    "DOMContentLoaded",
    () => {

        loadStatistics();
        loadRecentActivity();

    }
);


// ============================================
// SCAN BUTTON
// ============================================

scanBtn.addEventListener(
    "click",
    scanURL
);


// ============================================
// ENTER KEY
// ============================================

urlInput.addEventListener(
    "keydown",
    (event) => {

        if (event.key === "Enter") {

            scanURL();

        }

    }
);

// ============================================
// LOAD LOGGED-IN USER
// ============================================

function loadLoggedInUser() {

    const savedUser =
        localStorage.getItem(
            "phishguard_user"
        );

    if (!savedUser) {
        return;
    }

    try {

        const user =
            JSON.parse(savedUser);

        const profileName =
            document.getElementById(
                "profileName"
            );

        const profileAvatar =
            document.getElementById(
                "profileAvatar"
            );


        // Show registered name

        if (profileName) {

            profileName.textContent =
                user.name;

        }


        // Generate initials

        if (profileAvatar) {

            const initials =
                user.name
                    .trim()
                    .split(/\s+/)
                    .map(
                        word =>
                            word.charAt(0)
                    )
                    .join("")
                    .substring(0, 2)
                    .toUpperCase();

            profileAvatar.textContent =
                initials;

        }


    } catch (error) {

        console.error(
            "Could not load user:",
            error
        );

    }

}


// Load user when dashboard opens

loadLoggedInUser();

// ============================================
// PROFILE BUTTON
// ============================================

const profileButton =
    document.getElementById(
        "profileButton"
    );

if (profileButton) {

    profileButton.addEventListener(
        "click",
        () => {

            window.location.href =
                "pages/login.html";

        }
    );

}

// ============================================
// SCAN URL
// ============================================

async function scanURL() {

    const url =
        urlInput.value.trim();


    if (!url) {

        alert(
            "Please enter a URL."
        );

        return;

    }


    scanBtn.disabled = true;
    scanBtn.textContent =
        "Scanning...";


    try {

        console.log(
            "Sending URL to backend:",
            url
        );


        const response =
            await fetch(
                `${API_URL}/api/scan-url`,
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        url: url
                    })

                }
            );


        const data =
            await response.json();


        console.log(
            "Backend response:",
            data
        );


        if (!response.ok) {

            throw new Error(
                data.error ||
                "Backend returned an error."
            );

        }


        if (!data.success) {

            throw new Error(
                data.error ||
                "Scan failed."
            );

        }


        const result =
            data.result;


        // Display scan result

        displayResult(
            result
        );


        // Reload real statistics

        await loadStatistics();


        // Reload recent activity

        await loadRecentActivity();


    } catch (error) {

        console.error(
            "PhishGuard scan error:",
            error
        );


        alert(
            "PhishGuard could not connect to the backend.\n\n" +
            error.message
        );


    } finally {

        scanBtn.disabled = false;

        scanBtn.textContent =
            "Scan URL";

    }

}


// ============================================
// DISPLAY SCAN RESULT
// ============================================

function displayResult(result) {

    scanResult.classList.remove(
        "hidden"
    );


    // Risk score

    riskScore.textContent =
        result.score;


    // Status

    riskStatus.textContent =
        result.status;


    // Risk level

    riskLevel.textContent =
        result.level;


    // Flags

    const flags =
        Array.isArray(result.flags)
            ? result.flags
            : [];


    threatCount.textContent =
        flags.length;


    // Risk bar

    riskBar.style.width =
        Math.min(
            Math.max(
                Number(result.score) || 0,
                0
            ),
            100
        ) + "%";


    // Clear old flags

    flagList.innerHTML =
        "";


    // No threats

    if (flags.length === 0) {

        const li =
            document.createElement(
                "li"
            );

        li.textContent =
            "No major phishing indicators detected.";

        flagList.appendChild(
            li
        );

        return;

    }


    // Display flags

    flags.forEach(
        (flag) => {

            const li =
                document.createElement(
                    "li"
                );


            li.textContent =
                flag.message ||
                flag.type ||
                "Threat indicator detected";


            flagList.appendChild(
                li
            );

        }
    );

}


// ============================================
// LOAD REAL STATISTICS
// ============================================

async function loadStatistics() {

    try {

        const response =
            await fetch(
                `${API_URL}/api/stats`
            );


        const data =
            await response.json();


        if (
            !response.ok ||
            !data.success
        ) {

            throw new Error(
                data.error ||
                "Could not load statistics."
            );

        }


        const stats =
            data.stats;


        // Total scans

        totalScans.textContent =
            stats.totalScans;


        // Threats

        threatsDetected.textContent =
            stats.threatsDetected;


        // Safe URLs

        safeUrls.textContent =
            stats.safeScans;


        // Protection rate

        protectionRate.textContent =
            stats.protectionRate +
            "%";


        console.log(
            "Dashboard statistics loaded:",
            stats
        );


    } catch (error) {

        console.error(
            "Statistics loading error:",
            error
        );

    }

}


// ============================================
// LOAD RECENT ACTIVITY
// ============================================

async function loadRecentActivity() {

    try {

        const response =
            await fetch(
                `${API_URL}/api/history?limit=5`
            );


        const data =
            await response.json();


        if (
            !response.ok ||
            !data.success
        ) {

            throw new Error(
                data.error ||
                "Could not load history."
            );

        }


        renderRecentActivity(
            data.history
        );


    } catch (error) {

        console.error(
            "History loading error:",
            error
        );

    }

}


// ============================================
// RENDER RECENT ACTIVITY
// ============================================

function renderRecentActivity(
    history
) {

    recentActivity.innerHTML =
        "";


    if (
        !history ||
        history.length === 0
    ) {

        recentActivity.innerHTML = `

            <div class="empty-state">

                <span>🔍</span>

                <p>No scans yet</p>

                <small>
                    Scan a URL to see activity here.
                </small>

            </div>

        `;

        return;

    }


    history
        .slice(0, 5)
        .forEach(
            (record) => {

                const activity =
                    document.createElement(
                        "div"
                    );


                activity.style.padding =
                    "12px 0";


                activity.style.borderBottom =
                    "1px solid #202938";


                const score =
                    Number(
                        record.score
                    ) || 0;


                let statusColor;


                if (score >= 70) {

                    statusColor =
                        "#ff4d67";

                } else if (score >= 35) {

                    statusColor =
                        "#ffae42";

                } else {

                    statusColor =
                        "#26d07c";

                }


                const target =
                    record.target ||
                    "Unknown";


                const type =
                    record.type === "email"
                        ? "EMAIL"
                        : "URL";


                const time =
                    formatTime(
                        record.timestamp
                    );


                activity.innerHTML = `

                    <div style="
                        display:flex;
                        justify-content:space-between;
                        align-items:center;
                        gap:10px;
                    ">

                        <div style="
                            overflow:hidden;
                            min-width:0;
                        ">

                            <strong style="
                                display:block;
                                font-size:12px;
                                white-space:nowrap;
                                overflow:hidden;
                                text-overflow:ellipsis;
                            ">
                                ${escapeHTML(target)}
                            </strong>

                            <span style="
                                color:#8993a4;
                                font-size:10px;
                            ">
                                ${type} • ${time}
                            </span>

                        </div>


                        <span style="
                            color:${statusColor};
                            font-size:11px;
                            font-weight:600;
                            white-space:nowrap;
                        ">
                            ${escapeHTML(
                                record.status ||
                                "Unknown"
                            )}
                        </span>

                    </div>

                `;


                recentActivity.appendChild(
                    activity
                );

            }
        );

}


// ============================================
// FORMAT TIME
// ============================================

function formatTime(
    timestamp
) {

    if (!timestamp) {

        return "Unknown time";

    }


    const date =
        new Date(timestamp);


    if (
        Number.isNaN(
            date.getTime()
        )
    ) {

        return "Unknown time";

    }


    return date.toLocaleString();

}


// ============================================
// SECURITY: ESCAPE HTML
// ============================================

function escapeHTML(value) {

    return String(value)
        .replace(
            /&/g,
            "&amp;"
        )
        .replace(
            /</g,
            "&lt;"
        )
        .replace(
            />/g,
            "&gt;"
        )
        .replace(
            /"/g,
            "&quot;"
        )
        .replace(
            /'/g,
            "&#039;"
        );

}