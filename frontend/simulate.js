// ============================================
// PHISHGUARD ATTACK SIMULATION
// ============================================

const scenarios = {

    paypal: {
        senderName: "PayPal Support",
        senderEmail: "support@paypal-security-alert.xyz",
        replyTo: "security-team@random-mail.example",
        subject: "URGENT: Your PayPal account will be suspended",

        body:
`Dear Customer,

Immediate action required.

Your PayPal account will be suspended because we detected unusual activity.

Please verify your account password and confirm your identity within 24 hours.

Click the link below to verify your account:

https://paypal-login-verify-example.xyz

Failure to verify your account may result in permanent suspension.

PayPal Security Team`
    },


    bank: {
        senderName: "SBI Security Department",
        senderEmail: "security@sbi-account-alert.xyz",
        replyTo: "verification@random-mail.example",
        subject: "URGENT: Verify your banking account",

        body:
`Dear Customer,

We detected unusual activity on your bank account.

Immediate action is required.

Your account will be suspended within 24 hours unless you complete security verification.

Please verify your login credentials and OTP using the link below:

https://sbi-secure-login-example.xyz

Failure to verify will result in account suspension.

Security Department`
    },


    microsoft: {
        senderName: "Microsoft Account Security",
        senderEmail: "security@microsoft-account-alert.xyz",
        replyTo: "helpdesk@random-mail.example",
        subject: "Final Warning: Microsoft account verification required",

        body:
`Hello,

We detected unauthorized access to your Microsoft account.

Your account will be locked unless you verify your identity immediately.

Confirm your username and password using the following link:

https://microsoft-login-verify-example.xyz

This is your final warning.

Microsoft Account Security`
    }

};


// ============================================
// ELEMENTS
// ============================================

const scenarioButtons =
    document.querySelectorAll(".scenario-btn");

const generateBtn =
    document.getElementById("generateBtn");

const emailPreview =
    document.getElementById("emailPreview");

const analyzeSimulationBtn =
    document.getElementById("analyzeSimulationBtn");

const simSender =
    document.getElementById("simSender");

const simReplyTo =
    document.getElementById("simReplyTo");

const simSubject =
    document.getElementById("simSubject");

const simBody =
    document.getElementById("simBody");

const simulationResult =
    document.getElementById("simulationResult");

const simulationStatus =
    document.getElementById("simulationStatus");

const simulationScore =
    document.getElementById("simulationScore");

const simulationRiskBar =
    document.getElementById("simulationRiskBar");

const simulationIndicators =
    document.getElementById("simulationIndicators");

const simulationChain =
    document.getElementById("simulationChain");


// ============================================
// CURRENT SCENARIO
// ============================================

let selectedScenario = "paypal";

let generatedEmail = null;


// ============================================
// SCENARIO SELECTION
// ============================================

scenarioButtons.forEach(button => {

    button.addEventListener("click", () => {

        scenarioButtons.forEach(item => {

            item.classList.remove("active");

        });

        button.classList.add("active");

        selectedScenario =
            button.dataset.scenario;

    });

});


// ============================================
// GENERATE MOCK ATTACK
// ============================================

generateBtn.addEventListener(
    "click",
    generateMockAttack
);


function generateMockAttack() {

    const scenario =
        scenarios[selectedScenario];

    if (!scenario) {

        alert(
            "Unable to generate simulation."
        );

        return;
    }


    generatedEmail = {
        senderName:
            scenario.senderName,

        senderEmail:
            scenario.senderEmail,

        replyTo:
            scenario.replyTo,

        subject:
            scenario.subject,

        body:
            scenario.body
    };


    // Display email

    simSender.textContent =
        `${scenario.senderName} <${scenario.senderEmail}>`;

    simReplyTo.textContent =
        scenario.replyTo;

    simSubject.textContent =
        scenario.subject;

    simBody.textContent =
        scenario.body;


    // Show preview

    emailPreview.classList.add("show");


    // Hide previous result

    simulationResult.classList.remove("show");


    // Scroll preview into view

    emailPreview.scrollIntoView({
        behavior: "smooth",
        block: "nearest"
    });

}


// ============================================
// ANALYZE GENERATED EMAIL
// ============================================

analyzeSimulationBtn.addEventListener(
    "click",
    analyzeGeneratedEmail
);


async function analyzeGeneratedEmail() {

    if (!generatedEmail) {

        alert(
            "Generate a mock attack first."
        );

        return;
    }


    analyzeSimulationBtn.disabled = true;

    analyzeSimulationBtn.textContent =
        "Analyzing...";


    try {

        const response =
            await fetch(
                "http://localhost:3001/api/analyze-email",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify(
                        generatedEmail
                    )
                }
            );


        const data =
            await response.json();


        if (
            !response.ok ||
            !data.success
        ) {

            throw new Error(
                data.error ||
                "Simulation analysis failed."
            );
        }


        displaySimulationResult(
            data.result
        );


    } catch (error) {

        console.error(
            "Simulation error:",
            error
        );

        alert(
            "Unable to connect to the PhishGuard backend.\n\n" +
            "Make sure the backend is running at:\n" +
            "http://localhost:3001"
        );


    } finally {

        analyzeSimulationBtn.disabled = false;

        analyzeSimulationBtn.textContent =
            "Analyze Generated Email";
    }

}


// ============================================
// DISPLAY RESULT
// ============================================

function displaySimulationResult(result) {

    simulationResult.classList.add(
        "show"
    );


    simulationScore.textContent =
        result.score;


    simulationStatus.textContent =
        result.status;


    simulationRiskBar.style.width =
        result.score + "%";


    // ========================================
    // INDICATORS
    // ========================================

    simulationIndicators.innerHTML = "";


    if (
        !result.flags ||
        result.flags.length === 0
    ) {

        const message =
            document.createElement("div");

        message.className =
            "indicator";

        message.textContent =
            "No major phishing indicators detected.";

        simulationIndicators.appendChild(
            message
        );

    } else {

        result.flags.forEach(flag => {

            const indicator =
                document.createElement("div");

            indicator.className =
                "indicator";


            const title =
                document.createElement("strong");

            title.textContent =
                flag.type.replace(
                    /_/g,
                    " "
                );


            const description =
                document.createElement("span");

            description.textContent =
                flag.message;


            indicator.appendChild(title);

            indicator.appendChild(
                description
            );

            simulationIndicators.appendChild(
                indicator
            );

        });

    }


    // ========================================
    // ATTACK CHAIN
    // ========================================

    simulationChain.innerHTML = "";


    if (result.attackChain) {

        result.attackChain.forEach(stage => {

            const item =
                document.createElement("div");

            item.className =
                "chain-item";


            if (stage.detected) {

                item.classList.add(
                    "detected"
                );

                item.textContent =
                    `✓ ${stage.stage}. ${stage.name} — DETECTED`;

            } else {

                item.textContent =
                    `${stage.stage}. ${stage.name} — Not detected`;
            }


            simulationChain.appendChild(
                item
            );

        });

    }

}