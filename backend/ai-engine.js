/**
 * CYBERGUARD RISK ENGINE
 * Version: 4.1.0
 *
 * Combines:
 * - Heuristic detection
 * - AI/ML feature signals
 * - Threat intelligence
 * - Behavioral signals
 *
 * Produces:
 * - Unified risk score (0-100)
 * - Risk level
 * - Threat classification
 * - Explainable reasons
 * - Recommended response
 */

'use strict';

const { analyzeURL, analyzeEmail } = require('./heuristics');

/**
 * Clamp a number between minimum and maximum.
 */
function clamp(value, min = 0, max = 100) {
    const number = Number(value);

    if (!Number.isFinite(number)) {
        return min;
    }

    return Math.max(min, Math.min(max, number));
}

/**
 * Safely convert a value to a score.
 */
function score(value, fallback = 0) {
    const number = Number(value);

    if (!Number.isFinite(number)) {
        return fallback;
    }

    return clamp(number);
}

/**
 * Convert common boolean/string values to boolean.
 */
function toBoolean(value) {
    if (typeof value === 'boolean') {
        return value;
    }

    if (typeof value === 'string') {
        return ['true', 'yes', '1', 'detected', 'malicious'].includes(
            value.toLowerCase()
        );
    }

    return Boolean(value);
}

/**
 * Determine risk level from final score.
 */
function getRiskLevel(riskScore) {
    if (riskScore >= 80) return 'CRITICAL';
    if (riskScore >= 60) return 'HIGH';
    if (riskScore >= 35) return 'MEDIUM';
    if (riskScore >= 15) return 'LOW';

    return 'SAFE';
}

/**
 * Determine threat classification.
 */
function classifyThreat({
    heuristicScore,
    aiScore,
    threatIntelScore,
    behaviorScore,
    features = {}
}) {
    const scores = {
        phishing: 0,
        impersonation: 0,
        credentialTheft: 0,
        malicious: 0,
        suspicious: 0
    };

    /*
     * URL / phishing indicators
     */
    if (
        features.suspiciousTLD ||
        features.lookalikeDomain ||
        features.urlShortener ||
        features.hasPunycode ||
        features.hasIPAddress
    ) {
        scores.phishing += 20;
    }

    /*
     * Credential harvesting indicators
     */
    if (
        features.passwordField ||
        features.loginForm ||
        features.credentialRequest ||
        features.credentialHarvesting
    ) {
        scores.credentialTheft += 30;
    }

    /*
     * Impersonation indicators
     */
    if (
        features.brandImpersonation ||
        features.lookalikeDomain ||
        features.spoofedBrand ||
        features.deepfakeIndicators
    ) {
        scores.impersonation += 35;
    }

    /*
     * AI phishing/text indicators
     */
    if (
        features.urgency ||
        features.socialEngineering ||
        features.suspiciousLanguage ||
        features.paymentRequest
    ) {
        scores.phishing += 25;
    }

    /*
     * Threat intelligence
     */
    if (threatIntelScore >= 80) {
        scores.malicious += 50;
    } else if (threatIntelScore >= 50) {
        scores.malicious += 30;
    }

    /*
     * Behavioral anomalies
     */
    if (behaviorScore >= 70) {
        scores.suspicious += 40;
    } else if (behaviorScore >= 40) {
        scores.suspicious += 20;
    }

    /*
     * General AI signal
     */
    if (aiScore >= 80) {
        scores.phishing += 25;
        scores.malicious += 20;
    } else if (aiScore >= 60) {
        scores.phishing += 15;
        scores.suspicious += 15;
    }

    const [classification, classificationScore] =
        Object.entries(scores).sort((a, b) => b[1] - a[1])[0];

    if (classificationScore < 20) {
        return 'SUSPICIOUS_ACTIVITY';
    }

    const names = {
        phishing: 'PHISHING',
        impersonation: 'DIGITAL_IMPERSONATION',
        credentialTheft: 'CREDENTIAL_THEFT',
        malicious: 'MALICIOUS',
        suspicious: 'SUSPICIOUS_ACTIVITY'
    };

    return names[classification] || 'SUSPICIOUS_ACTIVITY';
}

/**
 * Generate explainable reasons.
 */
function generateReasons({
    heuristicScore,
    aiScore,
    threatIntelScore,
    behaviorScore,
    features = {},
    threatIntel = {}
}) {
    const reasons = [];

    if (heuristicScore >= 70) {
        reasons.push(
            'Traditional security heuristics identified multiple suspicious indicators.'
        );
    }

    if (aiScore >= 70) {
        reasons.push(
            'AI analysis identified a strong combination of threat-related features.'
        );
    }

    if (threatIntelScore >= 80) {
        reasons.push(
            'Threat-intelligence signals strongly indicate malicious infrastructure.'
        );
    } else if (threatIntelScore >= 50) {
        reasons.push(
            'Threat-intelligence sources returned suspicious indicators.'
        );
    }

    if (behaviorScore >= 70) {
        reasons.push(
            'Observed behavior contains significant anomalies.'
        );
    }

    if (features.hasPunycode) {
        reasons.push(
            'Punycode/Unicode domain encoding was detected.'
        );
    }

    if (features.hasIPAddress) {
        reasons.push(
            'The URL uses an IP address instead of a conventional domain.'
        );
    }

    if (features.lookalikeDomain) {
        reasons.push(
            'The domain appears similar to a legitimate or trusted domain.'
        );
    }

    if (features.urlShortener) {
        reasons.push(
            'A URL-shortening service may hide the final destination.'
        );
    }

    if (
        features.loginForm ||
        features.passwordField ||
        features.credentialRequest
    ) {
        reasons.push(
            'The page appears to request authentication or credential information.'
        );
    }

    if (features.urgency) {
        reasons.push(
            'Urgency-based social-engineering language was detected.'
        );
    }

    if (features.paymentRequest) {
        reasons.push(
            'The content contains indicators associated with payment or financial requests.'
        );
    }

    if (threatIntel?.malicious === true) {
        reasons.push(
            'External threat intelligence marked the indicator as malicious.'
        );
    }

    if (reasons.length === 0) {
        reasons.push(
            'No major malicious indicators were detected by the available analysis layers.'
        );
    }

    return [...new Set(reasons)];
}

/**
 * Generate recommended response.
 */
function getRecommendedAction(riskLevel, classification) {
    switch (riskLevel) {
        case 'CRITICAL':
            return {
                action: 'BLOCK',
                message:
                    'Block access immediately and investigate the indicator.',
                userAction:
                    'Do not enter credentials, download files, or interact with the content.'
            };

        case 'HIGH':
            return {
                action: 'BLOCK',
                message:
                    'Block or quarantine this indicator pending investigation.',
                userAction:
                    'Avoid interacting with the website or message.'
            };

        case 'MEDIUM':
            return {
                action: 'WARN',
                message:
                    'Warn the user and perform additional verification.',
                userAction:
                    'Verify the sender, domain, and request through an independent channel.'
            };

        case 'LOW':
            return {
                action: 'MONITOR',
                message:
                    'Allow with increased monitoring.',
                userAction:
                    'Continue carefully and avoid sharing sensitive information unless verified.'
            };

        default:
            return {
                action: 'ALLOW',
                message:
                    'No immediate threat action is required.',
                userAction:
                    'Continue normal safe-browsing practices.'
            };
    }
}

/**
 * Main risk assessment.
 *
 * Accepts flexible input so existing PhishGuard
 * routes can use this without major changes.
 */
function calculateRisk(input = {}) {
    const heuristicScore = score(
        input.heuristicScore ??
        input.heuristicsScore ??
        input.heuristic ??
        input.riskScore
    );

    const aiScore = score(
        input.aiScore ??
        input.aiRiskScore ??
        input.mlScore ??
        input.ai?.riskScore
    );

    const threatIntelScore = score(
        input.threatIntelScore ??
        input.threatIntelligenceScore ??
        input.intelligenceScore
    );

    const behaviorScore = score(
        input.behaviorScore ??
        input.behaviorRiskScore ??
        input.behavior?.riskScore
    );

    const features = input.features || input.aiFeatures || {};

    /*
     * Weighted risk fusion.
     *
     * Heuristics:       35%
     * AI/ML:            35%
     * Threat Intel:     20%
     * Behavior:         10%
     */
    let finalScore =
        heuristicScore * 0.35 +
        aiScore * 0.35 +
        threatIntelScore * 0.20 +
        behaviorScore * 0.10;

    /*
     * Strong threat-intelligence override.
     */
    if (input.threatIntel?.malicious === true) {
        finalScore = Math.max(finalScore, 90);
    }

    /*
     * Explicit malicious indicators.
     */
    if (toBoolean(input.malicious)) {
        finalScore = Math.max(finalScore, 85);
    }

    finalScore = Math.round(clamp(finalScore));

    const riskLevel = getRiskLevel(finalScore);

    const classification = classifyThreat({
        heuristicScore,
        aiScore,
        threatIntelScore,
        behaviorScore,
        features
    });

    const reasons = generateReasons({
        heuristicScore,
        aiScore,
        threatIntelScore,
        behaviorScore,
        features,
        threatIntel: input.threatIntel || {}
    });

    const recommendation =
        getRecommendedAction(riskLevel, classification);

    return {
        riskScore: finalScore,
        riskLevel,
        classification,

        confidence: Math.round(
            clamp(
                Math.max(
                    heuristicScore,
                    aiScore,
                    threatIntelScore,
                    behaviorScore
                )
            )
        ),

        signals: {
            heuristic: Math.round(heuristicScore),
            ai: Math.round(aiScore),
            threatIntelligence: Math.round(threatIntelScore),
            behavior: Math.round(behaviorScore)
        },

        explanation: reasons,

        recommendation,

        timestamp: new Date().toISOString()
    };
}

/**
 * Compatibility wrapper.
 *
 * Allows existing code to call:
 *
 * calculateRiskScore(...)
 */
function calculateRiskScore(input = {}) {
    return calculateRisk(input);
}

/**
 * Analyze a URL using available signals.
 */
function assessURL({
    heuristic = {},
    ai = {},
    threatIntel = {},
    behavior = {}
} = {}) {
    return calculateRisk({
        heuristicScore:
            heuristic.riskScore ??
            heuristic.score ??
            heuristic.threatScore ??
            0,

        aiScore:
            ai.riskScore ??
            ai.score ??
            ai.threatScore ??
            0,

        threatIntelScore:
            threatIntel.riskScore ??
            threatIntel.score ??
            threatIntel.threatScore ??
            0,

        behaviorScore:
            behavior.riskScore ??
            behavior.score ??
            behavior.threatScore ??
            0,

        features: {
            ...(heuristic.features || {}),
            ...(ai.features || {}),
            ...(behavior.features || {})
        },

        threatIntel
    });
}

/**
 * Simple helper used by APIs.
 */
function getRiskCategory(scoreValue) {
    return getRiskLevel(clamp(scoreValue));
}

function extractURLFeatures(url) {
    let parsed;

    try {
        parsed = new URL(/^https?:\/\//i.test(url) ? url : `https://${url}`);
    } catch {
        return {
            valid: false,
            featureScore: 100,
            reasons: ['The supplied value is not a valid URL.']
        };
    }

    const heuristic = analyzeURL(parsed.href);
    const flagTypes = new Set((heuristic.flags || []).map(flag => flag.type));
    const hostname = parsed.hostname.toLowerCase();
    const features = {
        suspiciousTld: /\.(tk|ml|ga|cf|gq|top|xyz|click)$/i.test(hostname),
        hasIPAddress: /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname),
        urlShortener: /(^|\.)(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|cutt\.ly|rb\.gy)$/i.test(hostname),
        lookalikeDomain: flagTypes.has('TYPOSQUATTING') || flagTypes.has('BRAND_IMPERSONATION'),
        credentialRequest: /login|signin|verify|account|password|authenticate/i.test(`${parsed.pathname}${parsed.search}`),
        excessiveSubdomains: hostname.split('.').length > 4,
        hostname
    };

    return {
        valid: true,
        ...features,
        featureScore: heuristic.score || 0,
        reasons: heuristic.flags || [],
        modelType: 'heuristic-feature-engineering baseline'
    };
}

function analyzeText(text, context = {}) {
    const content = typeof text === 'string' ? text : '';
    const emailResult = analyzeEmail({
        senderName: context.senderName || '',
        senderEmail: context.senderEmail || context.sender || '',
        replyTo: context.replyTo || '',
        subject: context.subject || '',
        body: content
    });
    const textContent = `${context.subject || ''} ${content}`.toLowerCase();
    const evidence = emailResult.flags || [];
    const features = {
        urgency: /urgent|immediately|act now|final warning|within 24 hours|action required/i.test(textContent),
        credentialRequest: /password|username|login|sign in|verify your account|otp|one time password/i.test(textContent),
        socialEngineering: /suspended|locked|unusual activity|failure to verify|immediate action/i.test(textContent),
        paymentRequest: /payment|bank details|credit card|debit card|wire transfer/i.test(textContent),
        suspiciousLanguage: evidence.length > 0,
        brandImpersonation: evidence.some(flag => ['SENDER_MISMATCH', 'REPLY_TO_SPOOFING'].includes(flag.type))
    };

    return {
        score: emailResult.score || 0,
        category: evidence.length ? 'SUSPICIOUS_COMMUNICATION' : 'LOW_RISK',
        evidence,
        features,
        model: 'heuristic-feature-engine-v1',
        modelType: 'rule-based feature analysis; no trained model'
    };
}

function analyzeLoginBehavior(logs = []) {
    if (!Array.isArray(logs)) {
        throw new TypeError('Login events must be provided as an array.');
    }

    const events = logs.filter(event => event && typeof event === 'object');
    const failedEvents = events.filter(event => event.success === false);
    const indicators = [];
    let riskScore = 0;

    if (failedEvents.length >= 3) {
        riskScore += Math.min(35, failedEvents.length * 8);
        indicators.push({ type: 'REPEATED_LOGIN_FAILURES', message: `${failedEvents.length} failed login attempts were observed.` });
    }

    for (const [field, indicator, description] of [
        ['ip', 'MULTIPLE_LOGIN_IPS', 'Login events came from multiple IP addresses.'],
        ['location', 'MULTIPLE_LOGIN_LOCATIONS', 'Login events came from multiple locations.'],
        ['device', 'NEW_OR_MULTIPLE_DEVICES', 'Login events used multiple devices.']
    ]) {
        const distinctValues = new Set(events.map(event => event[field]).filter(Boolean));
        if (distinctValues.size > 1) {
            riskScore += field === 'ip' ? 20 : 15;
            indicators.push({ type: indicator, message: description });
        }
    }

    const hasSuccessfulAfterFailures = events.some((event, index) =>
        event.success === true && events.slice(0, index).some(previous => previous.success === false)
    );
    if (hasSuccessfulAfterFailures) {
        riskScore += 20;
        indicators.push({ type: 'SUCCESS_AFTER_FAILURES', message: 'A successful login followed one or more failed attempts.' });
    }

    const scoreValue = clamp(riskScore);
    return {
        score: scoreValue,
        category: scoreValue >= 60 ? 'ACCOUNT_TAKEOVER' : scoreValue > 0 ? 'ABNORMAL_LOGIN' : 'LOW_RISK',
        evidence: indicators,
        features: { repeatedFailures: failedEvents.length >= 3, multipleIPs: new Set(events.map(event => event.ip).filter(Boolean)).size > 1 },
        modelType: 'rule-based login anomaly analysis; no trained model'
    };
}

function buildAssessment(analysis = {}) {
    const scoreValue = clamp(analysis.score ?? analysis.riskScore);
    const riskLevel = getRiskLevel(scoreValue);
    const recommendation = getRecommendedAction(riskLevel, analysis.category || 'SUSPICIOUS_ACTIVITY');
    const evidence = Array.isArray(analysis.evidence) ? analysis.evidence : [];
    const explanation = evidence.map(item => item.message).filter(Boolean);

    if (explanation.length === 0) {
        explanation.push('No major indicators were found by the available heuristic analysis.');
    }

    return {
        score: scoreValue,
        riskScore: scoreValue,
        level: riskLevel,
        riskLevel,
        status: riskLevel === 'SAFE' ? 'LOW RISK' : `${riskLevel} RISK`,
        verdict: scoreValue >= 60 ? 'THREAT_DETECTED' : scoreValue >= 35 ? 'SUSPICIOUS' : 'LOW_RISK',
        category: analysis.category || 'SUSPICIOUS_ACTIVITY',
        confidence: 'Not calibrated',
        evidence,
        indicators: evidence,
        explanation,
        recommendedActions: [recommendation.message, recommendation.userAction],
        recommendation,
        modelType: analysis.modelType || 'heuristic-feature-engineering baseline'
    };
}

module.exports = {
    clamp,
    getRiskLevel,
    classifyThreat,
    generateReasons,
    getRecommendedAction,
    calculateRisk,
    calculateRiskScore,
    assessURL,
    getRiskCategory,
    extractURLFeatures,
    analyzeText,
    analyzeLoginBehavior,
    buildAssessment
};