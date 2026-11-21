# Plan: AI Scan Explanations (offline)

Date: 2026-11-21
Status: completed

## Goal
Add plain-English, AI-style explanations to every scan result so users understand
the risk score, the indicators behind it, and what to do next. Runs fully offline
with no API key and reuses the existing heuristic / AI / threat-intel output.

## Scope
- New `backend/explanation-engine.js` (deterministic explainability layer).
- Attach `result.explanation` in:
  - `POST /api/scan-url`
  - `POST /api/analyze-email`
  - `POST /api/analyze-page`
- Display the explanation on:
  - Dashboard (`frontend/index.html` + `frontend/script.js`)
  - URL Scanner (`frontend/pages/scanner.html`)
  - Email Analyzer (`frontend/pages/email-analyzer.html`)
- Shared styling in `frontend/style.css`.

## Explanation payload
```
{
  engine: "PhishGuard Explainable AI (offline)",
  headline: string,
  summary: string,
  score: number,
  level: string,
  verdict: string,
  confidence: string,
  reasons: string[],
  indicators: [{ type, title, detail, severity }],
  recommendations: string[],
  generatedAt: ISO timestamp
}
```

## Steps
1. Create `backend/explanation-engine.js` with score/flag normalization,
   risk summaries, driver detection, severity-aware recommendations.
2. Wire the engine into the three scan endpoints in `backend/server.js`.
3. Add shared explanation UI styles to `frontend/style.css`.
4. Render explanation on the dashboard (`index.html`, `script.js`).
5. Render explanation on the scanner page (`scanner.html`).
6. Render explanation on the email analyzer page (`email-analyzer.html`).
7. Validate: node syntax check, start backend, POST sample URL + email,
   confirm `result.explanation` is present and UI markup ids exist.

## Validation
- `node --check backend/explanation-engine.js`
- `node --check backend/server.js`
- Start `backend/server.js`, POST to `/api/scan-url` with a suspicious URL
  and `/api/analyze-email` with a phishing sample; assert explanation fields.