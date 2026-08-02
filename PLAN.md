# Sentinel — Implementation Plan

Hackathon-scoped Chrome MV3 extension: detect suspicious page behavior, score
it locally, allow/warn/block, log incidents, optional AI explanation.
Vanilla JS extension + Node/Express backend. No frameworks, no TypeScript,
no Docker/DB/auth beyond MVP.

## Phase 1 — Foundation (risk engine first, everything else depends on it)
- [x] Folder scaffold: `extension/`, `server/`, `demo/` per spec
- [x] `extension/manifest.json` (MV3)
- [x] `extension/shared/constants.js` — thresholds, rule weights, incident model
- [x] `extension/shared/utils.js` — small shared helpers (origin parsing, IP detection, uuid)
- [x] `extension/risk/rules.js` — modular rule definitions
- [x] `extension/risk/engine.js` — scoring + decision
- [x] `server/` skeleton (package.json only, no server logic yet)
- [x] Risk engine tests (Node built-in test runner) — run and pass (15/15)

## Phase 2 — Instrumentation + pipeline
- [x] `extension/content/page-monitor.js` (MAIN world: fetch/XHR/sendBeacon/clipboard/history hooks)
- [x] `extension/content/content-script.js` (ISOLATED world: postMessage validation, relay to background, form-submission hold/resume)
- [x] `extension/background/service-worker.js` (webNavigation redirect tracking, risk evaluation, decision, badge, DNR raw-IP rule)
- [x] `extension/storage/incidents.js` (chrome.storage.local read/write/query)
- [x] Manual smoke test path documented (README demo instructions)

## Phase 3 — UI
- [x] `extension/popup/` (popup.html/css/js) — status, counts, recent 3, toggles, dashboard link
- [x] `extension/dashboard/` (dashboard.html/css/js) — summary cards, filterable table, expandable details, clear-history, explain button

## Phase 4 — Backend
- [x] `server/src/app.js`, `routes/explain.js`, `services/ai-explanation.js`, `middleware/error-handler.js`
- [x] Mock-mode fallback (no API key required) — verified via curl
- [x] Dashboard → `/api/explain` wiring

## Phase 5 — Demo + polish
- [x] `demo/safe-test.html`, `demo/suspicious-test.html`, `demo/redirect-test.html`
- [x] Full test pass (15/15 risk-engine tests, all JS syntax-checked, manifest.json validated)
- [x] Fixed a real bug found during this phase: `multipleRedirects` context wasn't being fed by `history_change` events, only real `webNavigation` redirects — fixed in `service-worker.js`
- [x] README (overview, threat model, Mermaid architecture, setup, testing, MV3 limitations, privacy, team split)

## Acceptance criteria (from spec)
- [x] Extension loads in Chrome with no errors — **not yet verified in an actual browser window** (see README known limitations / Phase 2 notes on sandboxed automation); manifest validated as JSON, all JS syntax-checked
- [ ] Popup opens cleanly — logic complete, needs manual verification
- [ ] Demo page events detected — logic complete, needs manual verification
- [x] Risk scores correct — verified via automated tests
- [x] High-risk form submissions preventable — implemented (preventDefault + async gate + form.submit() resume)
- [x] Incidents stored locally — implemented (chrome.storage.local)
- [ ] Dashboard displays + filters incidents — logic complete, needs manual verification
- [x] AI explanations work in mock mode — verified via curl
- [x] Risk-engine tests pass — 15/15
- [x] No sensitive data collected — enforced + tested
- [x] README complete
