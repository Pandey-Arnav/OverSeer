/**
 * Sentinel Transaction Guardian — shared constants.
 *
 * Deliberately a small, standalone extension now: unlike the earlier
 * prototype, transaction-tampering detection is pure native DOM/input-
 * event observation — no JS-method-overriding, so no MAIN-world hook is
 * needed at all (see content/content-script.ts). Scoring happens
 * server-side in the agent (the single canonical risk engine, matching
 * agent/src/risk/engine.ts) — this extension only detects and reports.
 */

export const AGENT_URL = "http://localhost:4100";

// Matches common payment/transfer field identifiers (name/id/autocomplete/
// placeholder) — kept in sync with agent/src/shared/constants.ts
// PAYMENT_FIELD_PATTERN by design; the two can't share a source file
// without a monorepo package, so duplication here is intentional and
// low-risk (a small, rarely-changed regex).
export const PAYMENT_FIELD_PATTERN =
  /\b(account|iban|routing|swift|recipient|payee|beneficiary|wallet|address|amount|sum|total|transfer)\b/i;
