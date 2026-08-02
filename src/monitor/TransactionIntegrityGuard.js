import { PROTECTED_FIELDS, cloneTransaction, readTransaction } from "../utils/snapshot.js";
import { createIncident } from "../models/Incident.js";
import { calculateRisk } from "./RiskEngine.js";

export class TransactionIntegrityGuard {
  constructor({ form, eventBus }) { this.form = form; this.eventBus = eventBus; this.snapshot = cloneTransaction(readTransaction(form)); this.frozen = false; this.findings = new Set(); this.observer = null; this.restore = []; }
  start() {
    for (const name of PROTECTED_FIELDS) {
      const field = this.form.elements[name]; if (!field) continue;
      const descriptor = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(field), "value");
      if (!descriptor?.set || !descriptor?.get) continue;
      Object.defineProperty(field, "value", { configurable: true, get: descriptor.get, set: (value) => { const before = descriptor.get.call(field); descriptor.set.call(field, value); if (before !== String(value)) this.detect([name]); } });
      this.restore.push(() => delete field.value);
    }
    this.form.addEventListener("input", (event) => {
      if (event.isTrusted && PROTECTED_FIELDS.includes(event.target.name)) this.snapshot[event.target.name] = event.target.value;
    }, true);
    this.form.addEventListener("change", (event) => {
      if (event.isTrusted && PROTECTED_FIELDS.includes(event.target.name)) this.snapshot[event.target.name] = event.target.value;
    }, true);
    this.form.addEventListener("submit", (event) => { if (this.frozen) { event.preventDefault(); event.stopImmediatePropagation(); } });
    this.observer = new MutationObserver(() => { const changed = PROTECTED_FIELDS.filter((name) => this.form.elements[name] && this.form.elements[name].value !== this.snapshot[name]); if (changed.length) this.detect(changed); });
    this.observer.observe(this.form, { subtree: true, childList: true, attributes: true });
  }
  detect(fields) {
    if (this.frozen) return;
    fields.forEach((field) => this.findings.add(field)); this.findings.add("protectedFieldModified"); this.findings.add("paymentFormModified");
    const { fraudRisk, detectedRules } = calculateRisk([...this.findings]);
    if (fraudRisk < 70) return;
    this.frozen = true; this.form.querySelector('[type="submit"]')?.setAttribute("disabled", "true");
    fields.forEach((field) => this.form.elements[field]?.classList.add("overseer-modified"));
    const modifiedTransaction = readTransaction(this.form);
    for (const field of this.findings) {
      if (!PROTECTED_FIELDS.includes(field) || !this.form.elements[field]) continue;
      const descriptor = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(this.form.elements[field]), "value");
      descriptor?.set?.call(this.form.elements[field], this.snapshot[field]);
    }
    const incident = createIncident({ attackType: "transaction-tampering", page: location.href, fraudRisk, modifiedFields: [...this.findings].filter((f) => PROTECTED_FIELDS.includes(f)), detectedRules, actionTaken: "transaction-frozen-values-restored", originalTransaction: cloneTransaction(this.snapshot), modifiedTransaction });
    this.eventBus.emit("incident", incident); this.eventBus.emit("transaction-frozen", incident);
  }
  recordFinding(rule) {
    if (this.frozen) return;
    this.findings.add(rule);
    const { fraudRisk } = calculateRisk([...this.findings]);
    if (fraudRisk >= 70) this.detect([]);
  }
  stop() { this.observer?.disconnect(); this.restore.forEach((restore) => restore()); }
}
