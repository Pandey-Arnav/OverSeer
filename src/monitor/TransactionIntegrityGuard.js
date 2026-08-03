import { PROTECTED_FIELDS, cloneTransaction, readTransaction } from "../utils/snapshot.js";
import { createIncident } from "../models/Incident.js";
import { calculateRisk } from "./RiskEngine.js";

export class TransactionIntegrityGuard {
  constructor({ form, eventBus }) {
    this.form = form;
    this.eventBus = eventBus;
    this.snapshot = cloneTransaction(readTransaction(form));
    this.modifiedTransaction = cloneTransaction(this.snapshot);
    this.frozen = false;
    this.findings = new Set();
    this.observer = null;
    this.incidentTimer = null;
    this.restore = [];
  }

  start() {
    for (const name of PROTECTED_FIELDS) {
      const field = this.form.elements[name];
      if (!field) continue;
      const descriptor = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(field), "value");
      if (!descriptor?.set || !descriptor?.get) continue;

      Object.defineProperty(field, "value", {
        configurable: true,
        get: descriptor.get,
        set: (value) => {
          const before = descriptor.get.call(field);
          descriptor.set.call(field, value);
          if (before !== String(value)) this.detect([name]);
        },
      });
      this.restore.push(() => delete field.value);
    }

    const updateSnapshot = (event) => {
      if (!event.isTrusted || !PROTECTED_FIELDS.includes(event.target.name) || this.frozen) return;
      this.snapshot[event.target.name] = event.target.value;
      this.modifiedTransaction[event.target.name] = event.target.value;
    };
    this.form.addEventListener("input", updateSnapshot, true);
    this.form.addEventListener("change", updateSnapshot, true);
    this.restore.push(() => this.form.removeEventListener("input", updateSnapshot, true));
    this.restore.push(() => this.form.removeEventListener("change", updateSnapshot, true));

    const blockFrozenSubmission = (event) => {
      if (!this.frozen) return;
      event.preventDefault();
      event.stopImmediatePropagation();
    };
    this.form.addEventListener("submit", blockFrozenSubmission, true);
    this.restore.push(() => this.form.removeEventListener("submit", blockFrozenSubmission, true));

    for (const method of ["submit", "requestSubmit"]) {
      const nativeMethod = this.form[method]?.bind(this.form);
      if (!nativeMethod) continue;
      Object.defineProperty(this.form, method, {
        configurable: true,
        value: (...args) => {
          if (!this.frozen) return nativeMethod(...args);
        },
      });
      this.restore.push(() => delete this.form[method]);
    }

    this.observer = new MutationObserver(() => {
      const changed = PROTECTED_FIELDS.filter(
        (name) => this.form.elements[name] && this.form.elements[name].value !== this.snapshot[name],
      );
      if (changed.length) this.detect(changed);
    });
    this.observer.observe(this.form, { subtree: true, childList: true, attributes: true });
  }

  detect(fields) {
    for (const name of fields) {
      const field = this.form.elements[name];
      if (!field) continue;
      this.modifiedTransaction[name] = field.value;
      this.findings.add(name);
      field.classList.add("overseer-modified");
      this.restoreField(name);
    }

    if (fields.length) {
      this.findings.add("protectedFieldModified");
      this.findings.add("paymentFormModified");
    }

    const { fraudRisk } = calculateRisk([...this.findings]);
    if (fraudRisk < 70) return;

    if (!this.frozen) {
      this.frozen = true;
      this.form.querySelector('[type="submit"]')?.setAttribute("disabled", "true");
    }
    this.restoreAllFields();
    this.scheduleIncident();
  }

  restoreField(name) {
    const field = this.form.elements[name];
    if (!field) return;
    const descriptor = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(field), "value");
    descriptor?.set?.call(field, this.snapshot[name]);
  }

  restoreAllFields() {
    for (const name of PROTECTED_FIELDS) this.restoreField(name);
  }

  scheduleIncident() {
    if (this.incidentTimer !== null) return;
    this.incidentTimer = setTimeout(() => {
      this.incidentTimer = null;
      const { fraudRisk, detectedRules } = calculateRisk([...this.findings]);
      const incident = createIncident({
        attackType: "transaction-tampering",
        page: location.href,
        fraudRisk,
        modifiedFields: [...this.findings].filter((finding) => PROTECTED_FIELDS.includes(finding)),
        detectedRules,
        actionTaken: "transaction-frozen-values-restored",
        originalTransaction: cloneTransaction(this.snapshot),
        modifiedTransaction: cloneTransaction(this.modifiedTransaction),
      });
      this.eventBus.emit("incident", incident);
      this.eventBus.emit("transaction-frozen", incident);
    }, 0);
  }

  recordFinding(rule) {
    this.findings.add(rule);
    const { fraudRisk } = calculateRisk([...this.findings]);
    if (fraudRisk >= 70) this.detect([]);
  }

  stop() {
    this.observer?.disconnect();
    if (this.incidentTimer !== null) clearTimeout(this.incidentTimer);
    this.restore.forEach((restore) => restore());
  }
}
