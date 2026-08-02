import React, { useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { EventBus } from "./services/EventBus.js";
import { TransactionIntegrityGuard } from "./monitor/TransactionIntegrityGuard.js";
import { ScriptDetector } from "./monitor/ScriptDetector.js";
import { SecurityBanner } from "./components/SecurityBanner.jsx";
import "./styles.css";

function BankingDemo() {
  const formRef = useRef(null); const [incident, setIncident] = useState(null); const [incidents, setIncidents] = useState([]); const busRef = useRef(null);
  useEffect(() => {
    const bus = new EventBus(); busRef.current = bus; const guard = new TransactionIntegrityGuard({ form: formRef.current, eventBus: bus }); const scripts = new ScriptDetector({ eventBus: bus });
    const history = JSON.parse(localStorage.getItem("overseer-incidents") || "[]"); setIncidents(history); bus.on("security-finding", ({ rule }) => guard.recordFinding(rule)); bus.on("incident", (next) => { setIncident(next); setIncidents((items) => { const updated = [next, ...items].slice(0, 100); localStorage.setItem("overseer-incidents", JSON.stringify(updated)); return updated; }); }); guard.start(); scripts.start(); return () => { guard.stop(); scripts.stop(); };
  }, []);
  function injectAttack() { const form = formRef.current; form.elements.recipient.value = "MALICIOUS ACCOUNT"; form.elements.amount.value = "$50,000.00"; form.elements.accountNumber.value = "999999999"; form.elements.routingNumber.value = "999000999"; const iframe = document.createElement("iframe"); iframe.hidden = true; document.body.appendChild(iframe); const script = document.createElement("script"); script.type = "application/json"; script.textContent = "demo injected script marker"; document.body.appendChild(script); }
  function submit(event) { event.preventDefault(); if (!incident) window.alert("Demo transaction passed integrity checks."); }
  return <main><header><div><p className="eyebrow">OVERSEER · BROWSER MONITORING ENGINE</p><h1>Transaction Integrity Guard</h1><p className="muted">A protected banking transaction running inside the Overseer desktop app.</p></div><span className="status">● Monitoring</span></header><SecurityBanner incident={incident}/><section className="grid"><div className="card"><div className="bank-brand">Northstar Bank <span>secure transfer</span></div><form ref={formRef} onSubmit={submit}><label>Recipient<input name="recipient" defaultValue="Alice Johnson" /></label><label>Transfer Amount<input name="amount" defaultValue="$500.00" /></label><label>Account Number<input name="accountNumber" defaultValue="123456789" /></label><label>Routing Number<input name="routingNumber" defaultValue="021000021" /></label><button type="submit">Transfer funds</button></form><button className="attack" onClick={injectAttack}>⚠ Inject Attack (demo)</button></div><aside className="card"><h2>Protection status</h2><div className={incident ? "risk critical" : "risk safe"}>{incident ? `${incident.fraudRisk}/100` : "Protected"}</div><p className="muted">MutationObserver watches protected fields, scripts, iframes, and unexpected DOM changes.</p><h3>Incident output</h3>{incidents.length === 0 ? <p className="muted">No incidents detected.</p> : incidents.map((item) => <div className="incident" key={item.id}><strong>{item.attackType}</strong><span>Risk {item.fraudRisk} · {item.actionTaken}</span><small>{new Date(item.timestamp).toLocaleTimeString()}</small></div>)}</aside></section></main>;
}

createRoot(document.getElementById("root")).render(<BankingDemo />);
