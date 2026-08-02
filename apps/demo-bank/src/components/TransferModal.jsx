import React, { useRef, useState } from "react";
import { useDemo } from "../context/DemoContext.jsx";
import { MalwareSimulator } from "./MalwareSimulator.jsx";
import { SecurityAlert } from "./SecurityAlert.jsx";

const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));
const ATTACKER = { recipient: "Hacker LLC", amount: "5000", memo: "Dinner", accountNumber: "991100773355" };

export function TransferModal({ onClose, onOpenCommandCenter }) {
  const { watchlist, freezeTransaction, overrideTransaction } = useDemo();
  const [draft, setDraft] = useState({ recipient: "Alice Johnson", amount: "100", memo: "Dinner", accountNumber: "482173901156" });
  const [original, setOriginal] = useState(null);
  const [phase, setPhase] = useState("idle");
  const [step, setStep] = useState("");
  const [modifiedFields, setModifiedFields] = useState([]);
  const running = useRef(false);
  const isWatchlisted = watchlist.some((item) => item.toLowerCase() === draft.recipient.trim().toLowerCase());

  const simulateAttack = async (event) => {
    event.preventDefault();
    if (running.current) return;
    running.current = true;
    const trusted = { ...draft };
    setOriginal(trusted); setPhase("attacking"); setStep("Malicious script injected into transfer DOM");
    await delay(550); setDraft((value) => ({ ...value, recipient: ATTACKER.recipient })); setModifiedFields(["recipient"]); setStep("Recipient silently rerouted");
    await delay(650); setDraft((value) => ({ ...value, amount: ATTACKER.amount })); setModifiedFields(["recipient", "amount"]); setStep("Transfer amount increased");
    await delay(650); setDraft((value) => ({ ...value, accountNumber: ATTACKER.accountNumber })); setModifiedFields(["recipient", "amount", "accountNumber"]); setStep("Destination account replaced");
    await delay(600); setPhase("detected"); running.current = false;
  };

  const freeze = () => { freezeTransaction(original, ATTACKER); setDraft(original); setModifiedFields([]); setPhase("frozen"); };
  const proceed = async () => { setPhase("overriding"); await delay(1000); overrideTransaction(original, ATTACKER); onClose(); };
  const fieldClass = (name) => modifiedFields.includes(name) ? "attack-flash" : phase === "frozen" ? "restored-field" : "";

  return <div className="modal-backdrop transfer-backdrop"><section className="transfer-modal"><header><div><p className="eyebrow">NORTHSTAR CHECKING ·· 1842</p><h2>Make a Transfer</h2></div><button onClick={onClose} aria-label="Close transfer">×</button></header>{isWatchlisted && <div className="preflight-warning">⚠ <div><strong>Flagged recipient detected</strong><small>{draft.recipient} is on the OverSeer threat watchlist. Verify before sending.</small></div></div>}<MalwareSimulator active={phase === "attacking"} step={step}/>{phase === "frozen" ? <div className="freeze-success"><span className="freeze-check">✓</span><h2>Transaction Frozen</h2><div><strong>✓ Original values restored</strong><strong>✓ Threat blocked</strong><strong>✓ Recipient flagged</strong></div><p>Hacker LLC was added to Threat Intelligence.</p><button className="primary" onClick={onOpenCommandCenter}>View in OverSeer Command Center</button></div> : phase === "overriding" ? <div className="override-progress"><span>!</span><h2>User Override</h2><p>Proceeding despite security warning…</p><i/></div> : <form onSubmit={simulateAttack}><label>Recipient<input className={fieldClass("recipient")} value={draft.recipient} onChange={(event) => setDraft({ ...draft, recipient: event.target.value })}/></label><div className="transfer-two-column"><label>Amount<div className="amount-input"><span>$</span><input className={fieldClass("amount")} value={draft.amount} onChange={(event) => setDraft({ ...draft, amount: event.target.value })}/></div></label><label>Destination account<input className={fieldClass("accountNumber")} value={draft.accountNumber} onChange={(event) => setDraft({ ...draft, accountNumber: event.target.value })}/></label></div><label>Memo <small>Optional</small><input value={draft.memo} onChange={(event) => setDraft({ ...draft, memo: event.target.value })}/></label><div className="transfer-review"><span>Available balance</span><strong>$12,400.52</strong><span>Arrival</span><strong>Today · No fee</strong></div><button className="primary send-button" disabled={phase === "attacking"}>{phase === "attacking" ? "Processing securely…" : "Send"}</button></form>}{phase === "detected" && <SecurityAlert original={original} modified={ATTACKER} onFreeze={freeze} onProceed={proceed}/>}</section></div>;
}
