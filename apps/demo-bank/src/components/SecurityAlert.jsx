import React from "react";

export function SecurityAlert({ original, modified, onFreeze, onProceed }) {
  const fields = [
    ["Recipient", original.recipient, modified.recipient],
    ["Amount", `$${Number(original.amount).toLocaleString()}`, `$${Number(modified.amount).toLocaleString()}`],
    ["Account", original.accountNumber, modified.accountNumber],
  ];
  return <div className="modal-backdrop security-backdrop"><section className="security-alert" role="alertdialog" aria-modal="true"><div className="alert-heading"><span>🚨</span><div><p>OVERSEER SECURITY</p><h2>Transaction Manipulation Detected</h2></div><b>98% confidence</b></div><div className="threat-summary"><div><span>Threat type</span><strong>DOM Injection</strong></div><div><span>Severity</span><strong className="critical-text">Critical</strong></div></div><p className="alert-explanation">OverSeer detected unauthorized modifications before the transaction was submitted.</p><div className="field-diffs"><span className="diff-title">Fields modified</span>{fields.map(([label, oldValue, newValue]) => <div className="field-diff" key={label}><strong>{label}</strong><span>{oldValue}</span><b>→</b><span className="malicious-value">{newValue}</span></div>)}</div><div className="alert-actions"><button className="freeze-button" onClick={onFreeze}>Freeze Transaction</button><button className="override-button" onClick={onProceed}>Proceed Anyway</button></div></section></div>;
}
