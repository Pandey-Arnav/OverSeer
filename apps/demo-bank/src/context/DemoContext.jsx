import React, { createContext, useContext, useMemo, useState } from "react";

const INITIAL_BALANCE = 12400.52;
const INITIAL_TRANSACTIONS = [
  { id: "payroll", recipient: "Cloudline Payroll", date: "Aug 1, 2026", amount: 4820, direction: "in", status: "Completed" },
  { id: "coffee", recipient: "Aperture Coffee", date: "Jul 31, 2026", amount: 8.75, direction: "out", status: "Completed" },
  { id: "electric", recipient: "Northstar Electric", date: "Jul 29, 2026", amount: 126.4, direction: "out", status: "Completed" },
];

const DemoContext = createContext(null);

function createIncident({ original, modified, actionTaken, status, threatPrevented }) {
  const incidentId = crypto.randomUUID();
  const outcome = threatPrevented ? "Frozen" : "User Override";
  return {
    id: incidentId,
    incidentId,
    timestamp: new Date().toISOString(),
    severity: "Critical",
    status,
    outcome,
    threatType: "DOM Injection",
    attackType: "DOM Injection",
    user: "Alex Morgan",
    originalRecipient: original.recipient,
    modifiedRecipient: modified.recipient,
    originalAmount: original.amount,
    modifiedAmount: modified.amount,
    originalAccount: original.accountNumber,
    modifiedAccount: modified.accountNumber,
    actionTaken,
    actionsTaken: threatPrevented ? ["Transaction Frozen", "Original values restored", "Threat blocked", "Recipient added to watchlist"] : ["User ignored warning", "Transaction completed", "Threat succeeded"],
    detectionConfidence: 98,
    confidence: 98,
    threatPrevented,
    timeline: ["Transfer Initiated", "DOM Manipulation Detected", "Recipient Modified", "Amount Modified", "Threat Detected", threatPrevented ? "Transaction Frozen" : "User Override", threatPrevented ? "Recipient Added to Watchlist" : "Malicious Transfer Completed", "Incident Closed"],
  };
}

export function DemoProvider({ children }) {
  const [balance, setBalance] = useState(INITIAL_BALANCE);
  const [transactions, setTransactions] = useState(INITIAL_TRANSACTIONS);
  const [incidents, setIncidents] = useState([]);
  const [watchlist, setWatchlist] = useState([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);

  const freezeTransaction = (original, modified) => {
    const incident = createIncident({ original, modified, actionTaken: "Transaction Frozen", status: "Blocked", threatPrevented: true });
    setIncidents((items) => [incident, ...items]);
    setSelectedIncidentId(incident.incidentId);
    setWatchlist((items) => items.includes(modified.recipient) ? items : [modified.recipient, ...items]);
    return incident;
  };

  const overrideTransaction = (original, modified) => {
    const amount = Number(modified.amount);
    const incident = createIncident({ original, modified, actionTaken: "User ignored warning", status: "Completed (User Override)", threatPrevented: false });
    setIncidents((items) => [incident, ...items]);
    setSelectedIncidentId(incident.incidentId);
    setBalance((value) => value - amount);
    setTransactions((items) => [{ id: incident.id, recipient: modified.recipient, date: "Just now", amount, direction: "out", status: "Completed · User Override", dangerous: true }, ...items]);
    return incident;
  };

  const resetDemo = () => { setBalance(INITIAL_BALANCE); setTransactions(INITIAL_TRANSACTIONS); setIncidents([]); setWatchlist([]); setSelectedIncidentId(null); };
  const value = useMemo(() => ({ balance, transactions, incidents, watchlist, selectedIncidentId, setSelectedIncidentId, freezeTransaction, overrideTransaction, resetDemo }), [balance, transactions, incidents, watchlist, selectedIncidentId]);
  return <DemoContext.Provider value={value}>{children}</DemoContext.Provider>;
}

export function useDemo() {
  const value = useContext(DemoContext);
  if (!value) throw new Error("useDemo must be used inside DemoProvider");
  return value;
}
