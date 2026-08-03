import React from "react";
import { useDemo } from "../context/DemoContext.jsx";

export function CommandCenter() {
  const { incidents, watchlist, selectedIncidentId, setSelectedIncidentId, resetDemo } = useDemo();
  const selected = incidents.find((incident) => incident.incidentId === selectedIncidentId) ?? incidents[0] ?? null;

  return <div className="command-center page-enter">
    <header className="command-header"><div><p className="eyebrow">GHOSTSHIELD / SECURITY COMMAND</p><h1>Live transaction defense</h1><p>Selected banking incident · Frontend event stream</p></div><span className="live-indicator"><i/> LIVE</span></header>
    <section className="command-metrics">
      <article><span>Live Risk Score</span><strong className={selected ? "risk-critical" : ""}>{selected ? 100 : 0}</strong><small>{selected?.severity ?? "Normal"}</small></article>
      <article><span>Security Alerts</span><strong>{incidents.length}</strong><small>Current session</small></article>
      <article><span>Status</span><strong className="metric-status">{selected?.outcome ?? "Clear"}</strong><small>{selected?.actionTaken ?? "No action required"}</small></article>
      <article><span>Confidence</span><strong>{selected?.confidence ?? 0}%</strong><small>{selected?.attackType ?? "No active threat"}</small></article>
    </section>
    <div className="command-grid">
      <section className="command-panel"><div className="command-panel-heading"><div><p className="eyebrow">SECURITY ALERTS</p><h2>Incident Timeline</h2></div><span className="streaming-badge">Selected automatically</span></div>
        {incidents.length === 0 ? <div className="command-empty"><span>✓</span><strong>No transaction threats detected</strong><small>Banking incidents appear here immediately.</small></div> : <div className="incident-feed">{incidents.map((incident) => <button className={`incident-event incident-select ${selected?.incidentId === incident.incidentId ? "selected" : ""}`} key={incident.incidentId} onClick={() => setSelectedIncidentId(incident.incidentId)}><span className={`incident-status ${incident.threatPrevented ? "blocked" : "succeeded"}`}>{incident.threatPrevented ? "BLOCKED" : "OVERRIDE"}</span><div><strong>{incident.attackType} · {incident.modifiedRecipient}</strong><p>{incident.originalRecipient} → {incident.modifiedRecipient} · ${incident.originalAmount} → ${incident.modifiedAmount}</p><small>{new Date(incident.timestamp).toLocaleTimeString()} · {incident.user} · {incident.confidence}% confidence</small></div><b>{incident.status}</b></button>)}</div>}
      </section>
      <aside className="command-panel watchlist-panel"><div className="command-panel-heading"><div><p className="eyebrow">CURRENT INCIDENT DETAILS</p><h2>{selected ? `Incident ${selected.incidentId.slice(0, 8)}` : "No incident selected"}</h2></div></div>
        {selected && <><div className="incident-detail-grid"><span>Status</span><strong>{selected.status}</strong><span>Severity</span><strong className="critical-text">{selected.severity}</strong><span>Confidence</span><strong>{selected.confidence}%</strong><span>User</span><strong>{selected.user}</strong><span>Original recipient</span><strong>{selected.originalRecipient}</strong><span>Modified recipient</span><strong className="critical-text">{selected.modifiedRecipient}</strong><span>Original amount</span><strong>${selected.originalAmount}</strong><span>Modified amount</span><strong className="critical-text">${selected.modifiedAmount}</strong></div><ol className="soc-timeline">{selected.timeline.map((event, index) => <li key={event}><i/><div><strong>{event}</strong><small>{index === selected.timeline.length - 1 ? selected.outcome : "Observed by OverSeer"}</small></div></li>)}</ol></>}
        <div className="command-panel-heading"><div><p className="eyebrow">THREAT INTELLIGENCE</p><h2>Blocked Recipients</h2></div></div>{watchlist.length === 0 ? <p className="empty-copy">No recipients have been flagged.</p> : watchlist.map((recipient) => <div className="watchlist-item" key={recipient}><span>!</span><div><strong>{recipient}</strong><small>High-risk recipient · blocked locally</small></div></div>)}
      </aside>
    </div>
    <button className="reset-demo-link" onClick={resetDemo}>Reset complete demo</button>
  </div>;
}
