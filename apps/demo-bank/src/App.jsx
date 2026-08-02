import React, { useState } from "react";
import { BankDashboard } from "./components/BankDashboard.jsx";
import { TransferModal } from "./components/TransferModal.jsx";
import { useDemo } from "./context/DemoContext.jsx";

function Brand() { return <div className="brand"><span>N</span><strong>Northstar</strong><small>DEMO BANK</small></div>; }

function Login({ onLogin }) {
  return <main className="login-page"><section className="login-aside"><Brand/><div><p className="eyebrow">BANKING, BEAUTIFULLY SIMPLE</p><h1>Move money with confidence.</h1><p>A safe mock bank built to demonstrate OverSeer transaction protection.</p></div><small>Educational environment · No real financial activity</small></section><section className="login-card"><div><p className="eyebrow">WELCOME BACK</p><h2>Sign in to Northstar</h2><p className="muted">Use the prefilled demo account to continue.</p></div><label>Email address<input defaultValue="alex.morgan@example.com" type="email" /></label><label>Password<input defaultValue="overseer-demo" type="password" /></label><button className="primary" onClick={onLogin}>Sign in securely</button><p className="safe-note">Protected by OverSeer · Demo credentials only</p></section></main>;
}

function Shell({ onOpenCommandCenter, children }) {
  return <div className="app-shell"><aside className="sidebar"><Brand/><nav><button className="active">Bank Overview</button><button className="command-nav" onClick={onOpenCommandCenter}>GhostShield Security Command</button><button>Accounts</button><button>Cards</button></nav><div className="demo-badge"><span>●</span><div><strong>OverSeer active</strong><small>Mutation detector armed</small></div></div><div className="profile"><span>AM</span><div><strong>Alex Morgan</strong><small>Demo account</small></div></div></aside><div className="content"><header className="topbar"><div><span className="status-dot"/>Safe local simulation · No real transactions</div><button className="command-shortcut" onClick={onOpenCommandCenter}>Open Command Center</button></header>{children}</div></div>;
}

export default function App() {
  const [loggedIn, setLoggedIn] = useState(false);
  const [transferOpen, setTransferOpen] = useState(false);
  const { incidents, selectedIncidentId } = useDemo();

  const openCommandCenter = () => {
    setTransferOpen(false);
    const incident = incidents.find((item) => item.incidentId === selectedIncidentId) ?? incidents[0];
    const commandCenterUrl = new URL("http://127.0.0.1:4100/");
    if (incident) commandCenterUrl.searchParams.set("bankIncident", JSON.stringify(incident));
    commandCenterUrl.hash = "incidents";
    window.location.assign(commandCenterUrl.toString());
  };

  if (!loggedIn) return <Login onLogin={() => setLoggedIn(true)}/>;
  return <Shell onOpenCommandCenter={openCommandCenter}><BankDashboard onTransfer={() => setTransferOpen(true)}/>{transferOpen && <TransferModal onClose={() => setTransferOpen(false)} onOpenCommandCenter={openCommandCenter}/>}</Shell>;
}
