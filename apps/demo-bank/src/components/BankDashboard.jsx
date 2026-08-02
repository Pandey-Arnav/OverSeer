import React from "react";
import { useDemo } from "../context/DemoContext.jsx";
import { RecentTransactions } from "./RecentTransactions.jsx";

export function BankDashboard({ onTransfer }) {
  const { balance, transactions, watchlist } = useDemo();
  return <div className="page page-enter"><div className="page-heading"><div><p className="eyebrow">GOOD AFTERNOON</p><h1>Alex Morgan</h1></div><button className="primary compact" onClick={onTransfer}>Make a Transfer</button></div>{watchlist.length > 0 && <div className="watchlist-notice"><span>🛡</span><div><strong>Threat intelligence active</strong><small>{watchlist.length} blocked recipient{watchlist.length === 1 ? "" : "s"} on your watchlist</small></div></div>}<section className="balance-card"><div><span>CHECKING ACCOUNT ·· 1842</span><strong className="balance-animated">${balance.toLocaleString("en-US", { minimumFractionDigits: 2 })}</strong><small>Available balance</small></div><div className="balance-mark">N</div></section><section className="panel"><div className="panel-heading"><div><h2>Recent Transactions</h2><p>Activity across your checking account</p></div><button className="text-button">View all</button></div><RecentTransactions transactions={transactions}/></section></div>;
}
