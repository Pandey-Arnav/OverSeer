import React from "react";

export function RecentTransactions({ transactions }) {
  return <div className="transaction-list">{transactions.map((item) => <div className={`transaction animated-row ${item.dangerous ? "dangerous-transaction" : ""}`} key={item.id}><span className="transaction-icon">{item.direction === "in" ? "↓" : "↑"}</span><div><strong>{item.recipient}</strong><small>{item.date} · {item.status}</small></div><b className={item.direction}>{item.direction === "in" ? "+" : "−"}${item.amount.toLocaleString("en-US", { minimumFractionDigits: 2 })}</b></div>)}</div>;
}
