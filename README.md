# Overseer Transaction Integrity Guard

Overseer has one mission: prevent unauthorized changes to financial transactions before submission.

## Scope

- Fake banking application
- Transaction Integrity Guard
- Browser-trusted transaction snapshot
- DOM monitoring with `MutationObserver`
- Protected-field monitoring for recipient, amount, account number, and routing number
- Dynamic script-injection detection
- Hidden-iframe detection
- Transparent risk engine
- Transaction freeze at the critical threshold
- Restoration of the trusted values
- Structured security-incident emission and local history

It does not perform endpoint, network, USB, malware, keystroke, or general-purpose device monitoring.

## Pipeline

```text
Browser Monitor
      ↓
Risk Engine
      ↓
Incident Object
```

The browser monitor creates the initial trusted snapshot and updates it only from browser-trusted user input. Programmatic changes to protected fields, suspicious DOM changes, injected scripts, and hidden iframes become risk findings. The risk engine scores those findings. At a score of 70 or greater, the guard blocks submission, restores the trusted field values, and emits an incident object.

## Run

```sh
npm install
npm start
```

Use **Inject Attack (demo)** to simulate unauthorized field changes, script insertion, and a hidden iframe.

## Build

```sh
npm run build
```
