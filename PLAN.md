# Transaction Integrity Guard — Delivery Plan

## Mission

Prevent unauthorized changes to financial transactions before submission.

## Completed pipeline

- [x] Fake banking application with recipient, amount, account number, and routing number
- [x] Browser-trusted transaction snapshot
- [x] Protected-field setter and trusted-input monitoring
- [x] DOM monitoring with `MutationObserver`
- [x] Dynamic script-injection detection
- [x] Hidden-iframe detection, including later visibility changes
- [x] Transparent additive risk engine
- [x] Submission freeze at the critical threshold
- [x] Restoration of original trusted values
- [x] Structured incident creation and local incident history

```text
Browser Monitor → Risk Engine → Incident Object
```

## Acceptance criteria

- [x] Programmatic protected-field changes cannot replace the trusted snapshot
- [x] Synthetic input/change events cannot replace the trusted snapshot
- [x] A critical event disables and blocks transaction submission
- [x] Modified fields are restored from the trusted snapshot
- [x] Each frozen transaction emits one structured incident
- [x] The active application has no network, USB, endpoint, keystroke, or general malware-monitoring behavior
