# GhostShield + AEGIS ForkGuard (Jac 0.16.7)
#
# This service performs an additive, counterfactual review of Sentinel's
# sanitized incident metadata. Sentinel remains the browser enforcement
# authority; AEGIS independently evaluates four possible futures and returns
# an explainable decision graph. No raw form values, credentials, cookies, or
# request bodies are accepted by this service.

import from datetime { datetime, timezone }
import from uuid { uuid4 }

node AegisNode {}

node IncidentRun(AegisNode) {
    has run_id: str;
    has source_incident_id: str;
    has created_at: str;
    has audit_seq: int = 0;
}

node ObservedEvent(AegisNode) {
    has event_type: str;
    has page_origin: str;
    has destination_origin: str;
    has sentinel_score: int;
    has sentinel_decision: str;
    has blockable: bool;
}

node Evidence(AegisNode) {
    has evidence_id: str;
    has rule_id: str;
    has label: str;
    has points: int;
    has trust_level: str = "sentinel_observed";
}

node FutureBranch(AegisNode) {
    has name: str;
    has title: str;
    has action_variant: str;
    has risk_score: int = 0;
    has utility_score: int = 0;
    has valid: bool = True;
    has verdict: str = "PENDING";
}

node Policy(AegisNode) {
    has policy_id: str;
    has description: str;
    has severity: str;
}

node Violation(AegisNode) {
    has branch_name: str;
    has policy_id: str;
    has reason: str;
    has severity: str;
}

node Decision(AegisNode) {
    has selected_branch: str;
    has status: str;
    has confidence: float;
    has summary: str;
}

node AuditEvent(AegisNode) {
    has seq: int;
    has stage: str;
    has details: str;
    has timestamp: str;
}

edge Contains: AegisNode --> AegisNode { has kind: str = ""; }
edge FORKS_TO: ObservedEvent --> FutureBranch {}
edge EVALUATED_AGAINST: FutureBranch --> Policy { has result: str = "pass"; }
edge VIOLATES: FutureBranch --> Policy { has severity: str = ""; }
edge SUPPORTED_BY: Decision --> Evidence {}
edge SELECTS: Decision --> FutureBranch {}

def now_iso() -> str {
    return datetime.now(timezone.utc).isoformat();
}

def safe_int(value: any, fallback: int) -> int {
    try {
        return int(float(str(value)));
    } except (ValueError, TypeError) {
        return fallback;
    }
}

def safe_bool(value: any) -> bool {
    return bool(value) if isinstance(value, bool) else False;
}

def bounded_score(value: any) -> int {
    score = safe_int(value, 0);
    if score < 0 { return 0; }
    if score > 100 { return 100; }
    return score;
}

def add_audit(run: IncidentRun, stage: str, details: str) -> None {
    run.audit_seq += 1;
    audit = AuditEvent(
        seq=run.audit_seq,
        stage=stage,
        details=details,
        timestamp=now_iso()
    );
    run +>:Contains(kind="audit"):+> audit;
}

def get_event(run: IncidentRun) -> ObservedEvent | None {
    events = [run ->:Contains:kind == "event":->[?:ObservedEvent]];
    return events[0] if events else None;
}

def get_branches(run: IncidentRun) -> list[FutureBranch] {
    return [run ->:Contains:kind == "branch":->[?:FutureBranch]];
}

def get_policies(run: IncidentRun) -> list[Policy] {
    return [run ->:Contains:kind == "policy":->[?:Policy]];
}

def get_evidence(run: IncidentRun) -> list[Evidence] {
    return [run ->:Contains:kind == "evidence":->[?:Evidence]];
}

def get_violations(run: IncidentRun) -> list[Violation] {
    return [run ->:Contains:kind == "violation":->[?:Violation]];
}

def get_decision(run: IncidentRun) -> Decision | None {
    decisions = [run ->:Contains:kind == "decision":->[?:Decision]];
    return decisions[0] if decisions else None;
}

def get_timeline(run: IncidentRun) -> list[AuditEvent] {
    events = [run ->:Contains:kind == "audit":->[?:AuditEvent]];
    return sorted(events, key=lambda item: AuditEvent : item.seq);
}

def find_policy(run: IncidentRun, policy_id: str) -> Policy | None {
    for policy_item in get_policies(run) {
        if policy_item.policy_id == policy_id { return policy_item; }
    }
    return None;
}

def find_branch(run: IncidentRun, branch_name: str) -> FutureBranch | None {
    for branch_item in get_branches(run) {
        if branch_item.name == branch_name { return branch_item; }
    }
    return None;
}

def add_violation(
    run: IncidentRun,
    branch_item: FutureBranch,
    policy_id: str,
    reason: str,
    severity: str
) -> None {
    policy_item = find_policy(run, policy_id);
    if policy_item is None { return; }
    policy_node = policy_item as Policy;
    violation = Violation(
        branch_name=branch_item.name,
        policy_id=policy_id,
        reason=reason,
        severity=severity
    );
    run +>:Contains(kind="violation"):+> violation;
    branch_item +>:VIOLATES(severity=severity):+> policy_node;
}

walker ingest_walker {
    has payload: dict[str, any];

    can ingest with IncidentRun entry {
        event = ObservedEvent(
            event_type=str(self.payload.get("eventType", "unknown")),
            page_origin=str(self.payload.get("pageOrigin", "unknown")),
            destination_origin=str(self.payload.get("destinationOrigin", "")),
            sentinel_score=bounded_score(self.payload.get("score", 0)),
            sentinel_decision=str(self.payload.get("decision", "allow")),
            blockable=safe_bool(self.payload.get("blockable", False))
        );
        here +>:Contains(kind="event"):+> event;

        reasons = self.payload.get("reasons", []) as list[dict[str, any]];
        index = 0;
        for reason in reasons {
            index += 1;
            evidence = Evidence(
                evidence_id=f"EV-{index:02d}",
                rule_id=str(reason.get("ruleId", "sentinel-finding")),
                label=str(reason.get("label", "Sentinel risk finding")),
                points=safe_int(reason.get("points", 0), 0)
            );
            here +>:Contains(kind="evidence"):+> evidence;
        }

        policies: list[Policy] = [
            Policy(
                policy_id="FG-REVIEW-40",
                description="Actions scoring 40 or higher require explicit review before continuation.",
                severity="high"
            ),
            Policy(
                policy_id="FG-CONTAIN-70",
                description="Actions scoring 70 or higher may not continue unchanged.",
                severity="critical"
            ),
            Policy(
                policy_id="FG-BLOCKABILITY",
                description="A technically non-blockable action must use containment and logging, not claim it was blocked.",
                severity="critical"
            )
        ];
        for policy_item in policies {
            here +>:Contains(kind="policy"):+> policy_item;
        }
        add_audit(here, "ingest", f"Sentinel incident ingested at risk {event.sentinel_score}/100 with {len(reasons)} findings.");
    }
}

walker fork_walker {
    can fork_futures with IncidentRun entry {
        event = get_event(here);
        if event is None { return; }
        event_node = event as ObservedEvent;
        branches: list[FutureBranch] = [
            FutureBranch(name="ALLOW", title="Allow Original Action", action_variant="allow_original"),
            FutureBranch(name="WARN", title="Warn and Require Review", action_variant="warn_and_review"),
            FutureBranch(name="BLOCK", title="Block the Action", action_variant="block_action"),
            FutureBranch(name="CONTAIN", title="Contain and Log", action_variant="contain_and_log")
        ];
        for branch_item in branches {
            here +>:Contains(kind="branch"):+> branch_item;
            event_node +>:FORKS_TO:+> branch_item;
        }
        add_audit(here, "fork", "Created ALLOW, WARN, BLOCK, and CONTAIN counterfactual futures.");
    }
}

walker policy_walker {
    can evaluate with IncidentRun entry {
        event = get_event(here);
        if event is None { return; }
        event_node = event as ObservedEvent;
        policies = get_policies(here);

        for branch_item in get_branches(here) {
            for policy_item in policies {
                branch_item +>:EVALUATED_AGAINST(result="pass"):+> policy_item;
            }

            if branch_item.name == "ALLOW" {
                branch_item.risk_score = event_node.sentinel_score;
                branch_item.utility_score = 100;
                if event_node.sentinel_score >= 40 {
                    branch_item.valid = False;
                    branch_item.verdict = "REJECTED_REVIEW_REQUIRED";
                    add_violation(here, branch_item, "FG-REVIEW-40", "The original action exceeded the automatic-allow threshold.", "high");
                } else {
                    branch_item.verdict = "ELIGIBLE";
                }
            } elif branch_item.name == "WARN" {
                branch_item.risk_score = max(0, event_node.sentinel_score - 20);
                branch_item.utility_score = 80;
                if event_node.sentinel_score >= 70 {
                    branch_item.valid = False;
                    branch_item.verdict = "REJECTED_CONTAINMENT_REQUIRED";
                    add_violation(here, branch_item, "FG-CONTAIN-70", "A warning alone is insufficient for a high-risk action.", "critical");
                } else {
                    branch_item.verdict = "ELIGIBLE";
                }
            } elif branch_item.name == "BLOCK" {
                branch_item.risk_score = 0;
                branch_item.utility_score = 35;
                if event_node.sentinel_score >= 70 and not event_node.blockable {
                    branch_item.valid = False;
                    branch_item.verdict = "TECHNICALLY_UNAVAILABLE";
                    if event_node.event_type == "usb_scan_result" {
                        add_violation(here, branch_item, "FG-BLOCKABILITY", "The current user-mode USB agent detects and contains findings after the volume mounts; it does not claim kernel-level blocking.", "critical");
                    } else {
                        add_violation(here, branch_item, "FG-BLOCKABILITY", "Manifest V3 cannot reliably block this browser event type after observation.", "critical");
                    }
                } else {
                    branch_item.verdict = "ELIGIBLE";
                }
            } else {
                branch_item.risk_score = 10;
                branch_item.utility_score = 65;
                branch_item.verdict = "ELIGIBLE";
            }
        }
        add_audit(here, "policy", "Evaluated all futures against review, containment, and technical-blockability policies.");
    }
}

walker select_walker {
    can select_future with IncidentRun entry {
        event = get_event(here);
        if event is None { return; }
        event_node = event as ObservedEvent;

        selected_name = "ALLOW";
        status = "ALLOW_WITH_MONITORING";
        confidence = 0.91;
        summary = "The observed behavior remains below Sentinel's review threshold.";

        if event_node.sentinel_score >= 70 {
            if event_node.blockable {
                selected_name = "BLOCK";
                status = "BLOCK_RECOMMENDED";
                confidence = 0.99;
                summary = "High-risk behavior is technically blockable; AEGIS selects the blocked future.";
            } else {
                selected_name = "CONTAIN";
                status = "CONTAINMENT_REQUIRED";
                confidence = 0.98;
                if event_node.event_type == "usb_scan_result" {
                    summary = "The USB finding is high risk. The current user-mode agent relies on Defender remediation, so AEGIS selects containment, logging, and user escalation without claiming kernel-level prevention.";
                } else {
                    summary = "The browser action is high risk but not reliably blockable in Manifest V3, so AEGIS selects containment, logging, and user escalation.";
                }
            }
        } elif event_node.sentinel_score >= 40 {
            selected_name = "WARN";
            status = "WARN_AND_REVIEW";
            confidence = 0.95;
            summary = "The action requires an explicit warning and user review before continuation.";
        }

        selected = find_branch(here, selected_name);
        if selected is None { return; }
        selected_node = selected as FutureBranch;
        selected_node.verdict = "SELECTED";
        decision = Decision(
            selected_branch=selected_name,
            status=status,
            confidence=confidence,
            summary=summary
        );
        here +>:Contains(kind="decision"):+> decision;
        decision +>:SELECTS:+> selected_node;
        for evidence in get_evidence(here) {
            decision +>:SUPPORTED_BY:+> evidence;
        }
        add_audit(here, "decision", f"Selected {selected_name}: {status}.");
    }
}

def violation_dicts(run: IncidentRun, branch_name: str) -> list[dict[str, any]] {
    return [
        {
            "policyId": item.policy_id,
            "reason": item.reason,
            "severity": item.severity
        }
        for item in get_violations(run) if item.branch_name == branch_name
    ];
}

def graph_payload(run: IncidentRun) -> dict[str, any] {
    decision = get_decision(run);
    selected = decision.selected_branch if decision is not None else "";
    nodes: list[dict[str, any]] = [
        {"id": "event", "kind": "event", "label": "Observed security event"}
    ];
    edges: list[dict[str, any]] = [];
    for branch_item in get_branches(run) {
        nodes.append({
            "id": f"branch-{branch_item.name}",
            "kind": "branch",
            "label": branch_item.name,
            "selected": branch_item.name == selected
        });
        edges.append({"from": "event", "to": f"branch-{branch_item.name}", "type": "FORKS_TO"});
    }
    for policy_item in get_policies(run) {
        nodes.append({"id": f"policy-{policy_item.policy_id}", "kind": "policy", "label": policy_item.policy_id});
    }
    nodes.append({"id": "decision", "kind": "decision", "label": selected});
    if selected != "" {
        edges.append({"from": "decision", "to": f"branch-{selected}", "type": "SELECTS"});
    }
    return {"nodes": nodes, "edges": edges};
}

walker report_walker {
    has result_data: dict[str, any] = {};

    can assemble with IncidentRun entry {
        event = get_event(here);
        decision = get_decision(here);
        if event is None or decision is None { return; }
        event_node = event as ObservedEvent;
        decision_node = decision as Decision;

        self.result_data = {
            "engine": "AEGIS_FORKGUARD",
            "version": "0.1.0",
            "runId": here.run_id,
            "sourceIncidentId": here.source_incident_id,
            "simulated": True,
            "sentinel": {
                "eventType": event_node.event_type,
                "score": event_node.sentinel_score,
                "decision": event_node.sentinel_decision,
                "blockable": event_node.blockable
            },
            "decision": {
                "selectedBranch": decision_node.selected_branch,
                "status": decision_node.status,
                "confidence": decision_node.confidence,
                "summary": decision_node.summary
            },
            "branches": [
                {
                    "name": branch_item.name,
                    "title": branch_item.title,
                    "actionVariant": branch_item.action_variant,
                    "riskScore": branch_item.risk_score,
                    "utilityScore": branch_item.utility_score,
                    "valid": branch_item.valid,
                    "verdict": branch_item.verdict,
                    "violations": violation_dicts(here, branch_item.name)
                }
                for branch_item in get_branches(here)
            ],
            "evidence": [
                {
                    "id": evidence.evidence_id,
                    "ruleId": evidence.rule_id,
                    "label": evidence.label,
                    "points": evidence.points,
                    "trustLevel": evidence.trust_level
                }
                for evidence in get_evidence(here)
            ],
            "timeline": [
                {
                    "seq": audit.seq,
                    "stage": audit.stage,
                    "details": audit.details,
                    "timestamp": audit.timestamp
                }
                for audit in get_timeline(here)
            ],
            "graph": graph_payload(here)
        };
    }
}

def run_pipeline(payload: dict[str, any]) -> dict[str, any] {
    source_id = str(payload.get("incidentId", "sentinel-incident"));
    run = IncidentRun(
        run_id=f"FG-{str(uuid4())[:8]}",
        source_incident_id=source_id,
        created_at=now_iso()
    );
    run spawn ingest_walker(payload=payload);
    run spawn fork_walker();
    run spawn policy_walker();
    run spawn select_walker();
    reporter = report_walker();
    run spawn reporter;
    return reporter.result_data;
}

walker:pub evaluate_sentinel_api {
    has payload: dict[str, any] = {};

    can execute with Root entry {
        report run_pipeline(self.payload);
    }
}

with entry:__main__ {
    sample = {
        "incidentId": "demo-incident",
        "eventType": "form_submission",
        "pageOrigin": "https://safe.example",
        "destinationOrigin": "https://unknown.example",
        "score": 95,
        "decision": "blocked",
        "blockable": True,
        "reasons": [
            {"ruleId": "cross-origin-password-form", "label": "Password form targeted another origin", "points": 50},
            {"ruleId": "cross-origin-request", "label": "Request sent to a different origin", "points": 45}
        ]
    };
    result = run_pipeline(sample);
    print(result.get("decision", {}));
}
