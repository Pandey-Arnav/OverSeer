import from main { run_pipeline }

def payload(score: int, blockable: bool) -> dict[str, any] {
    return {
        "incidentId": f"test-{score}-{blockable}",
        "eventType": "fetch_request",
        "pageOrigin": "https://page.example",
        "destinationOrigin": "https://destination.example",
        "score": score,
        "decision": "allow",
        "blockable": blockable,
        "reasons": []
    };
}

test "low-risk incidents select allow" {
    result = run_pipeline(payload(20, True));
    decision = result.get("decision", {}) as dict[str, any];
    assert decision.get("selectedBranch") == "ALLOW";
}

test "medium-risk incidents select warn" {
    result = run_pipeline(payload(55, True));
    decision = result.get("decision", {}) as dict[str, any];
    assert decision.get("selectedBranch") == "WARN";
}

test "high-risk blockable incidents select block" {
    result = run_pipeline(payload(90, True));
    decision = result.get("decision", {}) as dict[str, any];
    assert decision.get("selectedBranch") == "BLOCK";
}

test "high-risk non-blockable incidents select containment" {
    result = run_pipeline(payload(90, False));
    decision = result.get("decision", {}) as dict[str, any];
    assert decision.get("selectedBranch") == "CONTAIN";
}
