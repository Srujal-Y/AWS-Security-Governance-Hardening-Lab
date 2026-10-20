from copy import deepcopy

import pytest

from governance_lab.cli import run_exercises
from governance_lab.findings import normalize_event
from governance_lab.workflow import Exercise, WorkflowError


def exercise_for(case):
    return Exercise(normalize_event(case["event"]), case["before"], case["parameters"])


@pytest.mark.parametrize("index", range(4))
def test_response_approval_apply_verify_and_rollback(scenario, index):
    case = scenario["finding_cases"][index]
    original = deepcopy(case["before"])
    exercise = exercise_for(case)
    plan = exercise.triage()
    assert plan["execution"] == "simulation_only"
    assert exercise.current == original
    with pytest.raises(WorkflowError):
        exercise.simulate()
    exercise.approve("second-reviewer", "Fictional approved change")
    exercise.simulate()
    result = exercise.verify()
    assert result["status"] == "verified"
    assert [h["step"] for h in result["history"]] == [
        "new",
        "triaged",
        "approved",
        "simulated",
        "verified",
    ]
    assert case["before"] == original
    assert exercise.rollback()["after"] == original
    assert exercise.status == "rolled_back"


def test_expected_postconditions_are_observed(scenario):
    report = run_exercises(scenario)
    after = {r["id"]: r["exercise"]["after"] for r in report["response_results"]}
    assert after["guardduty-containment"]["security_group_ids"] == ["sg-00000000000000002"]
    assert after["securityhub-public-access"]["public_access_block"] == {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }
    assert after["config-required-tags"]["tags"] == {
        "Owner": "security-engineering",
        "Environment": "lab",
    }
    assert after["cloudtrail-blocked-tamper"]["logging_enabled"] is True
    assert report["summary"] == {
        "policy_total": 27,
        "policy_passed": 27,
        "response_total": 4,
        "response_passed": 4,
    }


def test_same_reviewer_or_empty_rationale_cannot_approve(scenario):
    exercise = exercise_for(scenario["finding_cases"][0])
    exercise.triage()
    for reviewer, reason in [("demo-analyst", "approved"), ("", "approved"), ("reviewer", "")]:
        with pytest.raises(WorkflowError):
            exercise.approve(reviewer, reason)


def test_illegal_transition_order_is_rejected(scenario):
    exercise = exercise_for(scenario["finding_cases"][0])
    for operation in (
        lambda: exercise.approve("reviewer", "reason"),
        exercise.simulate,
        exercise.verify,
        exercise.rollback,
    ):
        with pytest.raises(WorkflowError):
            operation()
    exercise.triage()
    with pytest.raises(WorkflowError):
        exercise.triage()


@pytest.mark.parametrize(
    "field,value",
    [("resource", "unrelated"), ("account_id", "999999999999"), ("region", "us-west-2")],
)
def test_cross_resource_and_account_remediation_rejected(scenario, field, value):
    case = scenario["finding_cases"][0]
    case["before"][field] = value
    with pytest.raises(WorkflowError):
        exercise_for(case).triage()


def test_verification_failure_cannot_be_reported_as_resolved(scenario):
    case = scenario["finding_cases"][3]
    case["before"]["logging_enabled"] = False
    exercise = exercise_for(case)
    exercise.triage()
    exercise.approve("reviewer", "Investigate")
    exercise.simulate()
    with pytest.raises(WorkflowError):
        exercise.verify()
    assert exercise.status == "verification_failed"
    assert run_exercises(scenario)["status"] == "failed"


@pytest.mark.parametrize(
    "index,key,value",
    [
        (0, "quarantine_group_id", "missing"),
        (2, "approved_tags", {"Owner": "", "Environment": "lab"}),
    ],
)
def test_remediation_parameters_require_explicit_values(scenario, index, key, value):
    case = scenario["finding_cases"][index]
    case["parameters"][key] = value
    with pytest.raises(WorkflowError):
        exercise_for(case).triage()


@pytest.mark.parametrize(
    "severity,expected", [(9.5, "critical"), (8, "high"), (4, "medium"), (2, "low")]
)
def test_guardduty_severity_mapping(scenario, severity, expected):
    event = scenario["finding_cases"][0]["event"]
    event["detail"]["severity"] = severity
    assert normalize_event(event)["severity"] == expected


@pytest.mark.parametrize("severity", [-1, 11, True, "8"])
def test_invalid_guardduty_severity(scenario, severity):
    event = scenario["finding_cases"][0]["event"]
    event["detail"]["severity"] = severity
    with pytest.raises(ValueError):
        normalize_event(event)


@pytest.mark.parametrize(
    "index,mutation",
    [
        (0, lambda e: e.update(source="aws.unsupported")),
        (1, lambda e: e["detail"]["findings"].clear()),
        (1, lambda e: e["detail"]["findings"][0].update(GeneratorId="unknown")),
        (1, lambda e: e["detail"]["findings"][0].update(AwsAccountId="999999999999")),
        (1, lambda e: e["detail"]["findings"][0].update(Resources=[])),
        (1, lambda e: e["detail"]["findings"][0].update(RecordState="ARCHIVED")),
        (1, lambda e: e["detail"]["findings"][0]["Severity"].update(Label="UNKNOWN")),
        (2, lambda e: e["detail"].update(configRuleName="unknown")),
        (2, lambda e: e["detail"]["newEvaluationResult"].update(complianceType="COMPLIANT")),
        (3, lambda e: e["detail"].update(eventName="DeleteTrail")),
        (3, lambda e: e["detail"].pop("errorCode")),
    ],
)
def test_unsupported_finding_is_rejected(scenario, index, mutation):
    event = scenario["finding_cases"][index]["event"]
    mutation(event)
    with pytest.raises(ValueError):
        normalize_event(event)


def test_finding_identity_and_copy_isolation(scenario):
    case = scenario["finding_cases"][0]
    assert normalize_event(case["event"])["id"] == normalize_event(deepcopy(case["event"]))["id"]
    exercise = exercise_for(case)
    plan = exercise.triage()
    plan["changes"]["security_group_ids"] = ["attacker"]
    exercise.approve("reviewer", "Training")
    exercise.simulate()
    assert exercise.current["security_group_ids"] == ["sg-00000000000000002"]
