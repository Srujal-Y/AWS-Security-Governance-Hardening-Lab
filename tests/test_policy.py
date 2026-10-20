import copy
import json

import pytest

from governance_lab.policy import evaluate_request, render_policies, validate_policy
from governance_lab.validation import bundled_json

CASES = bundled_json("scenario.json")["policy_cases"]


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_policy_case_matrix(scenario, case):
    policies = render_policies(scenario["allowed_regions"], scenario["administrator_role_arns"])
    observed = evaluate_request(policies, case["request"])
    assert observed["decision"] == case["expected"]
    assert bool(observed["matched_statements"]) == (case["expected"] == "explicit_deny")
    assert observed["decision"] != "allowed"


def test_render_is_deterministic_and_within_scp_limit(scenario):
    first = render_policies(scenario["allowed_regions"], scenario["administrator_role_arns"])
    second = render_policies(
        scenario["allowed_regions"][::-1], scenario["administrator_role_arns"][::-1]
    )
    assert first == second
    assert all(
        len(json.dumps(document, separators=(",", ":"))) <= 5120 for document in first.values()
    )
    assert "${" not in json.dumps(first)


@pytest.mark.parametrize(
    "regions,roles",
    [
        ([], ["arn:aws:iam::444444444444:role/Admin"]),
        (["*"], ["arn:aws:iam::444444444444:role/Admin"]),
        (["eu-west-1"], ["arn:aws:iam::*:role/Admin"]),
        (["eu-west-1"], ["arn:aws:iam::444444444444:role/*"]),
        (["eu-west-1"], []),
    ],
)
def test_unsafe_policy_inputs_rejected(regions, roles):
    with pytest.raises(ValueError):
        render_policies(regions, roles)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda p: p.update(Unknown="ignored"),
        lambda p: p.update(Statement=[]),
        lambda p: p["Statement"][0].update(Effect="Allow"),
        lambda p: p["Statement"][0].update(NotResource="*"),
        lambda p: p["Statement"][0].update(Action="ec2:*"),
        lambda p: p["Statement"][0].update(Resource=[]),
        lambda p: p["Statement"][0].update(
            Condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}}
        ),
        lambda p: p["Statement"][0].update(Condition={"ArnLike": {"unknown": "value"}}),
        lambda p: p["Statement"][0].update(Condition={"ArnLike": {"aws:PrincipalArn": []}}),
    ],
)
def test_unsupported_policy_semantics_fail_closed(scenario, mutation):
    policy = render_policies(scenario["allowed_regions"], scenario["administrator_role_arns"])[
        "region-restriction"
    ]
    mutation(policy)
    with pytest.raises(ValueError):
        validate_policy(policy)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda r: r.pop("account_type"),
        lambda r: r.pop("service_linked_role"),
        lambda r: r.update(action=""),
        lambda r: r["context"].pop("aws:PrincipalArn"),
        lambda r: r["context"].update({"aws:PrincipalArn": None}),
    ],
)
def test_ambiguous_request_context_rejected(scenario, mutation):
    request = copy.deepcopy(scenario["policy_cases"][0]["request"])
    mutation(request)
    with pytest.raises(ValueError):
        evaluate_request(
            render_policies(scenario["allowed_regions"], scenario["administrator_role_arns"]),
            request,
        )
