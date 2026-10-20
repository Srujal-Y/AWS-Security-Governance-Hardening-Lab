"""Small, strict deny evaluator for this lab's SCP vocabulary, not an IAM simulator."""

import fnmatch
import json
from importlib.resources import files

OPERATORS = {"StringNotEquals", "ArnNotEquals", "ArnLike"}
CONTEXT_KEYS = {"aws:RequestedRegion", "aws:PrincipalArn"}


def values(value):
    return value if isinstance(value, list) else [value]


def render_policies(allowed_regions, administrator_role_arns):
    from .validation import validate_policy_inputs

    validate_policy_inputs(allowed_regions, administrator_role_arns)
    substitutions = {
        "allowed_regions": sorted(set(allowed_regions)),
        "administrator_role_arns": sorted(set(administrator_role_arns)),
    }
    rendered = {}
    for name in ("region-restriction", "permissions-guardrails"):
        text = files("governance_lab").joinpath(f"policies/{name}.json.tftpl").read_text()
        for key, value in substitutions.items():
            text = text.replace("${" + key + "}", json.dumps(value))
        document = json.loads(text)
        if len(json.dumps(document, separators=(",", ":"))) > 5120:
            raise ValueError("Rendered SCP exceeds the size limit")
        validate_policy(document)
        rendered[name] = document
    return rendered


def validate_policy(document):
    if set(document) != {"Version", "Statement"} or document["Version"] != "2012-10-17":
        raise ValueError("Unsupported policy document")
    if not isinstance(document["Statement"], list) or not document["Statement"]:
        raise ValueError("Expected a nonempty statement list")
    for statement in document["Statement"]:
        if set(statement) - {"Sid", "Effect", "Action", "NotAction", "Resource", "Condition"}:
            raise ValueError("Unsupported statement field")
        if statement.get("Effect") != "Deny" or not statement.get("Sid"):
            raise ValueError("Only named Deny statements are supported")
        if ("Action" in statement) == ("NotAction" in statement):
            raise ValueError("Exactly one action selector is required")
        for key in ("Resource", "Action" if "Action" in statement else "NotAction"):
            if not values(statement.get(key)) or not all(
                isinstance(item, str) and item for item in values(statement.get(key))
            ):
                raise ValueError("Expected nonempty action/resource strings")
        for operator, entries in statement.get("Condition", {}).items():
            if operator not in OPERATORS or not entries or set(entries) - CONTEXT_KEYS:
                raise ValueError("Unsupported condition")
            for expected in entries.values():
                if not values(expected) or not all(
                    isinstance(item, str) and item for item in values(expected)
                ):
                    raise ValueError("Invalid condition values")


def evaluate_request(policies, request):
    """Returns not-denied, never 'allowed': other policy layers are out of scope."""
    for document in policies.values():
        validate_policy(document)
    if request.get("account_type") not in ("management", "member"):
        raise ValueError("Explicit account type is required")
    if not isinstance(request.get("service_linked_role"), bool):
        raise ValueError("Explicit service-linked role context is required")
    for key in ("action", "resource"):
        if not isinstance(request.get(key), str) or not request[key]:
            raise ValueError("Action and resource must be nonempty strings")
    if set(request.get("context", {})) != CONTEXT_KEYS:
        raise ValueError("Both principal ARN and requested region context are required")
    if not all(isinstance(value, str) and value for value in request["context"].values()):
        raise ValueError("Context must contain nonempty strings")
    if request["account_type"] == "management" or request["service_linked_role"]:
        return {"decision": "outside_scp_scope", "matched_statements": []}
    matches = []
    for name, document in policies.items():
        for statement in document["Statement"]:
            selectors = values(statement.get("Action", statement.get("NotAction")))
            action_match = any(
                fnmatch.fnmatchcase(request["action"].lower(), selector.lower())
                for selector in selectors
            )
            if "NotAction" in statement:
                action_match = not action_match
            if not action_match or not any(
                fnmatch.fnmatchcase(request["resource"], pattern)
                for pattern in values(statement["Resource"])
            ):
                continue
            conditions_match = True
            for operator, entries in statement.get("Condition", {}).items():
                for key, expected in entries.items():
                    actual = request["context"][key]
                    if operator == "ArnLike":
                        matched = any(fnmatch.fnmatchcase(actual, p) for p in values(expected))
                    else:
                        matched = actual not in values(expected)
                    conditions_match = conditions_match and matched
            if conditions_match:
                matches.append(f"{name}/{statement['Sid']}")
    return {
        "decision": "explicit_deny" if matches else "not_denied_by_lab_scps",
        "matched_statements": sorted(matches),
    }
