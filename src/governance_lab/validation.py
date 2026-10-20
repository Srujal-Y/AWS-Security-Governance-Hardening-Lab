import json
import re
from importlib.resources import files
from pathlib import Path

import jsonschema

REGION = r"[a-z]{2}(?:-[a-z]+)+-\d+"
ROLE = r"arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9_+=,.@/-]+"


def validate_policy_inputs(regions, role_arns):
    for values, pattern in ((regions, REGION), (role_arns, ROLE)):
        if (
            not isinstance(values, list)
            or not values
            or not all(isinstance(value, str) and re.fullmatch(pattern, value) for value in values)
        ):
            raise ValueError("Use explicit regions and exact commercial-partition role ARNs")


def bundled_json(name):
    return json.loads(files("governance_lab").joinpath("data/" + name).read_text(encoding="utf-8"))


def load_scenario(path=None):
    raw = (
        json.loads(Path(path).read_text(encoding="utf-8"))
        if path
        else bundled_json("scenario.json")
    )
    jsonschema.Draft202012Validator(bundled_json("scenario.schema.json")).validate(raw)
    validate_policy_inputs(raw["allowed_regions"], raw["administrator_role_arns"])
    for key in ("policy_cases", "finding_cases"):
        ids = [entry["id"] for entry in raw[key]]
        if len(ids) != len(set(ids)):
            raise ValueError("Case IDs must be unique")
    return raw
