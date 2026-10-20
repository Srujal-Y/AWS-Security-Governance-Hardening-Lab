import argparse
import json
import sys
from pathlib import Path

import boto3
import jsonschema
from botocore.exceptions import BotoCoreError

from .findings import SEVERITIES, normalize_event
from .live import verify_live
from .policy import evaluate_request, render_policies
from .reporting import now, write_demo_report, write_json
from .validation import load_scenario
from .workflow import Exercise


def run_exercises(scenario):
    policies = render_policies(scenario["allowed_regions"], scenario["administrator_role_arns"])
    results, responses, errors = [], [], []
    for case in scenario["policy_cases"]:
        observed = evaluate_request(policies, case["request"])
        results.append(
            {
                "id": case["id"],
                "expected": case["expected"],
                **observed,
                "passed": observed["decision"] == case["expected"],
            }
        )
    for case in scenario["finding_cases"]:
        try:
            finding = normalize_event(case["event"])
            exercise = Exercise(finding, case["before"], case["parameters"])
            exercise.triage()
            exercise.approve("demo-independent-reviewer", "Approved fictional training scenario")
            exercise.simulate()
            responses.append({"id": case["id"], "finding": finding, "exercise": exercise.verify()})
        except (ValueError, KeyError, TypeError, IndexError) as error:
            errors.append(
                {
                    "case": case["id"],
                    "code": type(error).__name__,
                    "message": "Unsupported event, invalid state or failed workflow postcondition.",
                }
            )
    responses.sort(key=lambda row: (SEVERITIES.index(row["finding"]["severity"]), row["id"]))
    summary = {
        "policy_total": len(results),
        "policy_passed": sum(r["passed"] for r in results),
        "response_total": len(scenario["finding_cases"]),
        "response_passed": len(responses),
    }
    return {
        "schema_version": "1.0",
        "mode": "synthetic_offline",
        "completed_at": now(),
        "status": "passed" if all(r["passed"] for r in results) and not errors else "failed",
        "summary": summary,
        "accounts": scenario["accounts"],
        "policies": policies,
        "policy_results": results,
        "response_results": responses,
        "errors": errors,
    }


def parser():
    root = argparse.ArgumentParser(description="AWS governance policy and response training lab")
    commands = root.add_subparsers(dest="command", required=True)
    for name in ("demo", "replay", "verify-live"):
        command = commands.add_parser(name)
        command.add_argument("--output", type=Path, default=Path("reports") / name)
        if name != "demo":
            command.add_argument("--input", type=Path, required=True)
        if name == "verify-live":
            command.add_argument("--profile", required=True)
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "verify-live":
            inventory = json.loads(args.input.read_text(encoding="utf-8"))
            report = verify_live(boto3.Session(profile_name=args.profile), inventory)
            report["completed_at"] = now()
            write_json(args.output / "verification.json", report)
        else:
            scenario = load_scenario(args.input if args.command == "replay" else None)
            report = run_exercises(scenario)
            for path in write_demo_report(report, args.output):
                print(path)
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        jsonschema.ValidationError,
        BotoCoreError,
    ) as error:
        print(
            f"Cannot complete command: {type(error).__name__}. Check inputs, profile and output path.",
            file=sys.stderr,
        )
        return 2
    print(f"{report['mode']}: {report['status']}")
    return 0 if report["status"] == "passed" else 2 if report["status"] == "partial" else 1
