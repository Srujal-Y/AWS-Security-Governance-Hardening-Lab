"""Validate locally without deploying AWS resources."""

import json
import platform
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STACKS = ("organization", "log-archive", "account-baseline")


def run(name, command):
    print(f"\n{name}", flush=True)
    result = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    (ROOT / "reports" / f"{name}.log").write_text(result.stdout, encoding="utf-8")
    print("\n".join(result.stdout.splitlines()[-12:]), flush=True)
    if result.returncode:
        raise RuntimeError(f"{name} failed; inspect reports/{name}.log")
    return result.stdout


def main():
    terraform = shutil.which("terraform")
    if terraform is None:
        print("Terraform is required for complete local validation.", file=sys.stderr)
        return 2
    (ROOT / "reports").mkdir(exist_ok=True)
    try:
        for name, arguments in (
            ("dependencies", ["pip", "check"]),
            ("lint", ["ruff", "check", "."]),
            ("format", ["ruff", "format", "--check", "."]),
            (
                "python-tests",
                [
                    "pytest",
                    "--cov=governance_lab",
                    "--cov-branch",
                    "--cov-report=term-missing",
                    "--cov-report=xml",
                    "--cov-fail-under=90",
                    "--junitxml=reports/junit.xml",
                ],
            ),
        ):
            run(name, [sys.executable, "-m", *arguments])
        run("terraform-format", [terraform, "fmt", "-check", "-recursive", "infra"])
        mock_runs = 0
        for stack in STACKS:
            run(f"{stack}-validate", [terraform, f"-chdir=infra/{stack}", "validate", "-no-color"])
            text = run(f"{stack}-tests", [terraform, f"-chdir=infra/{stack}", "test", "-no-color"])
            match = re.search(r"Success! (\d+) passed, 0 failed", text)
            if not match:
                raise RuntimeError("Terraform test results could not be verified")
            mock_runs += int(match.group(1))
        run("package-build", [sys.executable, "-m", "build", "--no-isolation"])
        run(
            "offline-demo",
            [sys.executable, "-m", "governance_lab", "demo", "--output", "reports/demo"],
        )
        junit = ET.parse(ROOT / "reports/junit.xml").getroot().find("testsuite").attrib
        coverage = ET.parse(ROOT / "coverage.xml").getroot().attrib
        total = int(coverage["lines-valid"]) + int(coverage["branches-valid"])
        covered = int(coverage["lines-covered"]) + int(coverage["branches-covered"])
        result = {
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "platform": platform.system(),
            "python": platform.python_version(),
            "scope": "Offline Python exercises and Terraform mock-provider plans",
            "tests": {k: int(junit[k]) for k in ("tests", "failures", "errors", "skipped")},
            "combined_coverage_percent": round(100 * covered / total, 2),
            "terraform_mock_runs_passed": mock_runs,
            "terraform_stacks_validated": list(STACKS),
            "live_aws_deployment": "not_performed",
            "hosted_ci": "not_run",
        }
        (ROOT / "reports/validation.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8"
        )
        print("\nLocal validation passed. No AWS resources were deployed or changed.")
        return 0
    except (RuntimeError, OSError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
