import json
from pathlib import Path

import pytest

from governance_lab.cli import main, run_exercises
from governance_lab.reporting import write_demo_report


def test_demo_never_initializes_aws(monkeypatch, tmp_path):
    def forbidden(**kwargs):
        raise AssertionError("Offline demo attempted AWS access")

    monkeypatch.setattr("governance_lab.cli.boto3.Session", forbidden)
    assert main(["demo", "--output", str(tmp_path)]) == 0
    report = json.loads((tmp_path / "report.json").read_text())
    assert report["mode"] == "synthetic_offline"
    assert report["summary"]["response_passed"] == 4
    assert "SYNTHETIC OFFLINE" in (tmp_path / "report.html").read_text()


def test_replay_failing_expected_result_returns_one(scenario, tmp_path):
    scenario["policy_cases"][0]["expected"] = "explicit_deny"
    path = tmp_path / "scenario.json"
    path.write_text(json.dumps(scenario), encoding="utf-8")
    assert main(["replay", "--input", str(path), "--output", str(tmp_path / "out")]) == 1


@pytest.mark.parametrize(
    "mutation",
    [
        lambda s: s.update(synthetic=False),
        lambda s: s["policy_cases"].append(s["policy_cases"][0]),
        lambda s: s.update(allowed_regions=[]),
        lambda s: s["finding_cases"][0]["event"].update(account="not-an-account"),
    ],
)
def test_invalid_replay_returns_two(scenario, tmp_path, mutation):
    mutation(scenario)
    path = tmp_path / "scenario.json"
    path.write_text(json.dumps(scenario))
    assert main(["replay", "--input", str(path), "--output", str(tmp_path / "out")]) == 2


def test_report_escapes_untrusted_html_and_replaces_files(scenario, tmp_path):
    report = run_exercises(scenario)
    report["response_results"][0]["finding"]["resource"] = "<script>alert(1)</script>"
    for _ in range(2):
        paths = write_demo_report(report, tmp_path)
    assert len(paths) == 3
    text = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "<script>" not in text
    assert "&lt;script&gt;" in text
    assert "default-src 'none'" in text
    assert not list(tmp_path.glob("*.tmp"))


def test_output_failure_returns_two(tmp_path):
    target = tmp_path / "occupied"
    target.write_text("file")
    assert main(["demo", "--output", str(target)]) == 2


def test_missing_replay_file_returns_two(tmp_path):
    assert main(["replay", "--input", str(tmp_path / "missing")]) == 2


def test_packaged_policy_templates_are_terraform_source_of_truth():
    root = Path(__file__).resolve().parents[1]
    text = (root / "infra/organization/main.tf").read_text()
    assert "../../src/governance_lab/policies/" in text
