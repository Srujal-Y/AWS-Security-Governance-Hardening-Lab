import html
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def now():
    return datetime.now(timezone.utc).isoformat()


def write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    write_atomic(path, json.dumps(data, indent=2, ensure_ascii=True) + "\n")


def write_atomic(path, text):
    handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=".lab-", suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_demo_report(report, output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "report.json", report)

    # Escape prose; JSON evidence is displayed only in indented code blocks.
    def safe(value):
        return html.escape(str(value)).translate({ord(c): f"&#{ord(c)};" for c in "\\`*_[]|"})

    lines = [
        "# AWS Security & Governance Hardening Lab",
        "",
        "**SYNTHETIC OFFLINE EXERCISE. No AWS resources were deployed or changed.**",
        "",
        f"Status: {report['status']} | Completed: {report['completed_at']}",
        "",
        f"Policy cases: {report['summary']['policy_passed']}/{report['summary']['policy_total']} passed.",
        f"Response exercises: {report['summary']['response_passed']}/{report['summary']['response_total']} verified in memory.",
        "",
        "## Policy outcomes",
        "",
        "| Case | Expected | Observed | Pass |",
        "| --- | --- | --- | --- |",
    ]
    for result in report["policy_results"]:
        lines.append(
            f"| {safe(result['id'])} | {safe(result['expected'])} | {safe(result['decision'])} | {result['passed']} |"
        )
    lines += ["", "## Findings and simulated response", ""]
    articles = []
    for case in report["response_results"]:
        finding = case["finding"]
        lines += [
            f"### {finding['severity'].upper()} - {safe(finding['issue'])}",
            "",
            f"- Resource: {safe(finding['resource'])}",
            f"- Risk: {safe(finding['risk'])}",
            f"- Remediation: {safe(finding['remediation'])}",
            f"- Workflow: {safe(case['exercise']['status'])} (simulation only)",
            "",
            "Evidence and before/after state:",
            "",
            *["    " + line for line in json.dumps(case, indent=2).splitlines()],
            "",
        ]
        articles.append(
            f'<article class="{finding["severity"]}"><small>{finding["severity"].upper()}'
            f" / {html.escape(finding['source'])}</small><h3>{html.escape(finding['issue'])}</h3>"
            f"<p><strong>Resource:</strong> <code>{html.escape(finding['resource'])}</code></p>"
            f"<p><strong>Risk:</strong> {html.escape(finding['risk'])}</p>"
            f"<p><strong>Response:</strong> {html.escape(finding['remediation'])}</p>"
            f"<p><strong>Workflow:</strong> {html.escape(case['exercise']['status'])} (simulation only)</p>"
            f"<details><summary>Evidence, approvals and before/after state</summary>"
            f"<pre>{html.escape(json.dumps(case, indent=2))}</pre></details></article>"
        )
    lines += [
        "## Errors",
        "",
        *([safe(e) for e in report["errors"]] or ["None."]),
        "",
        "## Interpretation",
        "",
        "SCP results cover only the supplied deny policies and context. Not denied does not mean IAM permission is granted. Fictional workflow approvals are not operational authorisations.",
        "",
    ]
    write_atomic(output / "report.md", "\n".join(lines))
    policy_rows = "".join(
        f"<tr><td>{html.escape(r['id'])}</td><td>{html.escape(r['decision'])}</td><td>{r['passed']}</td></tr>"
        for r in report["policy_results"]
    )
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>AWS Security &amp; Governance Hardening Lab</title>
<style>
body{{font:16px system-ui;max-width:1100px;margin:40px auto;padding:24px;background:#f3f6fa;color:#21324b}}
h1{{font-size:38px}}p,li{{line-height:1.6}}.banner{{background:#fff0ce;padding:20px;border-left:5px solid #b77c00}}
.metrics{{display:flex;gap:16px;flex-wrap:wrap;margin:24px 0}}.metric,article{{background:white;padding:24px;border-radius:10px}}
.metric{{flex:1}}.metric b{{font-size:30px;display:block}}article{{margin:18px 0;border-left:5px solid #c88b1e}}
.high{{border-color:#c34f25}}.critical{{border-color:#b32243}}table{{width:100%;background:white;border-collapse:collapse}}
td,th{{text-align:left;padding:10px;border-bottom:1px solid #ddd}}code,pre{{white-space:pre-wrap;overflow-wrap:anywhere}}
pre{{font-size:12px;background:#eef2f7;padding:15px}}summary{{cursor:pointer}}@media print{{body{{margin:0}}article{{break-inside:avoid}}}}
</style></head><body><small>FIVE-ACCOUNT GOVERNANCE MODEL</small><h1>AWS Security &amp; Governance Hardening Lab</h1>
<p class="banner"><strong>SYNTHETIC OFFLINE EXERCISE</strong><br>No AWS resources were deployed or changed. Findings, approvals and remediation outcomes are fictional.</p>
<p>Status: {html.escape(report["status"])} | Completed: {html.escape(report["completed_at"])}</p>
<div class="metrics"><div class="metric"><b>{report["summary"]["policy_passed"]}/{report["summary"]["policy_total"]}</b>Policy cases passed</div>
<div class="metric"><b>{report["summary"]["response_passed"]}/{report["summary"]["response_total"]}</b>Response exercises verified</div>
<div class="metric"><b>4</b>Service event types supported</div></div>
<h2>Policy evaluation</h2><p>Not denied by these SCPs does not mean access is granted. Other policies and organisation inheritance remain outside this evaluator.</p>
<table><tr><th>Case</th><th>Decision</th><th>Pass</th></tr>{policy_rows}</table>
<h2>Findings and simulated response</h2>{"".join(articles)}
<h2>Exercise errors</h2><pre>{html.escape(json.dumps(report["errors"], indent=2))}</pre>
<footer>Local review artifact. Live AWS deployment and operational validation require separately authorised access.</footer></body></html>"""
    write_atomic(output / "report.html", document)
    return [str(output / name) for name in ("report.json", "report.md", "report.html")]
