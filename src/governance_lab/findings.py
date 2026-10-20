"""Normalize the four explicitly supported synthetic event shapes."""

import hashlib

SEVERITIES = ("critical", "high", "medium", "low", "informational")


def normalize_event(event):
    source, detail = event["source"], event["detail"]
    if source == "aws.guardduty":
        score = detail["severity"]
        if isinstance(score, bool) or not isinstance(score, (int, float)) or not 0 <= score <= 10:
            raise ValueError("Invalid GuardDuty severity")
        severity = (
            "critical"
            if score >= 9
            else "high"
            if score >= 7
            else "medium"
            if score >= 4
            else "low"
        )
        resource = detail["resource"]["instanceDetails"]["instanceId"]
        issue = detail["type"]
        playbook = "quarantine-ec2"
        risk = "Suspected instance activity requires investigation and approved containment."
        remediation = "Review the sample finding, preserve evidence, and simulate assigning the approved quarantine security group."
    elif source == "aws.securityhub":
        records = detail["findings"]
        if len(records) != 1:
            raise ValueError("This lab accepts one Security Hub finding per exercise")
        finding = records[0]
        if finding["AwsAccountId"] != event["account"] or len(finding["Resources"]) != 1:
            raise ValueError(
                "Finding account must match the envelope and name exactly one resource"
            )
        if finding["GeneratorId"] != "security-control/S3.8":
            raise ValueError("Only the S3.8 playbook is implemented")
        if finding.get("RecordState") != "ACTIVE" or finding["Compliance"]["Status"] != "FAILED":
            raise ValueError("Exercise requires an active failed control")
        severity = finding["Severity"]["Label"].lower()
        if severity not in SEVERITIES:
            raise ValueError("Unknown severity")
        resource = finding["Resources"][0]["Id"]
        issue = finding["Title"]
        playbook = "block-public-s3"
        risk = "Unintended public bucket configuration can expose sensitive data."
        remediation = "Confirm the bucket's purpose and simulate all four bucket Block Public Access settings."
    elif source == "aws.config":
        if detail["configRuleName"] != "govlab-required-tags":
            raise ValueError("Only the required-tags playbook is implemented")
        if detail["newEvaluationResult"]["complianceType"] != "NON_COMPLIANT":
            raise ValueError("Exercise requires a noncompliant evaluation")
        resource = detail["resourceId"]
        severity = "medium"
        issue = "Required ownership and environment tags are missing"
        playbook = "apply-required-tags"
        risk = "Missing ownership metadata delays accountability and incident response."
        remediation = (
            "Obtain approved Owner and Environment values and simulate adding the missing tags."
        )
    elif source == "aws.cloudtrail":
        if (
            detail["eventSource"] != "cloudtrail.amazonaws.com"
            or detail["eventName"] != "StopLogging"
        ):
            raise ValueError("Only the StopLogging investigation is implemented")
        if detail.get("errorCode") not in ("AccessDenied", "AccessDeniedException"):
            raise ValueError("This exercise expects a blocked StopLogging attempt")
        resource = detail["requestParameters"]["name"]
        severity = "high"
        issue = "An attempt to stop audit logging was denied"
        playbook = "verify-blocked-tamper"
        risk = "A blocked attempt can still indicate misuse of credentials or an incorrect change process."
        remediation = "Verify continued logging, review the actor and denial reason, and preserve the event. A denial alone does not establish which policy caused it."
    else:
        raise ValueError("Unsupported event source")
    identity = f"{source}|{event['id']}|{event['account']}|{event['region']}|{resource}"
    return {
        "id": hashlib.sha256(identity.encode()).hexdigest()[:20],
        "source": source,
        "account_id": event["account"],
        "region": event["region"],
        "resource": resource,
        "issue": issue,
        "severity": severity,
        "risk": risk,
        "remediation": remediation,
        "playbook": playbook,
        "evidence": detail,
        "synthetic": True,
    }
