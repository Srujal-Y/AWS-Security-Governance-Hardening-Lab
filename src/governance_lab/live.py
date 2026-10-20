"""Read-only enablement checks; does not create findings or remediate resources."""

import re

from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

CONFIG = Config(
    retries={"mode": "standard", "total_max_attempts": 4},
    connect_timeout=5,
    read_timeout=15,
)


def verify_live(session, inventory):
    if not re.fullmatch(r"[0-9]{12}", inventory["account_id"]):
        raise ValueError("An explicit account ID is required")
    if not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d+", inventory["region"]):
        raise ValueError("An explicit region is required")
    required = ("guardduty_id", "config_recorder", "config_delivery", "config_rule_names")
    if any(not inventory.get(key) for key in required) or "trail_name" not in inventory:
        raise ValueError("Use the complete service_inventory Terraform output")
    report = {
        "mode": "live_read_only",
        "account_id": inventory["account_id"],
        "region": inventory["region"],
        "checks": [],
        "errors": [],
        "scope": "Service enablement and selected configuration only; log delivery, actual detections and SCP enforcement require separate evidence.",
    }

    def client(service):
        return session.client(service, region_name=inventory["region"], config=CONFIG)

    def record(name, callback):
        try:
            passed, evidence = callback()
            report["checks"].append({"service": name, "passed": passed, "evidence": evidence})
        except (BotoCoreError, ClientError) as error:
            code = (
                error.response["Error"]["Code"]
                if isinstance(error, ClientError)
                else type(error).__name__
            )
            report["errors"].append({"service": name, "code": code})

    try:
        identity = client("sts").get_caller_identity()
    except (BotoCoreError, ClientError) as error:
        report["errors"].append({"service": "identity", "code": type(error).__name__})
        report["status"] = "partial"
        return report
    if identity["Account"] != inventory["account_id"]:
        report["errors"].append({"service": "identity", "code": "AccountMismatch"})
        report["status"] = "partial"
        return report

    def trail():
        response = client("cloudtrail").get_trail_status(Name=inventory["trail_name"])
        return response.get("IsLogging") is True and not response.get("LatestDeliveryError"), {
            "is_logging": response.get("IsLogging"),
            "latest_delivery_time": str(response.get("LatestDeliveryTime", "not_observed")),
            "delivery_error_present": bool(response.get("LatestDeliveryError")),
        }

    def guardduty():
        response = client("guardduty").get_detector(DetectorId=inventory["guardduty_id"])
        s3_enabled = any(
            f.get("Name") == "S3_DATA_EVENTS" and f.get("Status") == "ENABLED"
            for f in response.get("Features", [])
        )
        return response["Status"] == "ENABLED" and s3_enabled, {
            "status": response["Status"],
            "s3_protection_enabled": s3_enabled,
        }

    def securityhub():
        hub = client("securityhub")
        hub.describe_hub()
        standards = []
        token = None
        while True:
            response = hub.get_enabled_standards(**({"NextToken": token} if token else {}))
            standards.extend(response.get("StandardsSubscriptions", []))
            token = response.get("NextToken")
            if not token:
                break
        expected = f"arn:aws:securityhub:{inventory['region']}::standards/aws-foundational-security-best-practices/v/1.0.0"
        ready = any(
            s["StandardsArn"] == expected and s["StandardsStatus"] == "READY" for s in standards
        )
        return ready, {"hub_enabled": True, "foundational_standard_ready": ready}

    def config():
        service = client("config")
        recorders = service.describe_configuration_recorder_status(
            ConfigurationRecorderNames=[inventory["config_recorder"]]
        )["ConfigurationRecordersStatus"]
        deliveries = service.describe_delivery_channel_status(
            DeliveryChannelNames=[inventory["config_delivery"]]
        )["DeliveryChannelsStatus"]
        rules = service.describe_config_rules(ConfigRuleNames=inventory["config_rule_names"])[
            "ConfigRules"
        ]
        recording = any(
            r["name"] == inventory["config_recorder"] and r.get("recording") is True
            for r in recorders
        )
        channel = any(d["name"] == inventory["config_delivery"] for d in deliveries)
        active_rules = {r["ConfigRuleName"] for r in rules if r["ConfigRuleState"] == "ACTIVE"}
        rules_present = set(inventory["config_rule_names"]) <= active_rules
        delivery_failed = any(
            d.get(key, {}).get("lastStatus") == "FAILURE"
            for d in deliveries
            for key in ("configHistoryDeliveryInfo", "configSnapshotDeliveryInfo")
        )
        return recording and channel and rules_present and not delivery_failed, {
            "recording": recording,
            "delivery_channel_present": channel,
            "all_requested_rules_active": rules_present,
            "delivery_failure_reported": delivery_failed,
        }

    if inventory["trail_name"]:
        record("cloudtrail", trail)
    else:
        report["checks"].append(
            {
                "service": "cloudtrail",
                "passed": None,
                "evidence": {"scope": "Primary-region trail must be checked separately"},
            }
        )
    for name, callback in (
        ("guardduty", guardduty),
        ("securityhub", securityhub),
        ("config", config),
    ):
        record(name, callback)
    report["status"] = (
        "partial"
        if report["errors"] or any(c["passed"] is None for c in report["checks"])
        else ("passed" if all(c["passed"] for c in report["checks"]) else "failed")
    )
    return report
