import json
from contextlib import ExitStack
from unittest.mock import Mock

import boto3
import pytest
from botocore.stub import Stubber

from governance_lab.cli import main
from governance_lab.live import verify_live

ACCOUNT = "444444444444"
REGION = "eu-west-1"
DETECTOR = "0" * 32


@pytest.fixture
def inventory():
    return {
        "account_id": ACCOUNT,
        "region": REGION,
        "trail_name": "govlab-trail",
        "guardduty_id": DETECTOR,
        "config_recorder": "govlab-recorder",
        "config_delivery": "govlab-delivery",
        "config_rule_names": ["govlab-required-tags"],
    }


@pytest.fixture
def aws():
    real = boto3.Session(aws_access_key_id="testing", aws_secret_access_key="testing")
    clients = {
        name: real.client(name, region_name=REGION)
        for name in ("sts", "cloudtrail", "guardduty", "securityhub", "config")
    }
    session = Mock()
    session.client.side_effect = lambda name, **kwargs: clients[name]
    return session, clients


def add_identity(stub, account=ACCOUNT):
    stub.add_response(
        "get_caller_identity",
        {
            "Account": account,
            "Arn": f"arn:aws:iam::{account}:role/Reader",
            "UserId": "AIDA00000000000000000",
        },
        {},
    )


def add_baseline(stubs, denied_detector=False, logging=True):
    stubs["cloudtrail"].add_response(
        "get_trail_status", {"IsLogging": logging}, {"Name": "govlab-trail"}
    )
    if denied_detector:
        stubs["guardduty"].add_client_error(
            "get_detector", "AccessDeniedException", expected_params={"DetectorId": DETECTOR}
        )
    else:
        stubs["guardduty"].add_response(
            "get_detector",
            {
                "Status": "ENABLED",
                "ServiceRole": f"arn:aws:iam::{ACCOUNT}:role/GuardDuty",
                "Features": [{"Name": "S3_DATA_EVENTS", "Status": "ENABLED"}],
            },
            {"DetectorId": DETECTOR},
        )
    stubs["securityhub"].add_response(
        "describe_hub", {"HubArn": f"arn:aws:securityhub:{REGION}:{ACCOUNT}:hub/default"}, {}
    )
    stubs["securityhub"].add_response(
        "get_enabled_standards", {"StandardsSubscriptions": [], "NextToken": "next"}, {}
    )
    stubs["securityhub"].add_response(
        "get_enabled_standards",
        {
            "StandardsSubscriptions": [
                {
                    "StandardsArn": f"arn:aws:securityhub:{REGION}::standards/aws-foundational-security-best-practices/v/1.0.0",
                    "StandardsSubscriptionArn": f"arn:aws:securityhub:{REGION}:{ACCOUNT}:subscription/aws-foundational-security-best-practices/v/1.0.0",
                    "StandardsStatus": "READY",
                    "StandardsInput": {},
                }
            ]
        },
        {"NextToken": "next"},
    )
    stubs["config"].add_response(
        "describe_configuration_recorder_status",
        {
            "ConfigurationRecordersStatus": [{"name": "govlab-recorder", "recording": True}],
        },
        {"ConfigurationRecorderNames": ["govlab-recorder"]},
    )
    stubs["config"].add_response(
        "describe_delivery_channel_status",
        {
            "DeliveryChannelsStatus": [{"name": "govlab-delivery"}],
        },
        {"DeliveryChannelNames": ["govlab-delivery"]},
    )
    stubs["config"].add_response(
        "describe_config_rules",
        {
            "ConfigRules": [
                {
                    "ConfigRuleName": "govlab-required-tags",
                    "ConfigRuleState": "ACTIVE",
                    "Source": {"Owner": "AWS", "SourceIdentifier": "REQUIRED_TAGS"},
                }
            ]
        },
        {"ConfigRuleNames": ["govlab-required-tags"]},
    )


@pytest.mark.parametrize(
    "denied,logging,status",
    [(False, True, "passed"), (True, True, "partial"), (False, False, "failed")],
)
def test_live_read_only_checks_and_failure_isolation(aws, inventory, denied, logging, status):
    session, clients = aws
    with ExitStack() as stack:
        stubs = {name: stack.enter_context(Stubber(client)) for name, client in clients.items()}
        add_identity(stubs["sts"])
        add_baseline(stubs, denied_detector=denied, logging=logging)
        report = verify_live(session, inventory)
        for stub in stubs.values():
            stub.assert_no_pending_responses()
    assert report["status"] == status
    assert report["mode"] == "live_read_only"
    if denied:
        assert report["errors"] == [{"service": "guardduty", "code": "AccessDeniedException"}]


def test_identity_mismatch_stops_before_service_calls(aws, inventory):
    session, clients = aws
    with Stubber(clients["sts"]) as stub:
        add_identity(stub, "999999999999")
        report = verify_live(session, inventory)
    assert report["status"] == "partial"
    assert report["errors"][0]["code"] == "AccountMismatch"
    assert session.client.call_count == 1


def test_identity_denial_never_passes(aws, inventory):
    session, clients = aws
    with Stubber(clients["sts"]) as stub:
        stub.add_client_error("get_caller_identity", "ExpiredToken", expected_params={})
        assert verify_live(session, inventory)["status"] == "partial"


@pytest.mark.parametrize(
    "field,value",
    [
        ("account_id", "bad"),
        ("region", "all-regions"),
        ("config_recorder", ""),
        ("guardduty_id", ""),
    ],
)
def test_invalid_live_inventory_rejected_before_aws(aws, inventory, field, value):
    session, _ = aws
    inventory[field] = value
    with pytest.raises(ValueError):
        verify_live(session, inventory)
    session.client.assert_not_called()


def test_live_cli_writes_verified_read_only_evidence(aws, inventory, monkeypatch, tmp_path):
    session, clients = aws
    monkeypatch.setattr("governance_lab.cli.boto3.Session", lambda **kwargs: session)
    source = tmp_path / "input.json"
    source.write_text(json.dumps(inventory), encoding="utf-8")
    with ExitStack() as stack:
        stubs = {name: stack.enter_context(Stubber(client)) for name, client in clients.items()}
        add_identity(stubs["sts"])
        add_baseline(stubs)
        assert (
            main(
                [
                    "verify-live",
                    "--profile",
                    "fictional",
                    "--input",
                    str(source),
                    "--output",
                    str(tmp_path / "out"),
                ]
            )
            == 0
        )
    report = json.loads((tmp_path / "out/verification.json").read_text())
    assert report["mode"] == "live_read_only"


def test_secondary_region_does_not_claim_trail_verified(aws, inventory):
    session, clients = aws
    inventory["trail_name"] = None
    with ExitStack() as stack:
        stubs = {name: stack.enter_context(Stubber(client)) for name, client in clients.items()}
        add_identity(stubs["sts"])
        add_baseline(stubs)
        report = verify_live(session, inventory)
    assert report["status"] == "partial"
    assert report["checks"][0]["passed"] is None
