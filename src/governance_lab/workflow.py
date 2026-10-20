"""In-memory training workflow. No AWS client or remote execution is used."""

from copy import deepcopy


class WorkflowError(ValueError):
    pass


class Exercise:
    def __init__(self, finding, before, parameters, requester="demo-analyst"):
        self.finding = deepcopy(finding)
        self.before = deepcopy(before)
        self.current = deepcopy(before)
        self.parameters = deepcopy(parameters)
        self.requester = requester
        self.status = "new"
        self.history = [{"step": "new", "actor": requester}]
        self.plan = None

    def record(self, status, actor):
        self.status = status
        self.history.append({"step": status, "actor": actor})

    def triage(self):
        if self.status != "new":
            raise WorkflowError("Only a new finding can be triaged")
        if self.current["resource"] != self.finding["resource"]:
            raise WorkflowError("State belongs to a different resource")
        if self.current["account_id"] != self.finding["account_id"]:
            raise WorkflowError("State belongs to a different account")
        if self.current["region"] != self.finding["region"]:
            raise WorkflowError("State belongs to a different region")
        playbook = self.finding["playbook"]
        if playbook == "quarantine-ec2":
            group = self.parameters["quarantine_group_id"]
            if (
                not isinstance(group, str)
                or not group.startswith("sg-")
                or not self.current["security_group_ids"]
            ):
                raise WorkflowError("An explicit quarantine group and original groups are required")
            changes = {"security_group_ids": [group]}
        elif playbook == "block-public-s3":
            changes = {
                "public_access_block": dict.fromkeys(
                    (
                        "BlockPublicAcls",
                        "IgnorePublicAcls",
                        "BlockPublicPolicy",
                        "RestrictPublicBuckets",
                    ),
                    True,
                )
            }
        elif playbook == "apply-required-tags":
            tags = self.parameters["approved_tags"]
            if not all(
                isinstance(tags.get(key), str) and tags[key].strip()
                for key in ("Owner", "Environment")
            ):
                raise WorkflowError("Approved tag values are required")
            changes = {"tags": {**self.current["tags"], **tags}}
        elif playbook == "verify-blocked-tamper":
            changes = {}
        else:
            raise WorkflowError("Unsupported playbook")
        self.plan = {
            "playbook": playbook,
            "resource": self.finding["resource"],
            "changes": changes,
            "execution": "simulation_only",
        }
        self.record("triaged", self.requester)
        return deepcopy(self.plan)

    def approve(self, reviewer, reason):
        if self.status != "triaged":
            raise WorkflowError("Triage must precede approval")
        if not isinstance(reviewer, str) or not reviewer.strip() or reviewer == self.requester:
            raise WorkflowError("A different named reviewer is required")
        if not isinstance(reason, str) or not reason.strip():
            raise WorkflowError("Approval rationale is required")
        self.record("approved", reviewer)
        self.history[-1]["reason"] = reason
        self.history[-1]["approval_mode"] = "fictional_training"

    def simulate(self):
        if self.status != "approved":
            raise WorkflowError("An approved plan is required")
        self.current.update(deepcopy(self.plan["changes"]))
        self.record("simulated", "offline-engine")

    def verify(self):
        if self.status != "simulated":
            raise WorkflowError("Simulation must precede verification")
        playbook = self.finding["playbook"]
        if playbook == "quarantine-ec2":
            passed = self.current["security_group_ids"] == [self.parameters["quarantine_group_id"]]
        elif playbook == "block-public-s3":
            passed = all(
                self.current["public_access_block"].get(k) is True
                for k in (
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets",
                )
            )
        elif playbook == "apply-required-tags":
            passed = all(
                self.current["tags"].get(k) == self.parameters["approved_tags"][k]
                for k in ("Owner", "Environment")
            )
        else:
            passed = self.current.get("logging_enabled") is True
        self.record("verified" if passed else "verification_failed", "offline-verifier")
        if not passed:
            raise WorkflowError("Expected postcondition was not observed")
        return self.result()

    def rollback(self):
        if self.status not in ("simulated", "verified", "verification_failed"):
            raise WorkflowError("There is no simulated change to roll back")
        self.current = deepcopy(self.before)
        self.record("rolled_back", "offline-engine")
        return self.result()

    def result(self):
        return deepcopy(
            {
                "finding_id": self.finding["id"],
                "status": self.status,
                "mode": "simulation_only",
                "before": self.before,
                "after": self.current,
                "plan": self.plan,
                "history": self.history,
            }
        )
