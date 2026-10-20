# Validation record

Recorded **20 October 2026**. Local environment: Windows, Python 3.14.2, Terraform 1.15.8 and AWS provider 6.69.1.

| Check | Result |
| --- | --- |
| Python tests | **101 passed**, zero failures |
| Combined statement/branch coverage | **98.64%**; configured minimum 90% |
| Terraform validation | All three roots passed |
| Terraform mock-provider tests | **10 passed**, zero failures |
| SCP scenario matrix | **27/27 expected decisions matched** |
| Fictional response exercises | **4/4 verified in memory** |
| Ruff lint and formatting | Passed |
| Dependency consistency | Passed |
| Runtime dependency advisory audit | 12 applicable packages checked; no known vulnerabilities reported |
| Package build | Source archive and wheel built successfully |
| Installed-wheel smoke test | Passed from outside the source directory; loaded the installed package |
| Hosted GitHub Actions | **Passed on Python 3.11 and 3.14**, including Terraform mock tests, dependency audits, builds and installed-wheel checks |
| Live AWS deployment | Not performed |
| Real SCP enforcement / log delivery / generated AWS findings | Not tested in an AWS account |
| Independent security or bank approval | Not performed or claimed |

See the [machine-readable record](../examples/validation/results.json) and [fictional report](../examples/demo/report.md). Dependency advisory results are time-specific; the hosted audits also passed for the Python 3.11 and 3.14 runtime environments, including the conditional Python 3.11 dependency.

Hosted evidence: [successful CI run on 20 October 2026](https://github.com/Srujal-Y/AWS-Security-Governance-Hardening-Lab/actions/runs/39465285504), commit `74e5bceb01b93e2adf9d1f32071ebb41b7b52d44`. Both Ubuntu jobs passed with Terraform 1.15.8 and AWS provider 6.69.1. Uploaded artifacts contain the test logs, coverage, fictional reports and distributions.

## Reproduction

After dependency installation and provider initialisation:

```powershell
.\.venv\Scripts\python.exe scripts/verify.py
.\.venv\Scripts\python.exe -m pip_audit -r requirements.txt --strict --disable-pip --no-deps
```

The verification script records logs in `reports/`, JUnit results in `reports/junit.xml`, coverage in `coverage.xml` and a compact record in `reports/validation.json`. Generated local artifacts and virtual environments are ignored by Git.

All Terraform test runs use `mock_provider "aws"` and `command = plan`. Their success proves configuration and tested plan invariants under the mocked schema, not that AWS accepted a live deployment.

## Cases exercised

- Approved and denied regions, global-service exceptions and action-name casing.
- Exact administrator-role exceptions; lookalike and foreign-account roles remain denied.
- Role trust/creation protection, service tampering, key administration, member departure and root credentials.
- Management-account and service-linked-role exclusions.
- Unsupported policy syntax, ambiguous request context and unsafe exception inputs.
- Private, versioned, encrypted archive settings and account-bound delivery statements.
- Four-service enablement, six Config rules and secondary-region global-resource handling.
- Independent fictional approval, wrong account/resource/region refusal, verification failures and rollback.
- GuardDuty severity mapping, supported event shapes and conflicting Security Hub account metadata.
- Read-only AWS verification with real botocore response schemas, paginated standards, denied reads and account mismatch.
- Report escaping, output failures, replay validation and credential-free demo behaviour.

Coverage is a measure of exercised code paths. It does not establish complete AWS security coverage, real network containment, organization-wide enforcement or compliance.

## Evidence still required

Follow the live acceptance procedure in [RESPONSE.md](RESPONSE.md): authorised deployment, actual delivery to each archive prefix, readable encrypted logs, actual service findings/evaluations, a controlled SCP test matrix, approved remediation and independent verification.

The included sample reports must remain labelled as fictional until separate live evidence exists.
