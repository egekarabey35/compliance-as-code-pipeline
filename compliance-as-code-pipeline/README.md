# Compliance-as-Code and Audit Evidence Lab

An **educational proof-of-concept** combining policy-as-code, static configuration scanning and evidence collection. The project maps selected security checks to concepts found in PCI-DSS v4.0 and SOC 2; this is **not PCI certification, a SOC 2 report, or an independent audit opinion**.

## Implemented project files

- [OPA/Conftest rules](policies/opa/pci_dss.rego) and [positive/negative test fixtures](test-workloads/negative-fixtures/)
- [Checkov configuration](policies/checkov/.checkov.yaml) and [example Terraform](infrastructure/prod/)
- [Python evidence collector](scripts/generate-audit-pack.py) and [example report](reports/AUDIT_EVIDENCE.md)
- [End-to-end workflow draft](.github/workflows/compliance.yaml), which combines secret scanning, IaC evaluation, container scanning and Sigstore commands

## What currently runs in GitHub Actions

The actual CI workflow is at the [repository root](../.github/workflows/policy-tests.yml), and it runs **offline Conftest policy checks** against a compliant Kubernetes workload and deliberately noncompliant Kubernetes/Terraform fixtures, plus a Python syntax check. GitHub Actions results are visible on the repository's Actions tab.

**The nested end-to-end workflow definition is not discovered automatically by GitHub Actions**. It uses sample cloud role and backend values, path assumptions and signing commands that still require configuration and a successful live execution before any cloud-backed evidence or cryptographic provenance can be asserted.

## Local policy test

From this subdirectory after installing Conftest v0.48.0 (or a compatible version):

```bash
# The safe fixture should pass.
conftest test infrastructure/prod/compliant-deployment.yaml -p policies/opa -n compliance.pci_dss

# These intentionally insecure fixtures should fail (nonzero exit status).
conftest test test-workloads/negative-fixtures/non-compliant-deployment.yaml -p policies/opa -n compliance.pci_dss
conftest test test-workloads/negative-fixtures/tf-plan-negative.json -p policies/opa -n compliance.pci_dss
```

The OPA policy checks selected controls only. For example, inspecting whether a Terraform plan's encryption configuration uses KMS does not establish that **all** buckets are encrypted. External validation and a licensed auditor would be required for regulatory assurance.

## Operational limitations

The proposed cloud workflow's AWS IAM role and state backend must be configured with least privilege; otherwise it cannot run. The evidence generator fails closed if required JSON reports are missing, but a successful offline policy fixture test does not validate the planned multi-tool evidence gate or Cosign signing.

The correct verification path for signing artifacts is the actual GitHub Actions output from a successful execution, not a hypothetical command in a README.
