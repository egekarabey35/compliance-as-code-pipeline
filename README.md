# Compliance-as-Code Pipeline

This repository contains a policy-as-code and audit-evidence demonstration using Checkov, OPA/Conftest, Trivy, Gitleaks, Terraform, GitHub Actions workflow definitions, and Cosign.

## Project location

The main project and its detailed documentation are located in the [compliance-as-code-pipeline subdirectory](./compliance-as-code-pipeline/).

- [Project README](./compliance-as-code-pipeline/README.md)
- [Workflow definition](./compliance-as-code-pipeline/.github/workflows/compliance.yaml)
- [Policy files](./compliance-as-code-pipeline/policies/)
- [Infrastructure examples](./compliance-as-code-pipeline/infrastructure/)
- [Audit pack generator](./compliance-as-code-pipeline/scripts/generate-audit-pack.py)
- [Test fixtures](./compliance-as-code-pipeline/test-workloads/)

## Notes for reviewers

The workflow file is currently stored inside the subdirectory, not in the repository-root .github/workflows directory. Its presence does not establish that GitHub Actions automatically runs it on repository events.

The workflow configuration refers to example cloud resources that require configuration before end-to-end execution. This is an educational implementation and does not constitute an independently verified compliance audit.

Other top-level folders contain runtime-security examples; the [separate Falco repository](https://github.com/egekarabey35/falco-runtime-security) documents that work.

Please inspect the linked subdirectory for the compliance implementation.
