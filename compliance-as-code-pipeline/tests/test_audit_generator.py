"""Offline tests for the evidence report generator.

These are unit tests of report parsing and fail-closed behavior; they do not
make PCI-DSS/SOC2 compliance claims or exercise live AWS credentials.
"""
import contextlib
import importlib.util
import json
import os
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("audit_generator", ROOT / "scripts" / "generate-audit-pack.py")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class EvidencePackTests(unittest.TestCase):
    @contextlib.contextmanager
    def sandbox(self):
        old_cwd = pathlib.Path.cwd()
        old_sha = os.environ.get("GITHUB_SHA")
        with tempfile.TemporaryDirectory() as directory:
            os.chdir(directory)
            os.environ["GITHUB_SHA"] = "a" * 40
            pathlib.Path("reports").mkdir()
            try:
                yield pathlib.Path(directory)
            finally:
                os.chdir(old_cwd)
                if old_sha is None:
                    os.environ.pop("GITHUB_SHA", None)
                else:
                    os.environ["GITHUB_SHA"] = old_sha

    def write_report(self, name, data):
        (pathlib.Path("reports") / name).write_text(json.dumps(data), encoding="utf-8")

    def test_all_scanners_pass(self):
        with self.sandbox():
            self.write_report("results_json.json", {"summary": {"failed": 0}})
            self.write_report("gitleaks-report.json", [])
            self.write_report("trivy-report.json", {"Results": []})
            self.write_report("opa-report.json", [])
            module.generate_report()
            report = pathlib.Path("reports/AUDIT_EVIDENCE.md").read_text(encoding="utf-8")
            self.assertIn("Overall Gate Status:** **PASSED**", report)
            self.assertIn("a" * 40, report)

    def test_missing_scanner_evidence_is_failure(self):
        with self.sandbox():
            with self.assertRaises(SystemExit) as context:
                module.generate_report()
            self.assertEqual(context.exception.code, 1)
            report = pathlib.Path("reports/AUDIT_EVIDENCE.md").read_text(encoding="utf-8")
            self.assertIn("Overall Gate Status:** **FAILED**", report)

    def test_detects_findings_from_multiple_tools(self):
        with self.sandbox():
            self.write_report("results_json.json", {"summary": {"failed": 1}})
            self.write_report("gitleaks-report.json", [{"file": "placeholder.py"}])
            self.write_report("trivy-report.json", {"Results": [{"Vulnerabilities": [{"VulnerabilityID": "example"}]}]})
            self.write_report("opa-report.json", [{"failures": [{"msg": "test violation"}]}])
            with self.assertRaises(SystemExit) as context:
                module.generate_report()
            self.assertEqual(context.exception.code, 1)
            content = pathlib.Path("reports/AUDIT_EVIDENCE.md").read_text(encoding="utf-8")
            self.assertIn("Overall Gate Status:** **FAILED**", content)


if __name__ == "__main__":
    unittest.main()
