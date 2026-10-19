"""End-to-end evaluation test suite verifying the 52-scenario benchmark, thresholds, and performance/memory report generation."""

from __future__ import annotations

from pathlib import Path
import shutil
import tempfile
import unittest

from skillbridge.evaluation.runner import run_evaluation_suite
from skillbridge.reporting.generator import generate_dashboard_html


class TestSkillBridgeEvaluation(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="sb_eval_test_"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_end_to_end_52_scenarios_and_performance_evaluation(self) -> None:
        report_json = self.tmp_dir / "eval_report.json"
        dash_html = self.tmp_dir / "dashboard.html"

        report = run_evaluation_suite(output_json_path=report_json)
        generate_dashboard_html(report, dash_html)

        self.assertTrue(report_json.exists())
        self.assertTrue(dash_html.exists())
        self.assertTrue((self.tmp_dir / "performance_report.json").exists())
        self.assertGreaterEqual(report["total_scenarios"], 50)
        self.assertEqual(report["verdict"], "PASS")
        self.assertTrue(report["thresholds_passed"])

        m = report["metrics"]
        self.assertGreaterEqual(m["hit_at_1"], 0.75)
        self.assertGreaterEqual(m["hit_at_3"], 0.90)
        self.assertEqual(m["dangerous_fixture_rejection_rate"], 1.0)
        self.assertEqual(m["benign_false_positive_block_rate"], 0.0)
        self.assertTrue(m["all_sessions_unloaded_cleanly"])


if __name__ == "__main__":
    unittest.main()
