from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
REGISTRY_HELPER = REPO_ROOT / ".claude" / "tools" / "manage_subagent_registry.py"
OBSERVATION_HELPER = REPO_ROOT / ".claude" / "tools" / "manage_observation_report.py"
EXPLOITATION_HELPER = REPO_ROOT / ".claude" / "tools" / "manage_exploitation_report.py"


class LightOrchestrationTests(unittest.TestCase):
    def run_cmd(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, *args],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=True,
        )

    def test_registry_v2_repair_and_proposal_flow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            registry = Path(tmp) / "reports" / "subagent_registry.json"
            registry.parent.mkdir(parents=True, exist_ok=True)
            registry.write_text(
                json.dumps(
                    {
                        "observation_owner": {"owner_id": "obs-1", "role": "observation-subagent", "status": "waiting"},
                        "exploitation_owners": [{"owner_id": "exp-1", "role": "exploitation-subagent", "vector_slug": "auth"}],
                    },
                    ensure_ascii=False,
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            self.run_cmd(str(REGISTRY_HELPER), "repair", "--registry", str(registry))
            repaired = json.loads(registry.read_text(encoding="utf-8"))
            self.assertEqual(repaired["schema_version"], 2)
            self.assertEqual(repaired["proposal_queue"], [])

            self.run_cmd(
                str(REGISTRY_HELPER),
                "proposal",
                "raise",
                "--registry",
                str(registry),
                "--kind",
                "fact_challenge",
                "--raised-by-owner-id",
                "exp-1",
                "--target-owner-id",
                "obs-1",
                "--vector-slug",
                "auth",
                "--report-ref",
                "reports/exploitation/exploitation_auth.json",
                "--exact-inputs",
                '{"username":"demo"}',
                "--expected-observation",
                "demo login works",
                "--actual-observation",
                "demo login failed",
            )
            proposed = json.loads(registry.read_text(encoding="utf-8"))
            proposal_id = proposed["proposal_queue"][0]["id"]
            self.assertEqual(proposed["proposal_queue"][0]["status"], "proposed")

            self.run_cmd(
                str(REGISTRY_HELPER),
                "proposal",
                "decide",
                "--registry",
                str(registry),
                "--proposal-id",
                proposal_id,
                "--decision",
                "accept_revalidate",
                "--assigned-owner-id",
                "obs-1",
            )
            decided = json.loads(registry.read_text(encoding="utf-8"))
            self.assertEqual(decided["proposal_queue"][0]["status"], "accepted")
            self.assertEqual(decided["proposal_queue"][0]["main_decision"], "accept_revalidate")

            self.run_cmd(
                str(REGISTRY_HELPER),
                "proposal",
                "resolve",
                "--registry",
                str(registry),
                "--proposal-id",
                proposal_id,
                "--resolution",
                '{"result":"revalidated"}',
            )
            resolved = json.loads(registry.read_text(encoding="utf-8"))
            self.assertEqual(resolved["proposal_queue"][0]["status"], "resolved")

    def test_observation_report_repairs_to_v2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "reports" / "observation_report.json"
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text(
                json.dumps(
                    {
                        "target": "http://example.com",
                        "hypotheses": [{"family": "sql_injection", "claim": "quote marker looks suspicious"}],
                        "recommendation": "Validate the quote anomaly on POST /jobs only",
                    },
                    ensure_ascii=False,
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            self.run_cmd(str(OBSERVATION_HELPER), "--report", str(report), "--repair-in-place")
            repaired = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(repaired["schema_version"], 2)
            self.assertIsInstance(repaired["probe_matrix"], list)
            self.assertIsInstance(repaired["decision_signals"], list)
            self.assertEqual(repaired["recommended_next_step"]["kind"], "exploitation_followup")
            self.assertEqual(repaired["recommended_next_step"]["target_role"], "exploitation-subagent")
            self.assertIn("Validate the quote anomaly", repaired["recommended_next_step"]["stop_condition"])

    def test_exploitation_index_surfaces_open_proposals_first(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports_dir = Path(tmp) / "reports"
            detail_dir = reports_dir / "exploitation"
            detail_dir.mkdir(parents=True, exist_ok=True)
            registry = reports_dir / "subagent_registry.json"
            registry.write_text(
                json.dumps(
                    {
                        "schema_version": 2,
                        "observation_owner": {},
                        "exploitation_owners": [],
                        "proposal_queue": [
                            {
                                "id": "prop_001",
                                "kind": "fact_challenge",
                                "status": "proposed",
                                "vector_slug": "auth",
                                "report_ref": "reports/exploitation/exploitation_auth.json",
                            }
                        ],
                    },
                    ensure_ascii=False,
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            detail = detail_dir / "exploitation_auth.json"
            detail.write_text(
                json.dumps(
                    {
                        "schema_version": 2,
                        "vector_slug": "auth",
                        "stage": "existence_check",
                        "status": "blocked",
                        "summary": {"objective": "Auth check", "next_steps": ["Revalidate auth fact"]},
                        "decision_signals": [{"kind": "fact_challenge", "summary": "auth fact mismatch"}],
                    },
                    ensure_ascii=False,
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            index_path = detail_dir / "exploitation_report.json"

            self.run_cmd(str(EXPLOITATION_HELPER), "--index", str(index_path), "--detail", str(detail))
            index = json.loads(index_path.read_text(encoding="utf-8"))
            self.assertEqual(index["schema_version"], 2)
            self.assertEqual(index["summary"]["open_proposals"][0]["kind"], "fact_challenge")
            self.assertEqual(index["summary"]["priority_actions"][0]["kind"], "proposal")

    def test_orchestrated_main_has_no_sandbox_tools(self) -> None:
        import run_task

        command = run_task.build_claude_shell_command(challenge_mcp_enabled=False, agent_mode="orchestrated")
        self.assertIn('--tools "Agent,Task,SendMessage,Read,Grep,Glob"', command)
        self.assertIn('--allowedTools "Agent Task SendMessage Read Grep Glob"', command)
        self.assertNotIn("mcp__sandbox__python_exec", command)


if __name__ == "__main__":
    unittest.main()
