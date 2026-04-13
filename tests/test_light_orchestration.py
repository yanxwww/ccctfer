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

    def test_registry_preserves_exact_owner_id_when_generic_role_is_sent_later(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            registry = Path(tmp) / "reports" / "subagent_registry.json"
            registry.parent.mkdir(parents=True, exist_ok=True)
            registry.write_text(
                json.dumps(
                    {
                        "schema_version": 2,
                        "observation_owner": {},
                        "exploitation_owners": [
                            {
                                "owner_id": "a711ce8d53e97c6bf",
                                "role": "exploitation-subagent",
                                "vector_slug": "sql_injection_job_type",
                                "detail_report": "reports/exploitation/exploitation_sql_injection_job_type.json",
                                "status": "running",
                            }
                        ],
                        "proposal_queue": [],
                    },
                    ensure_ascii=False,
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            self.run_cmd(
                str(REGISTRY_HELPER),
                "owner",
                "upsert",
                "--registry",
                str(registry),
                "--role",
                "exploitation-subagent",
                "--owner-id",
                "exploitation-subagent",
                "--vector-slug",
                "sql_injection_job_type",
                "--detail-report",
                "reports/exploitation/exploitation_sql_injection_job_type.json",
                "--stage",
                "exploit_or_retrieval",
                "--status",
                "running",
            )
            updated = json.loads(registry.read_text(encoding="utf-8"))
            self.assertEqual(updated["exploitation_owners"][0]["owner_id"], "a711ce8d53e97c6bf")

    def test_registry_preserves_exact_observation_owner_when_generic_agent_alias_is_sent_later(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            registry = Path(tmp) / "reports" / "subagent_registry.json"
            registry.parent.mkdir(parents=True, exist_ok=True)
            registry.write_text(
                json.dumps(
                    {
                        "schema_version": 2,
                        "observation_owner": {
                            "owner_id": "a6b517fa6187c077f",
                            "role": "observation-subagent",
                            "vector_slug": "observation",
                            "status": "waiting",
                        },
                        "exploitation_owners": [],
                        "proposal_queue": [],
                    },
                    ensure_ascii=False,
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            self.run_cmd(
                str(REGISTRY_HELPER),
                "owner",
                "upsert",
                "--registry",
                str(registry),
                "--role",
                "observation-subagent",
                "--owner-id",
                "observation-agent",
                "--vector-slug",
                "observation",
                "--stage",
                "finalization",
                "--status",
                "completed",
            )
            updated = json.loads(registry.read_text(encoding="utf-8"))
            self.assertEqual(updated["observation_owner"]["owner_id"], "a6b517fa6187c077f")
            self.assertEqual(updated["observation_owner"]["status"], "completed")

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
                        "schema_version": "1.0",
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
            normalized_detail = json.loads(detail.read_text(encoding="utf-8"))
            self.assertEqual(index["schema_version"], 2)
            self.assertEqual(normalized_detail["schema_version"], 2)
            self.assertEqual(index["summary"]["open_proposals"][0]["kind"], "fact_challenge")
            self.assertEqual(index["summary"]["priority_actions"][0]["kind"], "proposal")

    def test_exploitation_index_detects_nested_flag_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            detail_dir = Path(tmp) / "reports" / "exploitation"
            detail_dir.mkdir(parents=True, exist_ok=True)
            detail = detail_dir / "exploitation_xxe_svg_upload.json"
            detail.write_text(
                json.dumps(
                    {
                        "schema_version": 2,
                        "vector_slug": "xxe_svg_upload",
                        "stage": "exploit_or_retrieval",
                        "status": "success",
                        "evidence": [
                            {"type": "file_read", "target": "/app/flag.txt", "content": "flag{real_flag_123456}"}
                        ],
                        "decision_signals": ["Flag format matches expected pattern flag{...}"],
                        "mcp_submission": {
                            "attempted": False,
                            "status": "not_required",
                            "flag": "flag{real_flag_123456}",
                        },
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
            report = index["reports"][0]
            self.assertTrue(report["candidate_flag_found"])
            self.assertEqual(report["candidate_flag_count"], 1)
            self.assertEqual(index["summary"]["candidate_flag_reports"], 1)

    def test_orchestrated_hides_sandbox_tools_but_keeps_subagent_access(self) -> None:
        import run_task

        command = run_task.build_claude_shell_command(challenge_mcp_enabled=False, agent_mode="orchestrated")
        self.assertIn('--tools "Agent,Task,SendMessage,Read,Grep,Glob"', command)
        self.assertIn('--allowedTools "Agent Task SendMessage Read Grep Glob mcp__sandbox__python_exec', command)
        self.assertNotIn("mcp__sandbox__list_agent_runtimes", command)
        self.assertNotIn("mcp__sandbox__cleanup_agent_runtime", command)

    def test_orchestrated_prompt_includes_root_blocker_fast_fail_rules(self) -> None:
        import run_task

        challenge = {
            "challenge_title": "demo",
            "challenge_code": "demo-code",
            "target_host": "10.0.0.1:8080",
            "challenge_description": "demo target",
            "challenge_hint": "",
            "challenge_entrypoints": ["10.0.0.1:8080"],
            "challenge_mcp_enabled": True,
            "challenge_mcp_server": "http://10.0.0.1:8000",
            "server_host": "http://10.0.0.1:8000",
        }

        prompt = run_task.build_prompt(challenge, agent_mode="orchestrated")
        self.assertIn("视为 root blocker", prompt)
        self.assertIn("不要再启动新的 observation / exploitation subagent", prompt)
        self.assertIn("最多只允许 main 额外调用 1 次 `view_hint`", prompt)
        self.assertIn("不要让 exploitation-subagent 代替 observation 做基础侦察", prompt)
        self.assertIn("不要在拿到 `Agent` 工具返回的真实 `agentId` 前，用猜测的 owner_id 预写 registry", prompt)
        self.assertIn("真实 checkpoint", prompt)
        self.assertIn("不是权限型 root blocker", prompt)
        self.assertIn("每次 `Agent` / `SendMessage` 派单都必须显式携带完整题目元数据", prompt)
        self.assertIn("不要轮询同一份未变化的 JSON", prompt)
        self.assertIn("不要给同一个 owner 发送互相冲突的控制消息", prompt)
        self.assertIn("observation 是持续 frontier producer", prompt)
        self.assertIn("生成去重 frontier", prompt)
        self.assertIn("terminal success", prompt)
        self.assertIn("challenge_mcp_enabled=false", prompt)
        self.assertIn("curl-first", prompt)
        self.assertIn("--max-redirs 0", prompt)
        self.assertIn("redirect_history", prompt)
        self.assertIn("redirect_query_params", prompt)
        self.assertIn("redirect_param_keys", prompt)
        self.assertIn(".artifacts/observation/http_trace_<slug>.jsonl", prompt)
        self.assertIn("不要手写 multipart boundary", prompt)

    def test_http_trace_contract_is_documented_for_subagents(self) -> None:
        main_rules = (REPO_ROOT / ".claude" / "CLAUDE.md").read_text(encoding="utf-8")
        observation_rules = (REPO_ROOT / ".claude" / "agents" / "observation_subagent.md").read_text(
            encoding="utf-8"
        )
        exploitation_rules = (REPO_ROOT / ".claude" / "agents" / "exploitation-subagent.md").read_text(
            encoding="utf-8"
        )

        for text in (main_rules, observation_rules):
            self.assertIn("curl-first", text)
            self.assertIn("--max-redirs 0", text)
            self.assertIn("Location", text)
            self.assertIn("redirect_history", text)
            self.assertIn("redirect_query_params", text)
            self.assertIn("redirect_param_keys", text)
            self.assertIn(".artifacts/observation/http_trace_<slug>.jsonl", text)
            self.assertIn("不要手写 multipart boundary", text)

        self.assertIn("Python `requests`", exploitation_rules)
        self.assertIn("allow_redirects=False", exploitation_rules)
        self.assertIn("response.history", exploitation_rules)
        self.assertIn("redirect_query_params", exploitation_rules)
        self.assertIn("redirect_param_keys", exploitation_rules)
        self.assertIn("不要只写自然语言", exploitation_rules)


if __name__ == "__main__":
    unittest.main()
