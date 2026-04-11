#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import shlex
import subprocess
import sys
import time
import unicodedata
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


REPO_ROOT = Path(__file__).resolve().parent
CLAUDE_TEMPLATE_DIR = REPO_ROOT / ".claude"
DEFAULT_IMAGE = os.getenv("IMAGE_NAME", "ccctfer-mcp:latest")
DEFAULT_TIMEOUT_SECONDS = int(os.getenv("RUN_TIMEOUT_SECONDS", "7200"))
DEFAULT_READY_TIMEOUT_SECONDS = int(os.getenv("MCP_READY_TIMEOUT_SECONDS", "60"))
DEFAULT_POLL_INTERVAL_SECONDS = float(os.getenv("MCP_POLL_INTERVAL_SECONDS", "1"))
DEFAULT_DEBUG_MCP_PORT = os.getenv("DEBUG_MCP_PORT")
DEFAULT_DOCKER_PLATFORM = os.getenv("DOCKER_PLATFORM", "")
DEFAULT_AGENT_MODE = os.getenv("AGENT_MODE", "orchestrated").strip().lower() or "orchestrated"
AGENT_TEAMS_ENV_NAME = "CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS"
AGENT_TEAMS_ENV_VALUE = "1"
ENV_FILE_PATH = REPO_ROOT / ".env"
CLAUDE_MCP_CONFIG_NAME = "mcp.json"
INPUTS_DIR_NAME = ".inputs"
REPORTS_DIR_NAME = "reports"
EXPLOITATION_REPORTS_DIR_NAME = "exploitation"
ARTIFACTS_DIR_NAME = ".artifacts"
OBSERVATION_ARTIFACTS_DIR_NAME = "observation"
RESULTS_DIR_NAME = ".results"
INPUT_CHALLENGE_RELATIVE_PATH = f"{INPUTS_DIR_NAME}/challenge.json"
OBSERVATION_REPORT_RELATIVE_PATH = f"{REPORTS_DIR_NAME}/observation_report.json"
EXPLOITATION_REPORTS_RELATIVE_DIR = f"{REPORTS_DIR_NAME}/{EXPLOITATION_REPORTS_DIR_NAME}"
EXPLOITATION_MASTER_REPORT_RELATIVE_PATH = f"{EXPLOITATION_REPORTS_RELATIVE_DIR}/exploitation_report.json"
EXPLOITATION_DETAIL_PATTERN_RELATIVE_PATH = f"{EXPLOITATION_REPORTS_RELATIVE_DIR}/exploitation_<slug>.json"
OBSERVATION_ARTIFACTS_RELATIVE_DIR = f"{ARTIFACTS_DIR_NAME}/{OBSERVATION_ARTIFACTS_DIR_NAME}"
EXPLOITATION_ARTIFACTS_RELATIVE_DIR = f"{ARTIFACTS_DIR_NAME}/{EXPLOITATION_REPORTS_DIR_NAME}"
RESULT_FLAG_RELATIVE_PATH = f"{RESULTS_DIR_NAME}/flag.txt"
RESULT_FINAL_REPORT_RELATIVE_PATH = f"{RESULTS_DIR_NAME}/final_report.md"
RESULT_BLOCKER_REPORT_RELATIVE_PATH = f"{RESULTS_DIR_NAME}/blocker_report.md"
OBSERVATION_MERGER_RELATIVE_PATH = ".claude/tools/manage_observation_report.py"
EXPLOITATION_INDEX_MERGER_RELATIVE_PATH = ".claude/tools/manage_exploitation_report.py"
ARTIFACT_SUMMARIZER_RELATIVE_PATH = ".claude/tools/summarize_artifact.py"
MAX_PARALLEL_EXPLOITATION = 2
MAX_TOTAL_EXPLOITATION_SUBAGENTS = 5
MAX_CONSECUTIVE_EMPTY_TERMINAL_READS = 3
MAX_TERMINAL_READ_CALLS = 40
MAX_INLINE_TOOL_OUTPUT_BYTES = 4096
MAX_INLINE_TOOL_OUTPUT_LINES = 20
GRACEFUL_CLAUDE_INTERRUPT_SECONDS = 10
FLAG_PATTERN = re.compile(r"flag\{[^\r\n]+\}")
CANONICAL_OBSERVATION_ROOT_KEYS = {
    "target",
    "surface_map",
    "evidence",
    "hypotheses",
    "negative_findings",
    "unknowns",
    "recommended_next_step",
}

REQUIRED_CHALLENGE_ENV_KEYS = ["CHALLENGE_ENTRYPOINT"]
OPTIONAL_CHALLENGE_ENV_KEYS = [
    "AGENT_TOKEN",
    "SERVER_HOST",
    "CHALLENGE_CODE",
    "CHALLENGE_TITLE",
    "CHALLENGE_DESCRIPTION",
    "CHALLENGE_HINT",
]
CLAUDE_ENV_KEYS = [
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_MODEL",
]


def parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        values[key.strip()] = value
    return values

MCP_READY_SCRIPT = """
import sys
import urllib.error
import urllib.request

request = urllib.request.Request(
    "http://127.0.0.1:8000/mcp",
    headers={"Accept": "application/json, text/event-stream"},
)

try:
    with urllib.request.urlopen(request, timeout=2) as response:
        status = response.status
except urllib.error.HTTPError as error:
    status = error.code
except Exception:
    raise SystemExit(1)

raise SystemExit(0 if status in {200, 400, 404, 405, 406} else 1)
""".strip()

PYTHON_EXEC_HEALTHCHECK_SCRIPT = """
import json
import sys
from pathlib import Path

app_dir = Path("/home/kali/python-terminal-mcp/app")
worker_path = app_dir / "python_session_worker.py"
if not worker_path.is_file():
    raise SystemExit(f"python_session_worker.py is missing at {worker_path}")

sys.path.insert(0, str(app_dir))
import python_terminal_mcp as python_terminal_mcp_module

agent_id = "launcher-healthcheck"
executor = python_terminal_mcp_module.python_terminal_executor_v2
executor.configure_runtime("/home/kali/workspace/runtime_v2", workspace_dir="/home/kali/workspace")
result = executor.python_exec(
    agent_id=agent_id,
    code=\"\"\"import requests
print(requests.__version__)
print('python-exec-healthcheck-ok')\"\"\",
    wait_timeout_seconds=5,
    hard_timeout_seconds=10,
    background_on_timeout=False,
)

try:
    executor.cleanup_agent_runtime(agent_id=agent_id, force=True)
except Exception:
    pass

outputs = result.get("outputs") or []
saw_ok = any(
    isinstance(item, dict)
    and item.get("type") == "stream"
    and "python-exec-healthcheck-ok" in (item.get("text") or "")
    for item in outputs
)
print(
    json.dumps(
        {
            "status": result.get("status"),
            "error_summary": result.get("error_summary"),
            "saw_ok": saw_ok,
        },
        ensure_ascii=False,
    )
)
raise SystemExit(0 if result.get("status") in {"succeeded", "completed"} and saw_ok else 1)
""".strip()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run one automated CTF task in Docker.")
    parser.add_argument("--image", default=DEFAULT_IMAGE, help="Docker image name.")
    parser.add_argument(
        "--workspace-root",
        default="workspace",
        help="Workspace root under the current repository.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="Maximum time allowed for the Claude task.",
    )
    parser.add_argument(
        "--ready-timeout-seconds",
        type=int,
        default=DEFAULT_READY_TIMEOUT_SECONDS,
        help="Maximum time to wait for the in-container MCP server.",
    )
    parser.add_argument(
        "--poll-interval-seconds",
        type=float,
        default=DEFAULT_POLL_INTERVAL_SECONDS,
        help="Polling interval for the MCP readiness check.",
    )
    parser.add_argument(
        "--debug-mcp-port",
        type=int,
        default=int(DEFAULT_DEBUG_MCP_PORT) if DEFAULT_DEBUG_MCP_PORT else None,
        help="Optional host port to expose the container MCP server.",
    )
    parser.add_argument(
        "--docker-platform",
        default=DEFAULT_DOCKER_PLATFORM,
        help="Optional platform passed to docker run, for example linux/amd64.",
    )
    parser.add_argument(
        "--disable-challenge-mcp",
        action="store_false",
        dest="enable_challenge_mcp",
        default=True,
        help="Disable competition challenge MCP integration; by default it is enabled for the main agent only.",
    )
    parser.add_argument(
        "--agent-mode",
        choices=("single", "orchestrated"),
        default=DEFAULT_AGENT_MODE if DEFAULT_AGENT_MODE in {"single", "orchestrated"} else "orchestrated",
        help="Agent workflow mode. 'orchestrated' uses the multi-agent framework; 'single' is an A/B fallback without subagents.",
    )
    return parser.parse_args()


def get_runtime_value(runtime_env: dict[str, str], name: str) -> str | None:
    value = runtime_env.get(name)
    if value is None:
        value = os.getenv(name)
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def require_runtime_value(runtime_env: dict[str, str], name: str) -> str:
    value = get_runtime_value(runtime_env, name)
    if not value:
        raise SystemExit(f"Missing required environment variable: {name}")
    return value


def maybe_decode_text(value: str | None) -> str:
    if value is None:
        return ""
    stripped = value.strip()
    if not stripped:
        return ""
    if not re.fullmatch(r"[A-Za-z0-9+/=_-]+", stripped):
        return stripped
    candidate = stripped.replace("-", "+").replace("_", "/")
    padded = candidate + "=" * (-len(candidate) % 4)
    try:
        decoded_bytes = base64.b64decode(padded, validate=True)
        decoded = decoded_bytes.decode("utf-8")
    except Exception:
        return stripped

    if not decoded:
        return stripped

    printable = sum(1 for char in decoded if char.isprintable() or char.isspace())
    if printable / len(decoded) < 0.85:
        return stripped

    roundtrip = base64.b64encode(decoded_bytes).decode().rstrip("=")
    if roundtrip != candidate.rstrip("="):
        return stripped
    return decoded


def slugify_title(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).strip().lower()
    normalized = normalized.replace("/", "-").replace("\\", "-")
    normalized = re.sub(r"\s+", "-", normalized)
    normalized = re.sub(r"[^\w.-]+", "-", normalized, flags=re.UNICODE)
    normalized = normalized.replace("_", "-")
    normalized = re.sub(r"-{2,}", "-", normalized)
    normalized = normalized.strip("-.")
    return normalized or "challenge"


def default_title_from_entrypoint(entrypoints: list[str], server_host: str) -> str:
    target = server_host or (entrypoints[0] if entrypoints else "")
    parsed = urlsplit(target)
    candidate = parsed.netloc or parsed.path or target
    candidate = candidate.strip().strip("/") or "challenge"
    return candidate


def normalize_challenge_mcp_base_url(server_host: str) -> str:
    candidate = server_host.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", candidate):
        candidate = f"http://{candidate}"

    parsed = urlsplit(candidate)
    path = parsed.path.rstrip("/")
    if path.endswith("/api"):
        path = path[:-4]
    elif path.endswith("/mcp"):
        path = path[:-4]
    normalized = parsed._replace(path=path.rstrip("/"), query="", fragment="")
    return urlunsplit(normalized).rstrip("/")


def docker_name(value: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_.-]+", "-", value)
    safe = safe.strip("-.")
    return safe or "ctf-task"


def run_command(
    command: list[str],
    *,
    check: bool = True,
    capture_output: bool = True,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=check,
        capture_output=capture_output,
        text=True,
        input=input_text,
    )


def format_process_error(error: subprocess.CalledProcessError) -> str:
    parts = []
    if error.stderr:
        parts.append(error.stderr.strip())
    if error.stdout:
        parts.append(error.stdout.strip())
    return "\n".join(part for part in parts if part).strip() or str(error)


def ensure_image_exists(image: str) -> None:
    try:
        run_command(["docker", "image", "inspect", image])
    except subprocess.CalledProcessError as error:
        raise SystemExit(
            f"Docker image '{image}' was not found. Build it first with "
            f"'docker build -t {image} {shlex.quote(str(REPO_ROOT))}'."
        ) from error


def load_runtime_env() -> dict[str, str]:
    merged = parse_env_file(ENV_FILE_PATH)
    for key, value in os.environ.items():
        if value:
            merged[key] = value
    return merged


def load_challenge(runtime_env: dict[str, str], *, enable_challenge_mcp: bool = False) -> dict[str, object]:
    raw_entrypoints = require_runtime_value(runtime_env, "CHALLENGE_ENTRYPOINT")
    entrypoints = [item.strip() for item in raw_entrypoints.split(",") if item.strip()]
    if not entrypoints:
        raise SystemExit("CHALLENGE_ENTRYPOINT did not contain any usable entrypoints.")

    target_host = entrypoints[0]
    if enable_challenge_mcp:
        challenge_mcp_server = require_runtime_value(runtime_env, "SERVER_HOST")
        require_runtime_value(runtime_env, "AGENT_TOKEN")
        raw_challenge_code = require_runtime_value(runtime_env, "CHALLENGE_CODE")
    else:
        challenge_mcp_server = ""
        raw_challenge_code = get_runtime_value(runtime_env, "CHALLENGE_CODE")
    challenge_title = maybe_decode_text(get_runtime_value(runtime_env, "CHALLENGE_TITLE"))
    if not challenge_title:
        challenge_title = default_title_from_entrypoint(entrypoints, target_host)

    challenge_code = raw_challenge_code or slugify_title(challenge_title)
    challenge_description = maybe_decode_text(get_runtime_value(runtime_env, "CHALLENGE_DESCRIPTION"))
    challenge_hint = maybe_decode_text(get_runtime_value(runtime_env, "CHALLENGE_HINT"))
    challenge = {
        "server_host": target_host,
        "target_host": target_host,
        "challenge_mcp_enabled": enable_challenge_mcp,
        "challenge_mcp_server": challenge_mcp_server,
        "challenge_code": challenge_code,
        "challenge_entrypoints": entrypoints,
        "challenge_title": challenge_title,
        "challenge_description": challenge_description,
        "challenge_hint": challenge_hint,
        "has_agent_token": bool(get_runtime_value(runtime_env, "AGENT_TOKEN")),
        "created_at": datetime.now().isoformat(),
    }
    return challenge


def write_challenge_snapshot(task_dir: Path, challenge: dict[str, object]) -> None:
    snapshot = task_dir / INPUT_CHALLENGE_RELATIVE_PATH
    snapshot.parent.mkdir(parents=True, exist_ok=True)
    snapshot.write_text(
        json.dumps(challenge, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def initialize_task_dirs(task_dir: Path) -> None:
    (task_dir / INPUTS_DIR_NAME).mkdir(parents=True, exist_ok=True)
    (task_dir / REPORTS_DIR_NAME / EXPLOITATION_REPORTS_DIR_NAME).mkdir(parents=True, exist_ok=True)
    (task_dir / ARTIFACTS_DIR_NAME / OBSERVATION_ARTIFACTS_DIR_NAME).mkdir(parents=True, exist_ok=True)
    (task_dir / ARTIFACTS_DIR_NAME / EXPLOITATION_REPORTS_DIR_NAME).mkdir(parents=True, exist_ok=True)
    (task_dir / RESULTS_DIR_NAME).mkdir(parents=True, exist_ok=True)


def is_canonical_observation_payload(payload: object) -> bool:
    if not isinstance(payload, dict):
        return False
    if not CANONICAL_OBSERVATION_ROOT_KEYS.issubset(payload.keys()):
        return False
    if not isinstance(payload.get("target"), dict):
        return False
    if not isinstance(payload.get("surface_map"), dict):
        return False
    if not isinstance(payload.get("evidence"), list):
        return False
    if not isinstance(payload.get("hypotheses"), list):
        return False
    if not isinstance(payload.get("negative_findings"), list):
        return False
    if not isinstance(payload.get("unknowns"), list):
        return False
    if not isinstance(payload.get("recommended_next_step"), dict):
        return False
    return True


def ensure_canonical_observation_report(task_dir: Path, *, archive_noncanonical: bool) -> bool:
    report_path = task_dir / OBSERVATION_REPORT_RELATIVE_PATH
    if not report_path.exists():
        report_payload: object = {}
    else:
        try:
            report_payload = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            report_payload = {}

    changed = not is_canonical_observation_payload(report_payload)
    if changed and archive_noncanonical and report_path.exists():
        backup_dir = task_dir / ARTIFACTS_DIR_NAME / OBSERVATION_ARTIFACTS_DIR_NAME
        backup_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup_path = next_available_path(backup_dir / f"observation_report_noncanonical_{timestamp}.json")
        shutil.copy2(report_path, backup_path)

    try:
        run_command(
            [
                sys.executable,
                str(REPO_ROOT / OBSERVATION_MERGER_RELATIVE_PATH),
                "--report",
                str(report_path),
                "--repair-in-place",
            ],
            check=True,
        )
    except subprocess.CalledProcessError as error:
        print(
            "[!] Failed to repair observation report into canonical schema; keeping the existing file and continuing.\n"
            f"{format_process_error(error)}",
            file=sys.stderr,
        )
        return False
    return changed


def ensure_exploitation_report_index(task_dir: Path) -> None:
    exploitation_dir = task_dir / EXPLOITATION_REPORTS_RELATIVE_DIR
    exploitation_dir.mkdir(parents=True, exist_ok=True)
    index_path = task_dir / EXPLOITATION_MASTER_REPORT_RELATIVE_PATH
    if index_path.exists():
        return

    try:
        run_command(
            [
                sys.executable,
                str(REPO_ROOT / EXPLOITATION_INDEX_MERGER_RELATIVE_PATH),
                "--index",
                str(index_path),
                "--reconcile-dir",
                str(exploitation_dir),
            ],
            check=True,
        )
    except subprocess.CalledProcessError as error:
        print(
            "[!] Failed to initialize exploitation report index; continuing without a pre-created index.\n"
            f"{format_process_error(error)}",
            file=sys.stderr,
        )


def reconcile_exploitation_report_index(task_dir: Path) -> bool:
    exploitation_dir = task_dir / EXPLOITATION_REPORTS_RELATIVE_DIR
    detail_reports = [
        path
        for path in exploitation_dir.glob("exploitation_*.json")
        if not path.stem.startswith("exploitation_report")
    ]
    if not detail_reports:
        return False

    run_command(
        [
            sys.executable,
            str(REPO_ROOT / EXPLOITATION_INDEX_MERGER_RELATIVE_PATH),
            "--index",
            str(task_dir / EXPLOITATION_MASTER_REPORT_RELATIVE_PATH),
            "--reconcile-dir",
            str(exploitation_dir),
        ],
        check=True,
    )
    return True


def next_available_path(path: Path) -> Path:
    if not path.exists():
        return path
    stem = path.stem
    suffix = path.suffix
    counter = 2
    while True:
        candidate = path.with_name(f"{stem}_{counter}{suffix}")
        if not candidate.exists():
            return candidate
        counter += 1


def sanitize_task_workspace(task_dir: Path) -> None:
    allowed_roots = {
        ".claude",
        INPUTS_DIR_NAME,
        REPORTS_DIR_NAME,
        ARTIFACTS_DIR_NAME,
        RESULTS_DIR_NAME,
        "runtime_v2",
        "token_usage.txt",
    }
    misc_dir: Path | None = None

    for child in task_dir.iterdir():
        if child.name in allowed_roots:
            continue
        if child.name.startswith(".") and child.name not in {".DS_Store"}:
            continue
        if child.is_dir() and not any(child.iterdir()):
            child.rmdir()
            continue

        if misc_dir is None:
            misc_dir = task_dir / ARTIFACTS_DIR_NAME / "misc"
            misc_dir.mkdir(parents=True, exist_ok=True)
        target = next_available_path(misc_dir / child.name)
        shutil.move(str(child), str(target))


def initialize_workspace_claude_config(task_dir: Path) -> None:
    claude_dir = task_dir / ".claude"
    if claude_dir.exists() or claude_dir.is_symlink():
        if claude_dir.is_dir() and not claude_dir.is_symlink():
            shutil.rmtree(claude_dir)
        else:
            claude_dir.unlink()

    if CLAUDE_TEMPLATE_DIR.is_dir():
        shutil.copytree(
            CLAUDE_TEMPLATE_DIR,
            claude_dir,
            ignore=shutil.ignore_patterns("mcp.json", ".mcp.json", ".DS_Store", "__pycache__"),
        )
    else:
        claude_dir.mkdir(parents=True, exist_ok=True)

    (claude_dir / "agents").mkdir(parents=True, exist_ok=True)


def write_claude_mcp_config(task_dir: Path, runtime_env: dict[str, str], challenge: dict[str, object]) -> Path:
    config_path = task_dir / ".claude" / CLAUDE_MCP_CONFIG_NAME
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config = {
        "mcpServers": {
            "sandbox": {
                "type": "http",
                "url": "http://127.0.0.1:8000/mcp",
            }
        }
    }
    if challenge.get("challenge_mcp_enabled"):
        config["mcpServers"]["platform"] = {
            "type": "http",
            "url": f"{normalize_challenge_mcp_base_url(str(challenge['challenge_mcp_server']))}/mcp",
            "headers": {
                "Authorization": f"Bearer {require_runtime_value(runtime_env, 'AGENT_TOKEN')}",
            },
        }
    config_path.write_text(
        json.dumps(config, indent=2) + "\n",
        encoding="utf-8",
    )
    return config_path


def build_prompt(challenge: dict[str, object], *, agent_mode: str = "orchestrated") -> str:
    entrypoints = challenge["challenge_entrypoints"]
    entrypoint_lines = "\n".join(f"- {item}" for item in entrypoints) if entrypoints else "- (none provided)"
    description = str(challenge["challenge_description"]).strip() or "未提供"
    hint = str(challenge["challenge_hint"]).strip() or "未提供"
    input_challenge_path = f"/home/kali/workspace/{INPUT_CHALLENGE_RELATIVE_PATH}"
    observation_report_path = f"/home/kali/workspace/{OBSERVATION_REPORT_RELATIVE_PATH}"
    exploitation_master_report_path = f"/home/kali/workspace/{EXPLOITATION_MASTER_REPORT_RELATIVE_PATH}"
    exploitation_detail_pattern_path = f"/home/kali/workspace/{EXPLOITATION_DETAIL_PATTERN_RELATIVE_PATH}"
    observation_artifacts_dir = f"/home/kali/workspace/{OBSERVATION_ARTIFACTS_RELATIVE_DIR}"
    exploitation_artifacts_dir = f"/home/kali/workspace/{EXPLOITATION_ARTIFACTS_RELATIVE_DIR}"
    result_flag_path = f"/home/kali/workspace/{RESULT_FLAG_RELATIVE_PATH}"
    result_final_report_path = f"/home/kali/workspace/{RESULT_FINAL_REPORT_RELATIVE_PATH}"
    result_blocker_report_path = f"/home/kali/workspace/{RESULT_BLOCKER_REPORT_RELATIVE_PATH}"
    observation_merger_path = f"/home/kali/{OBSERVATION_MERGER_RELATIVE_PATH}"
    exploitation_index_merger_path = f"/home/kali/{EXPLOITATION_INDEX_MERGER_RELATIVE_PATH}"
    artifact_summarizer_path = f"/home/kali/{ARTIFACT_SUMMARIZER_RELATIVE_PATH}"
    challenge_mcp_enabled = bool(challenge.get("challenge_mcp_enabled"))
    challenge_mcp_lines = []
    if challenge_mcp_enabled:
        challenge_mcp_lines.extend(
            [
                "- challenge MCP 已启用；当前只开放 `submit_flag` 与 `view_hint`。",
                "- 题目入口点已经由 launcher 提供；不要尝试调用 `list_challenges`、`start_challenge`、`stop_challenge`，也不要把思路转向“先起题再拿入口”。",
                "- `view_hint` 只允许你这个 main agent 在明确阻塞时调用；不要下放给 subagent。",
                "- 任意 agent 一旦拿到完整、可复核、来源明确的候选 `flag{...}`，都必须立即调用 `mcp__platform__submit_flag`；不要等回到 main agent 再转交。",
                "- 只有 `submit_flag` 返回 `correct=true` 才算官方成功；一旦出现一次 `correct=true`，当前这次 run 就立即视为成功，不再继续追该题的其它 flag。",
                "- 如果 `submit_flag` 返回错误，不要再次提交同一个 flag；把它视为已拒绝候选，回到证据驱动分析，只在存在其它高价值向量或一个明确缺失事实时继续推进。",
                "- 任意 agent 收到 `correct=true` 后，都应立即写出最小结果文件 `/home/kali/workspace/.results/flag.txt` 与 `/home/kali/workspace/.results/final_report.md`，然后停止任务。",
                "- 如果某个 subagent 已提交成功，main agent 后续只负责停止重复调度与重复提交，不再继续该题。",
            ]
        )

    if agent_mode == "single":
        prompt_lines = [
            "你正在执行一个授权 Web CTF `find_flag` 任务。",
            "本轮使用**单智能体精简模式**：不要调用 `Task`，不要创建 subagent，不要套用多 agent 调度模板；你本人直接使用 `mcp__sandbox__*` 工具完成观察、验证、利用和最小落盘。",
            "",
            "核心原则：",
            "- 目标是找到并验证真实 `flag{...}`；不猜 flag，不把候选文件或本地 test flag 当成功。",
            "- 优先像人工解题一样推进：少量高信息量请求 -> 形成假设 -> 直接验证最高价值路径；不要把问题拆成大量报告分支。",
            "- 每个阶段只保留少量关键事实。大响应写入 `.artifacts/`，上下文只回传路径、状态、长度、hash、关键词命中和最多 20 行摘要。",
            f"- 遇到 `bootstrap` / `jquery` / `react` / `vue` / `*.min.js` / `*.min.css` / `chunk` / `bundle` 这类 vendor 资产，或任何超过 4KB 的 HTML/JS/CSS/JSON 正文时，先写入 artifact，再用 `{artifact_summarizer_path}` 生成摘要；不要把全文打回上下文。",
            "- 优先使用 `mcp__sandbox__python_exec` 进行 HTTP、解析、批量测试和文件写入；普通命令用 `mcp__sandbox__shell_exec`；默认不用交互式 `terminal_*`，除非确实需要 TTY 或长交互。",
            "- 如果 `python_exec` 对长脚本、结构化抓取或 JSON 生成发生非预期错误，把它视为环境故障并立即停止当前分支；不要把同一段长 Python 脚本降级塞进 `shell_exec`。",
            "- 不要反复 `Read` 整份大 JSON；需要状态时用 `python_exec` 提取少数字段。",
            "- 不要读取 `runtime_v2/*`、`.claude/projects/*.jsonl` 或 helper 源码来做任务决策。",
            "- 能 10 次请求验证的，不要开 50 次字典；payload/路径枚举必须有明确收益和停止条件。",
            "- 只有看到可复核证据，才确认漏洞或能力；文件可上传/可访问不等于代码执行，报错不等于漏洞成立。",
            "- 如果发现多个事实能组成利用链，只基于当前题已观察到的事实组合验证；不要套用固定技术路线。",
            "- 如果某个方向失败，先问：是否前置条件、连接条件、触发点、观测方式缺失；缺失则补最小验证，证据充分才放弃。",
            *challenge_mcp_lines,
            "",
            "输出约定：",
            f"- 题目信息：`{input_challenge_path}`",
            f"- 可选观察摘要：`{observation_report_path}`",
            f"- 可选利用总表：`{exploitation_master_report_path}`",
            f"- 成功后写：`{result_flag_path}` 与 `{result_final_report_path}`",
            f"- 阻塞才写：`{result_blocker_report_path}`",
            "- 报告只写最小必要信息；不要为了报告而消耗主要解题预算。",
            "",
            "当前题目：",
            f"- title: {challenge['challenge_title'] or '(未提供)'}",
            f"- code: {challenge['challenge_code']}",
            "- entrypoints:",
            entrypoint_lines,
            f"- server_host: {challenge['server_host'] or '(未提供)'}",
            f"- description: {challenge['challenge_description'] or '(未提供)'}",
            f"- hint: {challenge['challenge_hint'] or '(未提供)'}",
            "",
            "现在开始：先读取题目 JSON，然后直接解题；若拿到完整 flag 且 challenge MCP 可用，立即提交，`correct=true` 后立刻结束。",
        ]
        return "\n".join(prompt_lines)

    prompt_lines = [
        "你正在执行一个授权 Web CTF `find_flag` 任务。",
        "先读取 `~/.claude/CLAUDE.md` 并严格执行；这里只补充本轮题目与会话级参数。",
        "",
        "本轮会话级约束：",
        "- 固定状态机：`initial_observation -> targeted_exploitation -> optional_finalization`；只有 exploitation 明确缺少某个具体事实时，才允许一次 `supplemental_observation`。",
        "- 起步只允许 1 个 `observation-subagent`。",
        "- observation 一旦达到可利用 checkpoint，就应先结束当前轮并把主文件交回；不要为了“还能多收集一些背景”而继续独占时间片。",
        f"- exploitation 默认并发上限 {MAX_PARALLEL_EXPLOITATION}，全程 exploitation 子代理总数上限 {MAX_TOTAL_EXPLOITATION_SUBAGENTS}。",
        "- 创建 subagent 使用当前环境支持的 `Agent` / `Task`；继续同一条链必须优先 `SendMessage` 给已有 owner，不要机械新开 sibling。",
        "- 如果 `Agent` / `Task` tool_result 已返回 `agentId` 并提示可用 `SendMessage` 继续，把该 agent 视为这条链的默认 owner。",
        "- 如果当前环境支持 Agent Teams / resume，owner 暂停时优先恢复原 owner；只有无法继续时才新开 agent。",
        "- `supplemental_observation` 默认优先 `SendMessage` 继续原 observation owner，而不是新开 observation sibling。",
        "- 给 exploitation 派单时必须写清“只验证到哪一步就停止”；不要让 subagent 自行升级到更深验证。若你需要进一步探索，就用 `SendMessage` 唤醒同一 owner 并给新的窄任务说明。",
        "- `summary.priority_actions` 是候选队列，不是自动派单列表；新开 exploitation 前先做一次轻量四因子判断：证据强度、独立性/链路契合、预期收益、预计成本。",
        "- 默认只并行高收益且低/中成本的前 1-2 个动作；高噪声枚举、大范围 brute force、需要消化大量正文的动作，除非能闭合一条 `ready_for_validation` / `in_progress` 组合链，否则不要占用默认并行位。",
        "- 如果当前同时存在 2 个彼此独立且高价值的 exploitation 动作，先把这 2 个都派出去；不要串行等第 1 个结束后才决定第 2 个，除非第 2 个确实依赖第 1 个结果。",
        "- `targeted_exploitation` 起步优先做一轮广度优先的 initial exploitation wave：先让更多独立高价值向量完成首轮浅验证，再决定谁值得深挖。",
        "- 只要队列里还有尚未做首轮验证的高价值独立向量，就不要急着把并行位长期占给同一条链的深度 follow-up；优先补齐这些首轮 exploitation。",
        "- 只有当高价值独立向量的首轮验证基本完成，或某条链已出现强阳性信号并且再走一步就可能直接拿到 flag / file read / code exec 时，才优先深挖该链。",
        "- observation 达到 checkpoint 后的停止表示“本轮暂停并交棒”，不是 observation 生命周期终止；initial exploitation wave 启动后，要主动判断是否应 `SendMessage` 继续 observation owner。",
        "- 如果还存在未展开的独立 surface / atomic hypothesis、exploitation 返回了明确缺失事实、或当前 exploitation 队列未满且 observation 还能低成本补高价值事实，优先继续原 observation owner。",
        "- observation 审查优先看：`recommended_next_step` 与 `hypotheses[*].combines_with`。",
        "- exploitation 审查优先看总表：`summary.key_facts`、`summary.confirmed_capabilities`、`summary.composed_chains`、`summary.priority_actions`。",
        "- 新开 exploitation 分支前先确认：向量独立、detail 路径唯一、endpoint/参数/范围/停止条件能一句话说清。",
        "- `failed` / `blocked` / `exhausted` 不是终判；若缺少前提、连接条件、触发点或观测证据，把它视为 `attempted_but_incomplete`，优先继续同一 owner。",
        "- main agent 自己不执行 `mcp__sandbox__*`；HTTP、python、shell、terminal 都交给 subagent。",
        "- 非 finalization 阶段不读 `.results/*`；不要读取 `runtime_v2/*` 原始日志或 `.claude/projects/*.jsonl`。",
        "- helper 写完报告后不要整份回读；只有确实缺字段时再做按字段提取。",
        *challenge_mcp_lines,
        "",
        "关键路径：",
        f"- challenge: `{input_challenge_path}`",
        f"- observation: `{observation_report_path}`",
        f"- observation merge helper: `{observation_merger_path}`",
        f"- exploitation master: `{exploitation_master_report_path}`",
        f"- exploitation detail pattern: `{exploitation_detail_pattern_path}`",
        f"- exploitation merge helper: `{exploitation_index_merger_path}`",
        f"- artifact summarizer: `{artifact_summarizer_path}`",
        f"- observation artifacts: `{observation_artifacts_dir}`",
        f"- exploitation artifacts: `{exploitation_artifacts_dir}`",
        f"- results dir: `/home/kali/workspace/{RESULTS_DIR_NAME}/`",
        "",
        f"题目标题：{challenge['challenge_title']}",
        f"题目描述：{description}",
        f"题目提示：{hint}",
        f"目标主机：{challenge['target_host']}",
        f"题目标识：{challenge['challenge_code']}",
        "入口点：",
        entrypoint_lines,
        "",
        "现在开始：先读取 challenge JSON，再启动 1 个 `observation-subagent`。只要它产出第一个可利用 checkpoint，就立刻进入 exploitation 调度；若有两个独立高价值动作，优先并行派出，并先完成一轮广度优先的浅验证。checkpoint 不是 observation 的终局；后续若仍有未展开 surface 或明确缺失事实，优先继续同一 observation owner。",
    ]

    if challenge_mcp_enabled:
        prompt_lines.extend(["", f"比赛平台：{challenge['challenge_mcp_server']}"])

    return "\n".join(prompt_lines).strip()


def container_is_running(container_name: str) -> bool:
    result = run_command(
        [
            "docker",
            "inspect",
            "-f",
            "{{.State.Running}}",
            container_name,
        ],
        check=False,
    )
    return result.returncode == 0 and result.stdout.strip() == "true"


def docker_exec_python(container_name: str, script: str, *, check: bool = False) -> subprocess.CompletedProcess[str]:
    return run_command(
        ["docker", "exec", "-i", container_name, "/home/kali/python-terminal-mcp/.venv/bin/python", "-"],
        check=check,
        input_text=script,
    )


def wait_for_mcp(container_name: str, timeout_seconds: int, poll_interval_seconds: float) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if not container_is_running(container_name):
            logs = run_command(["docker", "logs", container_name], check=False).stdout
            raise SystemExit(f"Container exited before MCP was ready.\n{logs}")

        result = docker_exec_python(container_name, MCP_READY_SCRIPT, check=False)
        if result.returncode == 0:
            return
        time.sleep(poll_interval_seconds)

    logs = run_command(["docker", "logs", container_name], check=False).stdout
    raise SystemExit(f"MCP server did not become ready within {timeout_seconds} seconds.\n{logs}")


def verify_python_exec(container_name: str) -> None:
    result = docker_exec_python(container_name, PYTHON_EXEC_HEALTHCHECK_SCRIPT, check=False)
    if result.returncode == 0:
        return

    details = []
    if result.stderr and result.stderr.strip():
        details.append(result.stderr.strip())
    if result.stdout and result.stdout.strip():
        details.append(result.stdout.strip())
    logs = run_command(["docker", "logs", container_name], check=False).stdout.strip()
    if logs:
        details.append(logs)
    detail_text = "\n".join(part for part in details if part).strip() or "unknown error"
    raise SystemExit(f"python_exec health check failed before Claude started.\n{detail_text}")


def interrupt_claude(container_name: str) -> None:
    run_command(
        [
            "docker",
            "exec",
            container_name,
            "bash",
            "-lc",
            "pkill -INT -f 'claude' || true",
        ],
        check=False,
    )


def write_token_usage(container_name: str) -> None:
    command = (
        "if command -v ccusage >/dev/null 2>&1; then "
        "ccusage > /home/kali/workspace/token_usage.txt; "
        "else printf 'ccusage not available\\n' > /home/kali/workspace/token_usage.txt; "
        "fi"
    )
    run_command(
        ["docker", "exec", "-w", "/home/kali/workspace", container_name, "bash", "-lc", command],
        check=False,
    )


def archive_claude_home(container_name: str) -> None:
    command = """
set -e
workspace="/home/kali/workspace"
if [ -L /home/kali/.claude ]; then
  :
elif [ -d /home/kali/.claude ]; then
  rm -rf "${workspace}/.claude"
  cp -a /home/kali/.claude "${workspace}/.claude"
fi
if [ -f /home/kali/.claude.json ]; then
  mkdir -p "${workspace}/.claude"
  cp -a /home/kali/.claude.json "${workspace}/.claude/.claude.json"
fi
""".strip()
    run_command(
        ["docker", "exec", "-w", "/home/kali/workspace", container_name, "bash", "-lc", command],
        check=False,
    )


def stop_container(container_name: str) -> None:
    run_command(["docker", "stop", "-t", "5", container_name], check=False)


def container_start_script() -> str:
    return """
set -euo pipefail
workspace="${WORKSPACE_DIR:-/home/kali/workspace}"
app_home="${APP_HOME:-/home/kali/python-terminal-mcp}"
runtime_dir="${PYTHON_TERMINAL_MCP_RUNTIME_DIR:-${workspace}/runtime_v2}"
host="${PYTHON_TERMINAL_MCP_HOST:-0.0.0.0}"
port="${PYTHON_TERMINAL_MCP_PORT:-8000}"
python_bin="${PYTHON_TERMINAL_MCP_PYTHON:-${app_home}/.venv/bin/python}"

mkdir -p "${workspace}" "${runtime_dir}" "${workspace}/.claude"
mkdir -p "${workspace}/.inputs" "${workspace}/.artifacts/observation" "${workspace}/.artifacts/exploitation" "${workspace}/.results"
mkdir -p "${workspace}/reports/exploitation"
rm -rf "${HOME}/.claude"
ln -s "${workspace}/.claude" "${HOME}/.claude"
cd "${workspace}"

exec "${python_bin}" "${app_home}/app/python_terminal_mcp.py" \
  --host "${host}" \
  --port "${port}" \
  --runtime-dir "${runtime_dir}" \
  --workspace-dir "${workspace}" \
  --allow-remote
""".strip()


def build_run_command(
    args: argparse.Namespace,
    container_name: str,
    task_dir: Path,
    challenge: dict[str, object],
    runtime_env: dict[str, str],
) -> list[str]:
    command = ["docker", "run", "-d", "--rm", "--name", container_name]
    if args.docker_platform:
        command.extend(["--platform", args.docker_platform])
    if args.debug_mcp_port is not None:
        command.extend(["-p", f"{args.debug_mcp_port}:8000"])
    command.extend(["-v", f"{task_dir}:/home/kali/workspace"])

    challenge_env = {
        "CHALLENGE_CODE": str(challenge["challenge_code"]),
        "CHALLENGE_ENTRYPOINT": ",".join(str(item) for item in challenge["challenge_entrypoints"]),
    }
    server_host_value = str(challenge["server_host"])
    if server_host_value:
        challenge_env["SERVER_HOST"] = server_host_value
    if challenge["challenge_title"]:
        challenge_env["CHALLENGE_TITLE"] = str(challenge["challenge_title"])
    if challenge["challenge_description"]:
        challenge_env["CHALLENGE_DESCRIPTION"] = str(challenge["challenge_description"])
    if challenge["challenge_hint"]:
        challenge_env["CHALLENGE_HINT"] = str(challenge["challenge_hint"])

    for key, value in challenge_env.items():
        command.extend(["-e", f"{key}={value}"])
    for key in CLAUDE_ENV_KEYS:
        value = runtime_env.get(key)
        if value:
            command.extend(["-e", f"{key}={value}"])
    command.extend(["-e", f"{AGENT_TEAMS_ENV_NAME}={AGENT_TEAMS_ENV_VALUE}"])

    command.append(args.image)
    command.extend(["bash", "-c", container_start_script()])
    return command


SANDBOX_TOOL_NAMES = (
    "mcp__sandbox__python_exec",
    "mcp__sandbox__python_get",
    "mcp__sandbox__python_output",
    "mcp__sandbox__python_interrupt",
    "mcp__sandbox__python_restart",
    "mcp__sandbox__python_session_info",
    "mcp__sandbox__shell_exec",
    "mcp__sandbox__terminal_open",
    "mcp__sandbox__terminal_info",
    "mcp__sandbox__terminal_read",
    "mcp__sandbox__terminal_write",
    "mcp__sandbox__terminal_interrupt",
    "mcp__sandbox__terminal_close",
    "mcp__sandbox__list_agent_runtimes",
    "mcp__sandbox__cleanup_agent_runtime",
)


def build_claude_shell_command(*, challenge_mcp_enabled: bool = False, agent_mode: str = "orchestrated") -> str:
    base_tools = ["Read", "Grep", "Glob"]
    if agent_mode == "orchestrated":
        base_tools = ["Agent", "Task", "SendMessage", *base_tools]
    platform_tool_names: list[str] = []
    if challenge_mcp_enabled:
        platform_tool_names = ["mcp__platform__submit_flag", "mcp__platform__view_hint"]

    if agent_mode == "single":
        visible_tools = [*base_tools, *SANDBOX_TOOL_NAMES, *platform_tool_names]
        allowed_tools = [*base_tools, *SANDBOX_TOOL_NAMES, *platform_tool_names]
    else:
        visible_tools = [*base_tools, *platform_tool_names]
        allowed_tools = [*base_tools, *SANDBOX_TOOL_NAMES, *platform_tool_names]

    tools = ",".join(visible_tools)
    allowed_tools_text = " ".join(allowed_tools)
    return (
        f"export {AGENT_TEAMS_ENV_NAME}={AGENT_TEAMS_ENV_VALUE} && "
        "claude --verbose "
        "--mcp-config /home/kali/.claude/mcp.json "
        "--strict-mcp-config "
        f'--tools "{tools}" '
        f'--allowedTools "{allowed_tools_text}" '
        '--disallowedTools "Bash Write Edit MultiEdit WebFetch WebSearch NotebookRead NotebookEdit LS" '
        '-p "$(cat)"'
    )


def run_claude_task(
    container_name: str,
    prompt: str,
    timeout_seconds: int,
    *,
    challenge_mcp_enabled: bool = False,
    agent_mode: str = "orchestrated",
) -> tuple[int, bool]:
    command = [
        "docker",
        "exec",
        "-i",
        "-w",
        "/home/kali/workspace",
        container_name,
        "bash",
        "-c",
        build_claude_shell_command(challenge_mcp_enabled=challenge_mcp_enabled, agent_mode=agent_mode),
    ]
    process = subprocess.Popen(command, stdin=subprocess.PIPE, text=True)
    try:
        process.communicate(prompt, timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        print(f"[!] Claude task timed out after {timeout_seconds} seconds.", file=sys.stderr)
        interrupt_claude(container_name)
        try:
            process.communicate(timeout=GRACEFUL_CLAUDE_INTERRUPT_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            return 124, True
        return process.returncode or 124, True
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user, stopping Claude...", file=sys.stderr)
        interrupt_claude(container_name)
        process.kill()
        process.communicate()
        return 130, False
    return process.returncode or 0, False


def read_flag_result(task_dir: Path) -> str | None:
    flag_path = task_dir / RESULT_FLAG_RELATIVE_PATH
    if not flag_path.is_file():
        return None
    try:
        content = flag_path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if FLAG_PATTERN.fullmatch(content):
        return content
    return None


def iter_json_strings(value: object) -> list[str]:
    items: list[str] = []

    def visit(node: object) -> None:
        if isinstance(node, str):
            items.append(node)
        elif isinstance(node, dict):
            for child in node.values():
                visit(child)
        elif isinstance(node, list):
            for child in node:
                visit(child)

    visit(value)
    return items


def collect_json_keyed_strings(value: object, *, key_names: set[str]) -> list[str]:
    items: list[str] = []

    def visit(node: object) -> None:
        if isinstance(node, dict):
            for key, child in node.items():
                lowered = str(key).lower()
                if lowered in key_names and isinstance(child, str):
                    items.append(child)
                visit(child)
        elif isinstance(node, list):
            for child in node:
                visit(child)

    visit(value)
    return items


def extract_fallback_flag_from_observation(task_dir: Path) -> dict[str, object] | None:
    report_path = task_dir / OBSERVATION_REPORT_RELATIVE_PATH
    if not report_path.is_file():
        return None
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    direct_flag_values = collect_json_keyed_strings(report, key_names={"flag"})
    candidate_flags = sorted({match.group(0) for value in direct_flag_values for match in FLAG_PATTERN.finditer(value)})
    if not candidate_flags:
        candidate_flags = sorted(
            {
                match.group(0)
                for value in iter_json_strings(report)
                for match in FLAG_PATTERN.finditer(value)
            }
        )
    if len(candidate_flags) != 1:
        return None

    evidence_candidates = collect_json_keyed_strings(report, key_names={"path", "evidence_path", "artifact", "artifacts"})
    evidence_paths: list[str] = []
    for item in evidence_candidates:
        if item.startswith("/home/kali/workspace/") or item.startswith(".artifacts/"):
            evidence_paths.append(item)
    evidence_paths = list(dict.fromkeys(evidence_paths))
    if not evidence_paths:
        return None

    vulnerability = ""
    hypotheses = report.get("hypotheses")
    if isinstance(hypotheses, list):
        for item in hypotheses:
            if isinstance(item, dict):
                vulnerability = str(item.get("type") or item.get("family") or item.get("description") or "").strip()
                if vulnerability:
                    break

    target = str(report.get("target") or "").strip()
    return {
        "flag": candidate_flags[0],
        "report_path": str(report_path),
        "evidence_paths": evidence_paths[:5],
        "vulnerability": vulnerability,
        "target": target,
    }


def auto_finalize_from_observation(task_dir: Path, challenge: dict[str, object]) -> str | None:
    if challenge.get("challenge_mcp_enabled"):
        return None
    fallback = extract_fallback_flag_from_observation(task_dir)
    if not fallback:
        return None

    results_dir = task_dir / RESULTS_DIR_NAME
    results_dir.mkdir(parents=True, exist_ok=True)
    flag_value = str(fallback["flag"])
    evidence_paths = [str(item) for item in fallback["evidence_paths"]]
    vulnerability = str(fallback.get("vulnerability") or "Observation-derived finding").strip()
    target = str(fallback.get("target") or challenge.get("target_host") or "").strip()

    (results_dir / "flag.txt").write_text(f"{flag_value}\n", encoding="utf-8")

    evidence_lines = "\n".join(f"- `{path}`" for path in evidence_paths) or "- 未记录"
    report_text = f"""# Auto Finalization Report

## Summary
- Challenge: `{challenge["challenge_code"]}`
- Title: {challenge["challenge_title"]}
- Target: {target or "未提供"}
- Reason: Claude task ended before finalization completed, but observation report already contained one unique flag candidate with evidence.

## Flag
```
{flag_value}
```

## Source
- Observation report: `{fallback["report_path"]}`
- Vulnerability / finding: {vulnerability}

## Evidence
{evidence_lines}

## Status
SUCCESS (launcher fallback finalization from observation evidence)
"""
    (results_dir / "final_report.md").write_text(report_text.strip() + "\n", encoding="utf-8")
    return flag_value


def has_complete_final_results(task_dir: Path) -> tuple[bool, str | None]:
    flag_value = read_flag_result(task_dir)
    report_path = task_dir / RESULT_FINAL_REPORT_RELATIVE_PATH
    if not flag_value:
        return False, None
    if not report_path.is_file():
        return False, None
    try:
        report_text = report_path.read_text(encoding="utf-8")
    except OSError:
        return False, None
    if not report_text.strip():
        return False, None
    if flag_value not in report_text:
        return False, None
    return True, flag_value


def main() -> int:
    args = parse_args()
    ensure_image_exists(args.image)
    runtime_env = load_runtime_env()
    challenge = load_challenge(runtime_env, enable_challenge_mcp=args.enable_challenge_mcp)

    workspace_root = (REPO_ROOT / args.workspace_root).resolve()
    workspace_root.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%m%d-%H%M%S")
    title_slug = slugify_title(str(challenge["challenge_title"]))
    task_dir = workspace_root / f"{timestamp}-{title_slug}"
    task_dir.mkdir(parents=True, exist_ok=False)
    initialize_task_dirs(task_dir)
    write_challenge_snapshot(task_dir, challenge)
    initialize_workspace_claude_config(task_dir)
    write_claude_mcp_config(task_dir, runtime_env, challenge)
    ensure_canonical_observation_report(task_dir, archive_noncanonical=False)
    ensure_exploitation_report_index(task_dir)

    container_name = docker_name(f"ccctfer-{timestamp}-{challenge['challenge_code']}")
    try:
        run_command(build_run_command(args, container_name, task_dir, challenge, runtime_env))
    except subprocess.CalledProcessError as error:
        raise SystemExit(f"Failed to start container:\n{format_process_error(error)}") from error

    print(f"[+] Task workspace: {task_dir}")
    print(f"[+] Container: {container_name}")

    exit_code = 1
    try:
        wait_for_mcp(container_name, args.ready_timeout_seconds, args.poll_interval_seconds)
        verify_python_exec(container_name)
        print("[+] MCP server and python_exec are ready, starting Claude task...")
        prompt = build_prompt(challenge, agent_mode=args.agent_mode)
        exit_code, timed_out = run_claude_task(
            container_name,
            prompt,
            args.timeout_seconds,
            challenge_mcp_enabled=bool(challenge.get("challenge_mcp_enabled")),
            agent_mode=args.agent_mode,
        )
        repaired_observation = ensure_canonical_observation_report(task_dir, archive_noncanonical=True)
        if repaired_observation:
            print("[+] Repaired non-canonical observation report into canonical schema.")
        if reconcile_exploitation_report_index(task_dir):
            print("[+] Reconciled exploitation report index from detail reports.")
        completed_with_results, final_flag = has_complete_final_results(task_dir)
        if exit_code != 0 and not completed_with_results:
            fallback_flag = auto_finalize_from_observation(task_dir, challenge)
            if fallback_flag:
                completed_with_results, final_flag = has_complete_final_results(task_dir)
                if completed_with_results:
                    if timed_out:
                        print(
                            f"[+] Claude task timed out before finalization, but observation already contained one unique flag with evidence; launcher auto-finalized results ({final_flag})."
                        )
                    else:
                        print(
                            f"[+] Claude task exited with code {exit_code}, but observation already contained one unique flag with evidence; launcher auto-finalized results ({final_flag})."
                        )
        if exit_code != 0 and completed_with_results:
            if timed_out:
                print(
                    f"[+] Claude task timed out after finalization, but result files are complete; treating run as success ({final_flag})."
                )
            else:
                print(f"[+] Claude task exited with code {exit_code}, but complete result files were found; treating run as success ({final_flag}).")
            exit_code = 0
        if exit_code == 0:
            print("[+] Claude task completed.")
        else:
            print(f"[!] Claude task exited with code {exit_code}.", file=sys.stderr)
        return exit_code
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user during setup.", file=sys.stderr)
        exit_code = 130
        return exit_code
    finally:
        if container_is_running(container_name):
            print("[+] Writing token usage report...")
            write_token_usage(container_name)
            print("[+] Archiving Claude home for audit...")
            archive_claude_home(container_name)
        print("[+] Cleaning up container...")
        stop_container(container_name)
        try:
            if reconcile_exploitation_report_index(task_dir):
                print("[+] Reconciled exploitation report index from detail reports.")
        except Exception as exc:
            print(f"[!] Failed to reconcile exploitation report index: {exc}", file=sys.stderr)
        print("[+] Normalizing workspace layout...")
        sanitize_task_workspace(task_dir)
        print(f"[+] Minimal artifacts kept under: {task_dir}")


if __name__ == "__main__":
    sys.exit(main())
