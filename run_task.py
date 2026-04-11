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
DEFAULT_EXPLOITATION_REPORT_RELATIVE_PATH = f"{EXPLOITATION_REPORTS_RELATIVE_DIR}/exploitation_report.json"
OBSERVATION_ARTIFACTS_RELATIVE_DIR = f"{ARTIFACTS_DIR_NAME}/{OBSERVATION_ARTIFACTS_DIR_NAME}"
EXPLOITATION_ARTIFACTS_RELATIVE_DIR = f"{ARTIFACTS_DIR_NAME}/{EXPLOITATION_REPORTS_DIR_NAME}"
RESULT_FLAG_RELATIVE_PATH = f"{RESULTS_DIR_NAME}/flag.txt"
RESULT_FINAL_REPORT_RELATIVE_PATH = f"{RESULTS_DIR_NAME}/final_report.md"
RESULT_BLOCKER_REPORT_RELATIVE_PATH = f"{RESULTS_DIR_NAME}/blocker_report.md"
RESULT_CLAUDE_OUTPUT_RELATIVE_PATH = f"{RESULTS_DIR_NAME}/claude_output.txt"
OBSERVATION_MERGER_RELATIVE_PATH = ".claude/tools/manage_observation_report.py"
MAX_PARALLEL_EXPLOITATION = 2
MAX_TOTAL_EXPLOITATION_SUBAGENTS = 4
MAX_CONSECUTIVE_EMPTY_TERMINAL_READS = 3
MAX_TERMINAL_READ_CALLS = 40
MAX_INLINE_TOOL_OUTPUT_BYTES = 4096
MAX_INLINE_TOOL_OUTPUT_LINES = 20
GRACEFUL_CLAUDE_INTERRUPT_SECONDS = 10

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


def build_prompt(challenge: dict[str, object]) -> str:
    entrypoints = challenge["challenge_entrypoints"]
    entrypoint_lines = "\n".join(f"- {item}" for item in entrypoints) if entrypoints else "- (none provided)"
    description = str(challenge["challenge_description"]).strip() or "未提供"
    hint = str(challenge["challenge_hint"]).strip() or "未提供"
    input_challenge_path = f"/home/kali/workspace/{INPUT_CHALLENGE_RELATIVE_PATH}"
    observation_report_path = f"/home/kali/workspace/{OBSERVATION_REPORT_RELATIVE_PATH}"
    default_exploitation_report_path = f"/home/kali/workspace/{DEFAULT_EXPLOITATION_REPORT_RELATIVE_PATH}"
    observation_artifacts_dir = f"/home/kali/workspace/{OBSERVATION_ARTIFACTS_RELATIVE_DIR}"
    exploitation_artifacts_dir = f"/home/kali/workspace/{EXPLOITATION_ARTIFACTS_RELATIVE_DIR}"
    result_flag_path = f"/home/kali/workspace/{RESULT_FLAG_RELATIVE_PATH}"
    result_final_report_path = f"/home/kali/workspace/{RESULT_FINAL_REPORT_RELATIVE_PATH}"
    result_blocker_report_path = f"/home/kali/workspace/{RESULT_BLOCKER_REPORT_RELATIVE_PATH}"
    challenge_mcp_enabled = bool(challenge.get("challenge_mcp_enabled"))
    challenge_mcp_lines = []
    if challenge_mcp_enabled:
        challenge_mcp_lines.extend(
            [
                "- challenge MCP 已启用；当前只开放 `submit_flag` 与 `view_hint`，并且只允许你这个 main agent 调用，禁止下放给 subagent。",
                "- 题目入口点已经由 launcher 提供；不要尝试调用 `list_challenges`、`start_challenge`、`stop_challenge`，也不要把思路转向“先起题再拿入口”。",
                "- 只有 exploitation 带回完整、可复核、来源明确的候选 `flag{...}` 后，你才可以调用 `mcp__platform__submit_flag`。",
                "- 只有 `submit_flag` 返回 `correct=true` 才算官方成功；如果平台还有剩余 flag，继续当前题目，不要提前收工。",
                "- `view_hint` 只允许在你明确判定当前题目已经阻塞时调用。",
            ]
        )

    prompt_lines = [
        "你正在执行一个授权 Web CTF `find_flag` 任务。",
        "先读取 `~/.claude/CLAUDE.md`，并严格按其中规则工作；不要在这里重复整份模板。",
        "",
        "本次额外预算与调度约束：",
        "- 固定状态机：`initial_observation -> targeted_exploitation -> optional_finalization`；只有 exploitation 明确指出缺少某个具体事实时，才允许一次 `supplemental_observation`。",
        "- 起步只允许 1 个 `observation-subagent`。",
        f"- `exploitation-subagent` 默认单线程；只有 `reports/observation_report.json` 明确给出 2 个彼此独立且高价值的向量时，才允许并行到 {MAX_PARALLEL_EXPLOITATION} 个；全程 exploitation 子代理总数不得超过 {MAX_TOTAL_EXPLOITATION_SUBAGENTS} 个。",
        "- 只允许调度 `observation-subagent` 与 `exploitation-subagent`；不要使用 `general-purpose` 或其它未约束角色。",
        "- `深度信息搜集` 不是自由扩张阶段；它只能作为一次有明确目标的 supplemental observation。",
        "- 派单文字必须短，只给：目标、允许输入、禁止事项、输出路径、预算；不要复制整份规则给 subagent。",
        f"- subagent 优先使用 `mcp__sandbox__python_exec` 做 HTTP 抓取、解析和结构化输出；`terminal_*` 只用于确实需要 TTY 或交互式命令的场景。",
        f"- 如果 `terminal_read` 返回 `should_stop_polling=true`、`read_budget_exhausted=true`，或同一 cursor 连续空读达到 {MAX_CONSECUTIVE_EMPTY_TERMINAL_READS} 次，就立刻停止该 polling 分支，把控制权交回 main agent。",
        f"- 单个 terminal 会话的 `terminal_read` 总次数预算是 {MAX_TERMINAL_READ_CALLS}；不要为等待长任务而高频空轮询。",
        f"- 任何原始响应、源码、HTML、JS、CSS、命令输出超过 {MAX_INLINE_TOOL_OUTPUT_BYTES} bytes，都只允许落盘到 `.artifacts/` 或 runtime log；回报时只给 `path/status/content-type/bytes/sha256/≤{MAX_INLINE_TOOL_OUTPUT_LINES}行摘要`。",
        "- `bootstrap`、`jquery`、minified JS/CSS 等 vendor 文件，默认禁止全文回灌上下文；只有命中目标关键词时才提取局部片段。",
        "- `status>=400` 或标准 HTML 404 页面只能记入 `negative_findings`，不得写成 `Found`，也不得直接升级为 exploitation。",
        f"- main agent 只允许在阶段切换或 `reports/observation_report.json` 完成 merge 后重新读取它；不要每轮都全文重读。",
        f"- 非 finalization 阶段不得读取 `{result_flag_path}`、`{result_final_report_path}`、`{result_blocker_report_path}`；finalization 最多只允许发生一次。",
        "- 如果 observation 被动直接发现了完整 flag，可以跳过额外验证；但最终写 `.results/flag.txt` 与 `.results/final_report.md` 的任务仍必须交给 `exploitation-subagent`。",
        *challenge_mcp_lines,
        "",
        "规范路径：",
        f"- challenge: `{input_challenge_path}`",
        f"- observation: `{observation_report_path}`",
        f"- default exploitation: `{default_exploitation_report_path}`",
        f"- observation artifacts: `{observation_artifacts_dir}`",
        f"- exploitation artifacts: `{exploitation_artifacts_dir}`",
        f"- final results: `/home/kali/workspace/{RESULTS_DIR_NAME}/`",
        "",
        f"题目标题：{challenge['challenge_title']}",
        f"题目描述：{description}",
        f"题目提示：{hint}",
        f"目标主机：{challenge['target_host']}",
        f"题目标识：{challenge['challenge_code']}",
        "入口点：",
        entrypoint_lines,
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

    command.append(args.image)
    command.extend(["bash", "-c", container_start_script()])
    return command


def build_claude_shell_command(*, challenge_mcp_enabled: bool = False) -> str:
    tools = "Task,Read,Grep,Glob"
    platform_tools = ""
    if challenge_mcp_enabled:
        tools += ",mcp__platform__submit_flag,mcp__platform__view_hint"
        platform_tools = " mcp__platform__submit_flag mcp__platform__view_hint"

    output_path = shlex.quote(f"/home/kali/workspace/{RESULT_CLAUDE_OUTPUT_RELATIVE_PATH}")
    return (
        "set -o pipefail; "
        "claude --verbose "
        "--mcp-config /home/kali/.claude/mcp.json "
        "--strict-mcp-config "
        f'--tools "{tools}" '
        '--allowedTools "Task Read Grep Glob '
        'mcp__sandbox__python_exec mcp__sandbox__python_get mcp__sandbox__python_output '
        'mcp__sandbox__python_interrupt mcp__sandbox__python_restart mcp__sandbox__python_session_info '
        'mcp__sandbox__terminal_open mcp__sandbox__terminal_info mcp__sandbox__terminal_read '
        'mcp__sandbox__terminal_write mcp__sandbox__terminal_interrupt mcp__sandbox__terminal_close '
        f'mcp__sandbox__list_agent_runtimes mcp__sandbox__cleanup_agent_runtime{platform_tools}" '
        '--disallowedTools "Bash Write Edit MultiEdit WebFetch WebSearch NotebookRead NotebookEdit LS" '
        f'-p "$(cat)" 2>&1 | tee {output_path}'
    )


def run_claude_task(
    container_name: str,
    prompt: str,
    timeout_seconds: int,
    *,
    challenge_mcp_enabled: bool = False,
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
        build_claude_shell_command(challenge_mcp_enabled=challenge_mcp_enabled),
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
    if re.fullmatch(r"flag\{[^\r\n]+\}", content):
        return content
    return None


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
        print("[+] MCP server is ready, starting Claude task...")
        prompt = build_prompt(challenge)
        exit_code, timed_out = run_claude_task(
            container_name,
            prompt,
            args.timeout_seconds,
            challenge_mcp_enabled=bool(challenge.get("challenge_mcp_enabled")),
        )
        completed_with_results, final_flag = has_complete_final_results(task_dir)
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
        print("[+] Normalizing workspace layout...")
        sanitize_task_workspace(task_dir)
        print(f"[+] Minimal artifacts kept under: {task_dir}")


if __name__ == "__main__":
    sys.exit(main())
