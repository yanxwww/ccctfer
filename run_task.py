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
PLATFORM_MCP_AUTH_MODE_ENV = "PLATFORM_MCP_AUTH_MODE"
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
OBSERVATION_MERGER_RELATIVE_PATH = ".claude/tools/manage_observation_report.py"

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


def normalize_platform_server_base_url(server_host: str) -> str:
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


def normalize_platform_auth_mode(value: str | None) -> str:
    normalized = (value or "bearer").strip().lower().replace("_", "-")
    if normalized not in {"bearer", "agent-token"}:
        raise SystemExit(
            f"Unsupported {PLATFORM_MCP_AUTH_MODE_ENV} value: {value!r}. "
            "Use 'bearer' or 'agent-token'."
        )
    return normalized


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


def load_challenge(runtime_env: dict[str, str]) -> dict[str, object]:
    raw_entrypoints = require_runtime_value(runtime_env, "CHALLENGE_ENTRYPOINT")
    entrypoints = [item.strip() for item in raw_entrypoints.split(",") if item.strip()]
    if not entrypoints:
        raise SystemExit("CHALLENGE_ENTRYPOINT did not contain any usable entrypoints.")

    target_host = entrypoints[0]
    platform_server_host = get_runtime_value(runtime_env, "SERVER_HOST") or ""
    agent_token = get_runtime_value(runtime_env, "AGENT_TOKEN")
    raw_challenge_code = get_runtime_value(runtime_env, "CHALLENGE_CODE")
    platform_tools_enabled = bool(platform_server_host and agent_token and raw_challenge_code)
    challenge_title = maybe_decode_text(get_runtime_value(runtime_env, "CHALLENGE_TITLE"))
    if not challenge_title:
        challenge_title = default_title_from_entrypoint(entrypoints, target_host)

    challenge_code = raw_challenge_code or slugify_title(challenge_title)
    challenge_description = maybe_decode_text(get_runtime_value(runtime_env, "CHALLENGE_DESCRIPTION"))
    challenge_hint = maybe_decode_text(get_runtime_value(runtime_env, "CHALLENGE_HINT"))
    challenge = {
        "server_host": target_host,
        "target_host": target_host,
        "platform_server_host": platform_server_host,
        "challenge_code": challenge_code,
        "challenge_entrypoints": entrypoints,
        "challenge_title": challenge_title,
        "challenge_description": challenge_description,
        "challenge_hint": challenge_hint,
        "has_agent_token": bool(agent_token),
        "platform_tools_enabled": platform_tools_enabled,
        "platform_auth_mode": (
            normalize_platform_auth_mode(get_runtime_value(runtime_env, PLATFORM_MCP_AUTH_MODE_ENV))
            if platform_tools_enabled
            else ""
        ),
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


def build_platform_mcp_server(runtime_env: dict[str, str], challenge: dict[str, object]) -> dict[str, object] | None:
    platform_server_host = str(challenge.get("platform_server_host") or "").strip()
    agent_token = get_runtime_value(runtime_env, "AGENT_TOKEN")
    raw_challenge_code = get_runtime_value(runtime_env, "CHALLENGE_CODE")
    if not (platform_server_host and agent_token and raw_challenge_code):
        return None

    auth_mode = normalize_platform_auth_mode(get_runtime_value(runtime_env, PLATFORM_MCP_AUTH_MODE_ENV))
    headers = (
        {"Authorization": f"Bearer {agent_token}"}
        if auth_mode == "bearer"
        else {"Agent-Token": agent_token}
    )
    return {
        "type": "http",
        "url": f"{normalize_platform_server_base_url(platform_server_host)}/mcp",
        "headers": headers,
    }


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
    platform_server = build_platform_mcp_server(runtime_env, challenge)
    if platform_server:
        config["mcpServers"]["platform"] = platform_server

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
    observation_merger_path = f"/home/kali/workspace/{OBSERVATION_MERGER_RELATIVE_PATH}"
    platform_tools_enabled = bool(challenge.get("platform_tools_enabled"))
    main_tools_text = "`Task`（运行日志中也可能显示为 `Agent`）、`Read`、`Grep`、`Glob`"
    if platform_tools_enabled:
        main_tools_text += "，以及 `mcp__platform__submit_flag`、`mcp__platform__view_hint`、`mcp__platform__stop_challenge`"
    platform_rules = f"""
- 比赛平台工具只对你这个 main agent 开放；禁止把 `mcp__platform__submit_flag`、`mcp__platform__view_hint`、`mcp__platform__stop_challenge` 下放给任何 subagent。
- 只有当 exploitation 带回了完整、可复核、来源明确的候选 `flag{{...}}` 后，你才可以亲自调用 `mcp__platform__submit_flag`。
- 只有 `mcp__platform__submit_flag` 返回 `correct=true`，才允许认定“官方判定成功”；本地 `flag.txt`、`final_report.md`、候选片段、测试文件都不是官方成功信号。
- 如果题目存在多个 flag，只有当平台返回的 `flag_got_count == flag_count` 时，才允许把整道题判定为完成；否则继续当前题目，不要提前收工。
- `mcp__platform__view_hint` 只允许在你明确判定“当前题目已阻塞”后调用；不要让 subagent 决定是否看提示。
- `mcp__platform__stop_challenge` 只允许在任务结束、明确放弃或已经官方判定成功后调用。
""".strip()
    platform_workflow_steps = f"""
11. 如果 exploitation 带回了候选完整 flag，你必须亲自调用 `mcp__platform__submit_flag` 做官方判定。
12. 只有平台确认正确后，你才可以认定成功，并再指派合适的 `exploitation-subagent` 将 `flag.txt` 和 `final_report.md` 写入结果目录。
13. 如果平台返回不正确，必须继续当前题目的证据驱动分析，不能把候选 flag 当作成功。
14. 如果你明确判定当前题目已阻塞，才可以亲自调用 `mcp__platform__view_hint`；拿到提示后继续调度，不要让 subagent 直接看提示。
15. 在任务结束、明确放弃或已官方判定成功后，你可以亲自调用 `mcp__platform__stop_challenge` 做收尾。
16. 如果最终未找到 flag，则指派合适的 `exploitation-subagent` 写入 `{result_blocker_report_path}`。
""".strip()
    platform_context = f"""
比赛平台：
{challenge["platform_server_host"]}

平台认证模式：
{challenge["platform_auth_mode"]}
""".strip()
    return f"""
你正在执行一个授权 CTF Web `find_flag` 任务。
你的身份是 **main agent**，只负责：读取上下文、制定计划、调度 subagent、审核证据、做最终判定。
你不是执行者，禁止亲自做信息搜集、漏洞验证或漏洞利用。

先执行以下硬性规则，禁止偏离：
- 第一件事必须是读取 `~/.claude/CLAUDE.md`。
- 你当前只应该使用 {main_tools_text}。
- 你不能亲自发请求、跑命令、运行 Python、做网络探测、写结果文件。
- 所有外部交互、命令执行、Python 执行、HTTP 请求、文件写入，都必须由 subagent 通过 `mcp__sandbox__*` 完成，以确保 `runtime_v2` 保留完整审计。
- `Task`（运行日志中也可能显示为 `Agent`）只用于调度 subagent，不要把它当成分析结论的替代品。
- 禁止猜测 flag、补全 flag、脑补漏洞、脑补隐藏接口、脑补返回内容。
- 只有拿到完整、可复核、来源明确的 `flag{{...}}` 原文，才可以认定“找到 flag”。
- 如果只是拿到疑似片段、页面提示、推测结果、历史缓存、他人结论，都不能当作最终 flag。
- 如果证据不足，请明确说明“未找到 flag / 当前阻塞原因”，不要编造结论。
- 不要扫描无关 IP、无关端口、无关域名；仅允许围绕题目提供的 entrypoint、同源重定向和解题必需的直接关联资源行动。
- 固定只使用这些规范路径：题目信息在 `{input_challenge_path}`，observation 主文件在 `{observation_report_path}`，exploitation 结果默认在 `/home/kali/workspace/{EXPLOITATION_REPORTS_RELATIVE_DIR}/`，最终结果只能写入 `/home/kali/workspace/{RESULTS_DIR_NAME}/`。
- 除非某份规范报告明确引用某个 artifact 路径，否则不要主动扫描 `/home/kali/workspace/{ARTIFACTS_DIR_NAME}/` 下的临时文件，也不要用 `Glob` / `Grep` 枚举它。
- 任何位于工作区根目录或 `{ARTIFACTS_DIR_NAME}/` 下的 `*flag*.txt`、`*report*.md`、`test_*.txt`、临时脚本、样例文件，都不是规范结果文件；不要把它们当作可信输入。
- 在最终落盘前，不要主动读取 `{result_flag_path}`、`{result_final_report_path}`、`{result_blocker_report_path}`；这些路径只有在你明确派发“最终落盘”任务后才应出现有效内容。
- 在最终落盘前，不要用 `Glob` / `Grep` 枚举 `/home/kali/workspace/{RESULTS_DIR_NAME}/`；如果当前没有最终落盘任务，就把这个目录视为不可触碰。
{platform_rules if platform_tools_enabled else ""}

角色分工必须保持清晰：
- `observation-subagent`：唯一可以做大规模信息搜集、攻击面梳理、线索提取的执行者。
- `exploitation-subagent`：只负责单个漏洞假设 / 单个能力目标的最小验证与受控利用。
- 只有在已有一个或多个“已验证成功”的能力 / 原语时，你才可以指派 `exploitation-subagent` 做组合利用。
- 你自己永远不允许做 observation、验证或利用。
- `observation-subagent` 不能做漏洞测试；如果某个动作是在“通过 payload / 输入变化证明漏洞成立”，那就必须交给 `exploitation-subagent`。
- `observation-subagent` 如果只是在允许的 observation 动作中被动直接发现了完整 flag，可以如实上报；但它不能为了拿 flag 主动升级成利用。
- 已验证假设、已验证能力、利用结论默认保留在 `{default_exploitation_report_path}` 或 `/home/kali/workspace/{EXPLOITATION_REPORTS_RELATIVE_DIR}/exploitation_*.json`；是否把新的客观事实回流到 `{observation_report_path}`，只能由你决定。
- subagent 不得调用任何比赛平台工具；平台相关的提交、提示、停题都只能由你亲自执行。

强制工作流：
1. 读取 `~/.claude/CLAUDE.md`、`{input_challenge_path}`，以及当前已经存在的规范报告文件；不要一开始就扫描整个工作区，也不要枚举 `{ARTIFACTS_DIR_NAME}` 或 `{RESULTS_DIR_NAME}`。
2. 必须先调用 `observation-subagent` 生成并维护 `{observation_report_path}`。
3. `{observation_report_path}` 是默认且唯一的 observation 主文件；不要为了常规补充 observation 而制造多个工作文件。
4. 只有在你明确需要保留审计快照时，才额外要求生成 `/home/kali/workspace/{REPORTS_DIR_NAME}/observation_report_v2.json`、`/home/kali/workspace/{REPORTS_DIR_NAME}/observation_report_v3.json` 等快照；工作集仍以 `{observation_report_path}` 为准。
5. 把 `{observation_report_path}` 视为持续维护的数据集：补充 observation 时要求 subagent 先读取当前文件，再通过 `{observation_merger_path}` 对其做 merge-update，而不是整份覆盖重写。
6. 审核 `{observation_report_path}` 中的事实、evidence、hypotheses，只从证据出发，不从经验套路出发。
7. 若只有一个攻击向量，就派发一个 `exploitation-subagent`；若存在多个彼此独立的攻击向量，可以并行派发 2-3 个 `exploitation-subagent`。
8. 如果 exploitation 缺少上下文，回到 observation 补证据，不要跳步。
9. 如果 exploitation 带回了新的客观事实，由你决定是否重新派发 `observation-subagent` 把这些事实合并回 `{observation_report_path}`；不要把 exploitation 的“已验证成功”直接改写进 observation 结论。
10. 只有当已有“已验证成功”的能力 / 原语时，才允许派发组合利用任务。
{platform_workflow_steps if platform_tools_enabled else f"11. 你审核完整证据链后，若确认 flag 真实，再指派合适的 `exploitation-subagent` 将 `flag.txt` 和 `final_report.md` 写入 `{result_flag_path}` 与 `{result_final_report_path}`.\n12. 如果最终未找到 flag，则指派合适的 `exploitation-subagent` 写入 `{result_blocker_report_path}`。"}

给 `observation-subagent` 派单时，必须遵守：
- 只让它做 surface map、公开文件检查、页面和脚本读取、参数面提取、有限枚举、事实证据整理
- 不要让它做 SSRF / SQLi / SSTI / XSS / RCE / 路径穿越 / 越权 等漏洞验证
- 不要让它做参数篡改、对象 ID 切换、恶意 payload 注入、内网目标替换
- 如果 observation 阶段发现疑似漏洞点，只能记录为 hypothesis，并把验证动作留给 `exploitation-subagent`
- 如果 observation 在允许动作中被动直接看到了完整 flag，可以把它当作事实证据上报；但不要命令它为了拿 flag 主动做验证或利用
- 要求它维护 `{observation_report_path}` 时，强调“先读现有文件，再通过 `{observation_merger_path}` 合并新增内容、更新状态”，不要整份覆盖抹掉旧 evidence / hypotheses / surface_map
- observation 阶段产生的临时脚本、抓取样本、摘要、候选片段，应写入 `{observation_artifacts_dir}`，不要散落到工作区根目录

并行 exploitation 时，必须遵守：
- 只有当多个攻击向量彼此独立时，才并行
- 每个 `exploitation-subagent` 只负责一个向量，不能混做多个方向
- 并行数量默认控制在 2-3 个
- 每个 subagent 都要分配唯一输出文件，例如 `/home/kali/workspace/{EXPLOITATION_REPORTS_RELATIVE_DIR}/exploitation_web.json`、`/home/kali/workspace/{EXPLOITATION_REPORTS_RELATIVE_DIR}/exploitation_smb.json`、`/home/kali/workspace/{EXPLOITATION_REPORTS_RELATIVE_DIR}/exploitation_ssh.json`
- 禁止多个 subagent 同时写同一个报告文件
- 并行阶段默认不要让多个 subagent 同时写 `{result_flag_path}`、`{result_final_report_path}`、`{result_blocker_report_path}`
- 等并行结果都返回后，再审核并决定是否派发一个最终落盘任务
- exploitation 阶段产生的脚本、请求样本、下载文件、候选 flag、PoC 产物都应写入 `{exploitation_artifacts_dir}/<vector>/` 之类的专属子目录，不要直接丢在工作区根目录

报告文件必须防止覆盖：
- `{observation_report_path}` 是默认的唯一 observation 主文件
- 常规 observation 刷新时，直接维护 `{observation_report_path}`
- 对它的更新必须是 merge-update：追加新项、合并已有项、按状态淘汰旧项，而不是整份重写覆盖
- 旧 evidence、旧 hypotheses、旧 surface_map 项目，除非被明确判错或转入 `negative_findings`，否则不要无痕删除
- 只有在你明确要求保留历史快照时，才额外生成 `/home/kali/workspace/{REPORTS_DIR_NAME}/observation_report_v2.json`、`/home/kali/workspace/{REPORTS_DIR_NAME}/observation_report_v3.json`
- exploitation 的验证状态、能力确认、利用结果保留在 `{default_exploitation_report_path}` 或 `/home/kali/workspace/{EXPLOITATION_REPORTS_RELATIVE_DIR}/exploitation_*.json`，不要把它们直接写成 observation 主文件里的“已确认漏洞”
- 在派发 exploitation 任务前，先检查目标报告文件是否已经存在
- 如果已存在，分配新的版本号文件名，而不是覆盖旧文件
- 命名示例：`{EXPLOITATION_REPORTS_RELATIVE_DIR}/exploitation_web.json`、`{EXPLOITATION_REPORTS_RELATIVE_DIR}/exploitation_web_v2.json`、`{EXPLOITATION_REPORTS_RELATIVE_DIR}/exploitation_web_v3.json`
- 默认共享文件也一样：`{DEFAULT_EXPLOITATION_REPORT_RELATIVE_PATH}`、`{EXPLOITATION_REPORTS_RELATIVE_DIR}/exploitation_report_v2.json`
- `status` 写进 JSON 内容，不要放进主文件名
- 规范输入、规范报告、规范结果之外的临时文件一律视为 artifact；除非被规范报告引用，否则不得把它们当作结论依据

反幻觉要求：
- 不要把“看起来像 flag”写成 flag。
- 不要把“可能存在 SSRF / SQLi / RCE”写成“已确认存在”。
- 不要引用未实际执行过的命令、未实际访问过的 URL、未实际读取过的文件。
- 如果你引用某条证据，必须能指出它来自哪个命令、哪个文件或哪个响应。

题目标题：
{challenge["challenge_title"]}

题目描述：
{description}

题目提示：
{hint}

目标主机：
{challenge["target_host"]}

{platform_context if platform_tools_enabled else ""}

题目标识：
{challenge["challenge_code"]}

入口点：
{entrypoint_lines}
""".strip()


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
    server_host_value = str(challenge.get("platform_server_host") or challenge["server_host"])
    if server_host_value:
        challenge_env["SERVER_HOST"] = server_host_value
    if challenge["challenge_title"]:
        challenge_env["CHALLENGE_TITLE"] = str(challenge["challenge_title"])
    if challenge["challenge_description"]:
        challenge_env["CHALLENGE_DESCRIPTION"] = str(challenge["challenge_description"])
    if challenge["challenge_hint"]:
        challenge_env["CHALLENGE_HINT"] = str(challenge["challenge_hint"])
    agent_token = get_runtime_value(runtime_env, "AGENT_TOKEN")
    if agent_token:
        challenge_env["AGENT_TOKEN"] = agent_token

    for key, value in challenge_env.items():
        command.extend(["-e", f"{key}={value}"])
    for key in CLAUDE_ENV_KEYS:
        value = runtime_env.get(key)
        if value:
            command.extend(["-e", f"{key}={value}"])

    command.append(args.image)
    command.extend(["bash", "-c", container_start_script()])
    return command


def run_claude_task(
    container_name: str,
    prompt: str,
    timeout_seconds: int,
    *,
    platform_tools_enabled: bool = False,
) -> int:
    platform_tools = (
        " mcp__platform__submit_flag mcp__platform__view_hint mcp__platform__stop_challenge"
        if platform_tools_enabled
        else ""
    )
    tools = "Task,Read,Grep,Glob"
    if platform_tools:
        tools += ",mcp__platform__submit_flag,mcp__platform__view_hint,mcp__platform__stop_challenge"
    command = [
        "docker",
        "exec",
        "-i",
        "-w",
        "/home/kali/workspace",
        container_name,
        "bash",
        "-c",
        'claude --verbose '
        '--mcp-config /home/kali/.claude/mcp.json '
        '--strict-mcp-config '
        f'--tools "{tools}" '
        '--allowedTools "Task Read Grep Glob '
        'mcp__sandbox__python_exec mcp__sandbox__python_get mcp__sandbox__python_output '
        'mcp__sandbox__python_interrupt mcp__sandbox__python_restart mcp__sandbox__python_session_info '
        'mcp__sandbox__terminal_open mcp__sandbox__terminal_info mcp__sandbox__terminal_read '
        'mcp__sandbox__terminal_write mcp__sandbox__terminal_interrupt mcp__sandbox__terminal_close '
        f'mcp__sandbox__list_agent_runtimes mcp__sandbox__cleanup_agent_runtime{platform_tools}" '
        '--disallowedTools "Bash Write Edit MultiEdit WebFetch WebSearch NotebookRead NotebookEdit LS" '
        '-p "$(cat)"',
    ]
    process = subprocess.Popen(command, stdin=subprocess.PIPE, text=True)
    try:
        process.communicate(prompt, timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        print(f"[!] Claude task timed out after {timeout_seconds} seconds.", file=sys.stderr)
        interrupt_claude(container_name)
        process.kill()
        process.communicate()
        return 124
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user, stopping Claude...", file=sys.stderr)
        interrupt_claude(container_name)
        process.kill()
        process.communicate()
        return 130
    return process.returncode or 0


def main() -> int:
    args = parse_args()
    ensure_image_exists(args.image)
    runtime_env = load_runtime_env()
    challenge = load_challenge(runtime_env)

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
        exit_code = run_claude_task(
            container_name,
            prompt,
            args.timeout_seconds,
            platform_tools_enabled=bool(challenge.get("platform_tools_enabled")),
        )
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
