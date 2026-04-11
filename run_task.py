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
EXPLOITATION_MASTER_REPORT_RELATIVE_PATH = f"{EXPLOITATION_REPORTS_RELATIVE_DIR}/exploitation_report.json"
EXPLOITATION_DETAIL_PATTERN_RELATIVE_PATH = f"{EXPLOITATION_REPORTS_RELATIVE_DIR}/exploitation_<slug>.json"
OBSERVATION_ARTIFACTS_RELATIVE_DIR = f"{ARTIFACTS_DIR_NAME}/{OBSERVATION_ARTIFACTS_DIR_NAME}"
EXPLOITATION_ARTIFACTS_RELATIVE_DIR = f"{ARTIFACTS_DIR_NAME}/{EXPLOITATION_REPORTS_DIR_NAME}"
RESULT_FLAG_RELATIVE_PATH = f"{RESULTS_DIR_NAME}/flag.txt"
RESULT_FINAL_REPORT_RELATIVE_PATH = f"{RESULTS_DIR_NAME}/final_report.md"
RESULT_BLOCKER_REPORT_RELATIVE_PATH = f"{RESULTS_DIR_NAME}/blocker_report.md"
OBSERVATION_MERGER_RELATIVE_PATH = ".claude/tools/manage_observation_report.py"
EXPLOITATION_INDEX_MERGER_RELATIVE_PATH = ".claude/tools/manage_exploitation_report.py"
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


def build_prompt(challenge: dict[str, object]) -> str:
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
                "- 如果 `submit_flag` 返回错误，不要再次提交同一个 flag；把它视为已拒绝候选，回到证据驱动分析，只在存在其它高价值向量或一个明确缺失事实时继续推进。",
            ]
        )

    prompt_lines = [
        "你正在执行一个授权 Web CTF `find_flag` 任务。",
        "先读取 `~/.claude/CLAUDE.md` 并严格执行；这里不再重复模板全文。",
        "",
        "本轮只补充会话级约束：",
        "- 固定状态机：`initial_observation -> targeted_exploitation -> optional_finalization`；只有 exploitation 明确指出缺少某个具体事实时，才允许一次 `supplemental_observation`。",
        "- 起步只允许 1 个 `observation-subagent`。",
        f"- exploitation 默认并发上限 {MAX_PARALLEL_EXPLOITATION}，全程 exploitation 子代理总数上限 {MAX_TOTAL_EXPLOITATION_SUBAGENTS}。",
        "- 新线索如果只是现有利用链的子步骤，必须继续沿用该链已有的 detail JSON 和 owner subagent 语义，不得再拆成新的 sibling 分支。",
        "- 只有当向量彼此独立、端点/目标不同、现有 detail 文件未覆盖，而且任务可以被一句话清楚限定时，才允许新开 `exploitation-subagent`。",
        "- 每次 observation merge 后、每次 exploitation 总表更新后，先只检查 exploitation 总表里的四个结构化状态：`summary.key_facts`、`summary.confirmed_capabilities`、`summary.composed_chains`、`summary.priority_actions`，以及 observation 主文件里的 `recommended_next_step`。",
        "- 如果 upload/write primitive、可预测可访问路径、以及 template/include/render loader 同时存在，必须优先作为**一条组合链**派发；不要把同一条链再拆成多个后缀/探针/单文件平行小分支。",
        "- 已确认 capability 是 sticky 的：后续某个 payload / 路径失败，不能推翻之前已确认的 loader、upload path、目录索引、有效 session 等事实；失败只代表这次组合尝试未闭环。",
        "- 如果 exploitation 总表把某条链标成 `ready_for_validation`、`in_progress` 或 `attempted_but_incomplete`，就说明它还没有闭环；不要被单个 detail JSON 里的悲观总结带偏。",
        "- 对 upload + loader 组合链，派单时必须写清：认证前提、上传动作、上传前后目录 diff/枚举、实际落盘路径解析、最终 loader 调用；不要只测若干猜测路径就宣布失败。",
        "- 禁止派发“final comprehensive test”“把剩余向量都再试一遍”这类模糊任务；最终 exploitation 任务也必须引用明确 source reports、明确 chain、明确步骤顺序与停止条件。",
        "- 非 finalization 阶段不得读取 `.results/*`；在 `recommended_next_step` 或 `priority_actions` 仍有高价值动作时，禁止 blocker/finalization。",
        "- main agent 自己不执行 `mcp__sandbox__*`；subagent 一律先 `python_exec`，再 `shell_exec`，最后才是 `terminal_*`。",
        "- 长 `.py` / `.json` / `.md` / update payload 必须优先用 `python_exec` 生成；不要用 shell heredoc、`cat > file`、或超长 `shell_exec`/`terminal_write` 输入去写文件。",
        "- helper 成功后不要再 `cat` / `head` / `json.tool` 回读刚写出的报告；只有确实需要某个字段时再按字段提取。",
        "- 同一阶段内不要反复整份 `Read` 同一个 observation / exploitation 报告；只有在 subagent 完成、helper merge 成功、或你明确需要一个此前未提取的字段时才允许再次读取。",
        "- exploitation detail JSON 只保留最小 canonical 字段：`target`、`hypothesis_id`、`title`、`status`、`confidence`、对象型 `summary`、`evidence`、`new_facts`、`recommendation`、`needs_more_observation`、`artifacts`，以及必要时的 `chain_validation`；不要再平行堆 `key_findings` / `conclusions` / `next_actions` / `next_steps`。",
        "- 不要读取 `runtime_v2/*` 原始日志或 `.claude/projects/*.jsonl`；不要把超过 4KB 的 artifact 正文带回上下文。",
        "- 不要用 `shell_exec` 的 heredoc / `cat > file` 写长脚本、长 JSON、长 markdown；超过几行就必须改用 `python_exec`。",
        *challenge_mcp_lines,
        "",
        "关键路径：",
        f"- challenge: `{input_challenge_path}`",
        f"- observation: `{observation_report_path}`",
        f"- observation merge helper: `{observation_merger_path}`",
        f"- exploitation master: `{exploitation_master_report_path}`",
        f"- exploitation detail pattern: `{exploitation_detail_pattern_path}`",
        f"- exploitation merge helper: `{exploitation_index_merger_path}`",
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

    return (
        "claude --verbose "
        "--mcp-config /home/kali/.claude/mcp.json "
        "--strict-mcp-config "
        f'--tools "{tools}" '
        '--allowedTools "Task Read Grep Glob '
        'mcp__sandbox__python_exec mcp__sandbox__python_get mcp__sandbox__python_output '
        'mcp__sandbox__python_interrupt mcp__sandbox__python_restart mcp__sandbox__python_session_info '
        'mcp__sandbox__shell_exec '
        'mcp__sandbox__terminal_open mcp__sandbox__terminal_info mcp__sandbox__terminal_read '
        'mcp__sandbox__terminal_write mcp__sandbox__terminal_interrupt mcp__sandbox__terminal_close '
        f'mcp__sandbox__list_agent_runtimes mcp__sandbox__cleanup_agent_runtime{platform_tools}" '
        '--disallowedTools "Bash Write Edit MultiEdit WebFetch WebSearch NotebookRead NotebookEdit LS" '
        '-p "$(cat)"'
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
