#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


FLAG_PATTERN = re.compile(r"flag\{[^\r\n{}]+\}")
WORKSPACE_DEFAULT = "/home/kali/workspace"
INPUT_CHALLENGE_RELATIVE_PATH = ".inputs/challenge.json"
STATE_RELATIVE_PATH = ".results/flag_hook_state.json"
HOOK_LOG_RELATIVE_PATH = ".results/flag_hook_events.jsonl"
SUCCESS_SENTINEL_RELATIVE_PATH = ".results/hook_submit_success.json"
PARTIAL_SENTINEL_RELATIVE_PATH = ".results/hook_submit_partial.json"
FLAG_RESULT_RELATIVE_PATH = ".results/flag.txt"
FINAL_REPORT_RELATIVE_PATH = ".results/final_report.md"
EXCLUDED_RELATIVE_PREFIXES = (".results/", ".inputs/", ".claude/projects/")
EXAMPLE_FLAG_MARKERS = ("test_flag", "flag_test", "example_flag", "placeholder", "demo flag", "sample flag")
FLAG_PRODUCING_KEYS = {
    "content",
    "contents",
    "data",
    "output",
    "outputs",
    "response",
    "responses",
    "result",
    "results",
    "stderr",
    "stdout",
    "text",
    "tool_output",
    "tool_response",
    "tool_result",
    "value",
}
FLAG_EXCLUDED_KEYS = {
    "command",
    "commands",
    "description",
    "descriptions",
    "input",
    "inputs",
    "matcher",
    "message",
    "messages",
    "name",
    "prompt",
    "prompts",
    "question",
    "questions",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def workspace_root() -> Path:
    return Path(os.getenv("CLAUDE_PROJECT_DIR") or os.getenv("WORKSPACE_DIR") or WORKSPACE_DEFAULT)


def workspace_path(relative_path: str) -> Path:
    return workspace_root() / relative_path


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    temp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp_path.replace(path)


def append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def normalize_server_host(server_host: str) -> str:
    text = (server_host or "").strip()
    if not text:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", text):
        text = f"http://{text}"
    parsed = urllib.parse.urlsplit(text)
    path = parsed.path.rstrip("/")
    if path.endswith("/mcp"):
        path = path[:-4]
    elif path.endswith("/api"):
        path = path[:-4]
    normalized = parsed._replace(path=path.rstrip("/"), query="", fragment="")
    return urllib.parse.urlunsplit(normalized).rstrip("/")


def truthy_env(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def read_challenge_context() -> dict[str, Any]:
    snapshot = load_json(workspace_path(INPUT_CHALLENGE_RELATIVE_PATH), {})
    env_enabled = truthy_env(os.getenv("CHALLENGE_MCP_ENABLED", ""))
    file_enabled = bool(snapshot.get("challenge_mcp_enabled"))
    challenge_code = str(snapshot.get("challenge_code") or "").strip()
    env_code = os.getenv("CHALLENGE_CODE", "").strip()
    server_host = str(snapshot.get("challenge_mcp_server") or snapshot.get("server_host") or "").strip()
    env_server_host = os.getenv("SERVER_HOST", "").strip()
    agent_token = os.getenv("AGENT_TOKEN", "").strip()

    mismatch_errors: list[str] = []
    if challenge_code and env_code and challenge_code != env_code:
        mismatch_errors.append("challenge.json 的 challenge_code 与 CHALLENGE_CODE 环境变量不一致")
    if server_host and env_server_host and normalize_server_host(server_host) != normalize_server_host(env_server_host):
        mismatch_errors.append("challenge.json 的 challenge_mcp_server 与 SERVER_HOST 环境变量不一致")

    effective_code = challenge_code or env_code
    effective_server_host = normalize_server_host(server_host or env_server_host)
    enabled = env_enabled and file_enabled
    if mismatch_errors:
        enabled = False

    return {
        "enabled": enabled,
        "challenge_code": effective_code,
        "server_host": effective_server_host,
        "agent_token": agent_token,
        "mismatch_errors": mismatch_errors,
    }


def load_state() -> dict[str, Any]:
    return load_json(
        workspace_path(STATE_RELATIVE_PATH),
        {
            "submitted_flags": [],
            "rejected_flags": [],
            "partial_flags": [],
            "success_flag": "",
            "last_error": "",
            "last_response": None,
            "cooldown_until": 0.0,
        },
    )


def save_state(state: dict[str, Any]) -> None:
    write_json(workspace_path(STATE_RELATIVE_PATH), state)


def parse_json_maybe(value: Any) -> Any:
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("{") or text.startswith("["):
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return value
    return value


def event_name(payload: dict[str, Any]) -> str:
    for key in ("hook_event_name", "hookEventName", "event_name", "eventName"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def log_event(payload: dict[str, Any], action: str, **extra: Any) -> None:
    record = {
        "ts": now_iso(),
        "action": action,
        "hook_event": event_name(payload),
        "tool_name": tool_name(payload),
    }
    if isinstance(payload.get("agent_id"), str) and payload.get("agent_id"):
        record["agent_id"] = payload["agent_id"]
    if isinstance(payload.get("session_id"), str) and payload.get("session_id"):
        record["session_id"] = payload["session_id"]
    for key, value in extra.items():
        if value not in (None, "", [], {}):
            record[key] = value
    append_jsonl(workspace_path(HOOK_LOG_RELATIVE_PATH), record)


def tool_name(payload: dict[str, Any]) -> str:
    for key in ("tool_name", "toolName", "name"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def tool_input(payload: dict[str, Any]) -> dict[str, Any]:
    for key in ("tool_input", "toolInput", "input"):
        value = payload.get(key)
        value = parse_json_maybe(value)
        if isinstance(value, dict):
            return value
    return {}


def tool_response(payload: dict[str, Any]) -> Any:
    for key in ("tool_response", "toolResponse", "tool_output", "toolOutput", "tool_result", "toolResult", "result", "response"):
        if key in payload:
            return parse_json_maybe(payload.get(key))
    return None


def submission_payload_from_tool_response(value: Any) -> dict[str, Any]:
    value = parse_json_maybe(value)
    if isinstance(value, dict):
        return value
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                for key in ("text", "content", "value"):
                    parsed = parse_json_maybe(item.get(key))
                    if isinstance(parsed, dict):
                        return parsed
    if isinstance(value, str):
        parsed = parse_json_maybe(value)
        if isinstance(parsed, dict):
            return parsed
    return {}


def tool_error(payload: dict[str, Any]) -> str:
    for key in ("error", "tool_error", "toolError", "message"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def should_include_path(path_parts: tuple[str, ...]) -> bool:
    lowered = [part.lower() for part in path_parts]
    if any(part in FLAG_EXCLUDED_KEYS for part in lowered):
        return False
    if not lowered:
        return True
    return any(part in FLAG_PRODUCING_KEYS for part in lowered)


def collect_candidate_texts(node: Any, *, path_parts: tuple[str, ...] = ()) -> list[str]:
    texts: list[str] = []
    if isinstance(node, str):
        if should_include_path(path_parts):
            texts.append(node)
        return texts
    if isinstance(node, dict):
        for key, value in node.items():
            texts.extend(collect_candidate_texts(value, path_parts=(*path_parts, str(key))))
        return texts
    if isinstance(node, list):
        for item in node:
            texts.extend(collect_candidate_texts(item, path_parts=path_parts))
    return texts


def contains_example_marker(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in EXAMPLE_FLAG_MARKERS)


def extract_flags_from_text(text: str) -> list[str]:
    if contains_example_marker(text):
        return []
    return [match.group(0) for match in FLAG_PATTERN.finditer(text)]


def extract_flags_from_payload(payload: Any) -> list[str]:
    candidates = collect_candidate_texts(payload)
    if not candidates and isinstance(payload, str):
        candidates = [payload]
    flags: list[str] = []
    seen: set[str] = set()
    for text in candidates:
        for flag in extract_flags_from_text(text):
            if flag not in seen:
                seen.add(flag)
                flags.append(flag)
    return flags


def extract_relevant_paths(payload: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    for source in (tool_input(payload), payload):
        for key in ("file_path", "filePath", "path", "paths"):
            value = source.get(key) if isinstance(source, dict) else None
            if isinstance(value, str):
                paths.append(value)
            elif isinstance(value, list):
                paths.extend(item for item in value if isinstance(item, str))
    return list(dict.fromkeys(paths))


def path_is_excluded(path_value: str) -> bool:
    normalized = path_value.replace("\\", "/").strip()
    if normalized.startswith("/home/kali/workspace/"):
        normalized = normalized[len("/home/kali/workspace/") :]
    normalized = normalized.lstrip("./")
    return any(normalized.startswith(prefix) for prefix in EXCLUDED_RELATIVE_PREFIXES)


def pretooluse_deny(reason: str) -> int:
    response = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }
    sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
    return 0


def posttooluse_additional_context(message: str) -> int:
    response = {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": message,
        }
    }
    sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
    return 0


def submit_flag(server_host: str, agent_token: str, challenge_code: str, flag: str) -> dict[str, Any]:
    request = urllib.request.Request(
        f"{normalize_server_host(server_host)}/api/submit",
        data=json.dumps({"code": challenge_code, "flag": flag}).encode("utf-8"),
        headers={"Content-Type": "application/json", "Agent-Token": agent_token},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            body = response.read().decode("utf-8", errors="replace")
            status_code = response.status
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", errors="replace")
        status_code = error.code
    except OSError as error:
        return {"status_code": 0, "payload": {}, "transport_error": str(error)}

    try:
        payload = json.loads(body) if body else {}
    except json.JSONDecodeError:
        payload = {"message": body}
    return {"status_code": status_code, "payload": payload}


def write_success_outputs(flag: str, response: dict[str, Any]) -> None:
    flag_path = workspace_path(FLAG_RESULT_RELATIVE_PATH)
    final_report_path = workspace_path(FINAL_REPORT_RELATIVE_PATH)
    success_path = workspace_path(SUCCESS_SENTINEL_RELATIVE_PATH)
    partial_path = workspace_path(PARTIAL_SENTINEL_RELATIVE_PATH)

    flag_path.parent.mkdir(parents=True, exist_ok=True)
    flag_path.write_text(flag + "\n", encoding="utf-8")

    payload = response.get("payload") or {}
    data = payload.get("data") if isinstance(payload, dict) else {}
    final_report = "\n".join(
        [
            "# Auto-Submitted Flag Report",
            "",
            "## Summary",
            f"- Flag: `{flag}`",
            f"- Submitted at: {now_iso()}",
            "- Submission mode: Claude hook auto-submit",
            f"- Platform message: {str((data or {}).get('message') or payload.get('message') or '').strip() or '(none)'}",
            "",
            "## Status",
            "SUCCESS (hook auto-submitted and confirmed by platform)",
        ]
    )
    final_report_path.write_text(final_report + "\n", encoding="utf-8")
    if partial_path.exists():
        partial_path.unlink()
    write_json(
        success_path,
        {
            "flag": flag,
            "submitted_at": now_iso(),
            "status_code": response.get("status_code"),
            "response": payload,
        },
    )


def write_partial_output(flag: str, response: dict[str, Any]) -> None:
    write_json(
        workspace_path(PARTIAL_SENTINEL_RELATIVE_PATH),
        {
            "flag": flag,
            "submitted_at": now_iso(),
            "status_code": response.get("status_code"),
            "response": response.get("payload") or {},
        },
    )


def submission_is_correct(response: dict[str, Any]) -> tuple[bool, bool]:
    status_code = int(response.get("status_code") or 0)
    payload = response.get("payload") or {}
    data = payload.get("data") if isinstance(payload, dict) else {}
    correct = status_code == 200 and payload.get("code") == 0 and isinstance(data, dict) and data.get("correct") is True
    if not correct:
        return False, False
    flag_count = data.get("flag_count")
    flag_got_count = data.get("flag_got_count")
    if isinstance(flag_count, int) and isinstance(flag_got_count, int):
        return True, flag_got_count >= flag_count
    return True, True


def handle_submit_result(flag: str, response: dict[str, Any], state: dict[str, Any]) -> str:
    submitted = set(state.get("submitted_flags") or [])
    rejected = set(state.get("rejected_flags") or [])
    partial_flags = set(state.get("partial_flags") or [])
    submitted.add(flag)

    correct, is_complete = submission_is_correct(response)
    state["last_response"] = response.get("payload") or {}

    if response.get("status_code") == 429:
        state["cooldown_until"] = time.time() + 2.0
        state["last_error"] = "submit_flag API rate limited (429)"
    elif response.get("transport_error"):
        state["last_error"] = str(response["transport_error"])

    if correct and is_complete:
        state["submitted_flags"] = sorted(submitted)
        state["rejected_flags"] = sorted(rejected)
        state["partial_flags"] = sorted(partial_flags)
        state["success_flag"] = flag
        state["last_error"] = ""
        save_state(state)
        write_success_outputs(flag, response)
        return "complete"

    if correct:
        partial_flags.add(flag)
        state["submitted_flags"] = sorted(submitted)
        state["rejected_flags"] = sorted(rejected)
        state["partial_flags"] = sorted(partial_flags)
        state["last_error"] = ""
        save_state(state)
        write_partial_output(flag, response)
        return "partial"

    rejected.add(flag)
    state["submitted_flags"] = sorted(submitted)
    state["rejected_flags"] = sorted(rejected)
    state["partial_flags"] = sorted(partial_flags)
    if not state.get("last_error"):
        payload = response.get("payload") or {}
        state["last_error"] = str(payload.get("message") or ((payload.get("data") or {}).get("message") if isinstance(payload, dict) else "") or "").strip()
    save_state(state)
    return "rejected"


def should_skip_auto_submit(payload: dict[str, Any]) -> bool:
    return any(path_is_excluded(path) for path in extract_relevant_paths(payload))


def auto_submit_flags(
    flags: list[str],
    context: dict[str, Any],
    state: dict[str, Any],
    *,
    allow_additional_context: bool,
    source_payload: dict[str, Any],
) -> int:
    if not flags:
        return 0
    if time.time() < float(state.get("cooldown_until") or 0):
        return 0

    submitted = set(state.get("submitted_flags") or [])
    rejected = set(state.get("rejected_flags") or [])
    success_flag = str(state.get("success_flag") or "").strip()
    if success_flag:
        return 0

    challenge_code = context["challenge_code"]
    server_host = context["server_host"]
    agent_token = context["agent_token"]

    for flag in flags:
        if flag in submitted or flag in rejected:
            continue
        payload_preview = {"flag": flag, "challenge_code": challenge_code, "server_host": server_host}
        response = submit_flag(server_host, agent_token, challenge_code, flag)
        status = handle_submit_result(flag, response, state)
        payload_obj = response.get("payload") or {}
        data = payload_obj.get("data") if isinstance(payload_obj, dict) else {}
        log_event(
            source_payload,
            "auto_submit_attempt",
            **payload_preview,
            submission_status=status,
            status_code=response.get("status_code"),
            platform_message=str((data or {}).get("message") or payload_obj.get("message") or "").strip(),
            transport_error=response.get("transport_error"),
        )
        if allow_additional_context and status == "complete":
            message = str((data or {}).get("message") or payload_obj.get("message") or "").strip()
            return posttooluse_additional_context(f"Hook auto-submitted `{flag}` successfully. {message}".strip())
        if allow_additional_context and status == "partial":
            message = str((data or {}).get("message") or payload_obj.get("message") or "").strip()
            return posttooluse_additional_context(
                f"Hook auto-submitted `{flag}` successfully, but this challenge still has remaining flag points. {message}".strip()
            )
    return 0


def handle_pre_tool_use(payload: dict[str, Any], context: dict[str, Any], state: dict[str, Any]) -> int:
    if tool_name(payload) != "mcp__platform__submit_flag":
        return 0
    if context["mismatch_errors"]:
        log_event(payload, "pretooluse_deny", reason="context_mismatch", details=context["mismatch_errors"])
        return pretooluse_deny(" / ".join(context["mismatch_errors"]))
    if not context["enabled"]:
        log_event(payload, "pretooluse_deny", reason="challenge_mcp_disabled_or_context_invalid")
        return pretooluse_deny("challenge MCP 未启用或 challenge.json 与环境不一致，禁止提交 flag")

    tool_payload = tool_input(payload)
    submitted_code = str(tool_payload.get("code") or "").strip()
    submitted_flag = str(tool_payload.get("flag") or "").strip()
    expected_code = str(context["challenge_code"] or "").strip()

    if not expected_code:
        log_event(payload, "pretooluse_deny", reason="missing_challenge_code")
        return pretooluse_deny("challenge.json 中缺少 challenge_code，禁止提交 flag")
    if submitted_code != expected_code:
        log_event(payload, "pretooluse_deny", reason="wrong_challenge_code", submitted_code=submitted_code, expected_code=expected_code)
        return pretooluse_deny("只能使用 challenge.json 中的精确 challenge_code；禁止猜测或变体提交")
    if submitted_flag:
        submitted = set(state.get("submitted_flags") or [])
        rejected = set(state.get("rejected_flags") or [])
        success_flag = str(state.get("success_flag") or "").strip()
        if submitted_flag == success_flag or submitted_flag in submitted or submitted_flag in rejected:
            log_event(payload, "pretooluse_deny", reason="duplicate_flag_submission", flag=submitted_flag)
            return pretooluse_deny("这个 flag 已提交过或已被判错，不要重复提交")
    log_event(payload, "pretooluse_allow", code=submitted_code, flag=submitted_flag)
    return 0


def handle_post_tool_use(payload: dict[str, Any], context: dict[str, Any], state: dict[str, Any]) -> int:
    if not context["enabled"]:
        log_event(payload, "skip", reason="challenge_mcp_disabled")
        return 0
    if should_skip_auto_submit(payload):
        log_event(payload, "skip", reason="excluded_path", paths=extract_relevant_paths(payload))
        return 0

    current_tool = tool_name(payload)
    if current_tool == "mcp__platform__submit_flag":
        tool_payload = tool_input(payload)
        submitted_flag = str(tool_payload.get("flag") or "").strip()
        if not submitted_flag:
            log_event(payload, "skip", reason="submit_flag_without_flag")
            return 0
        response = {"status_code": 200, "payload": submission_payload_from_tool_response(tool_response(payload))}
        status = handle_submit_result(submitted_flag, response, state)
        result_payload = response.get("payload") or {}
        data = result_payload.get("data") if isinstance(result_payload, dict) else {}
        log_event(
            payload,
            "submit_flag_tool_result",
            flag=submitted_flag,
            submission_status=status,
            status_code=response.get("status_code"),
            platform_message=str((data or {}).get("message") or result_payload.get("message") or "").strip(),
        )
        if status == "complete":
            message = str((data or {}).get("message") or result_payload.get("message") or "").strip()
            return posttooluse_additional_context(f"submit_flag 已成功命中官方答案：{message}".strip())
        if status == "partial":
            return posttooluse_additional_context("submit_flag 已命中一个 flag 点，但本题仍可能有剩余 flag。")
        return 0

    response = tool_response(payload)
    flags = extract_flags_from_payload(response)
    log_event(payload, "scan_tool_output", detected_flags=flags, paths=extract_relevant_paths(payload))
    return auto_submit_flags(flags, context, state, allow_additional_context=True, source_payload=payload)


def handle_post_tool_use_failure(payload: dict[str, Any], _context: dict[str, Any], state: dict[str, Any]) -> int:
    if tool_name(payload) != "mcp__platform__submit_flag":
        return 0
    error_text = tool_error(payload)
    if error_text:
        state["last_error"] = error_text
        save_state(state)
        log_event(payload, "submit_flag_tool_error", error=error_text)
    return 0


def handle_stop_like(payload: dict[str, Any], context: dict[str, Any], state: dict[str, Any]) -> int:
    if not context["enabled"]:
        log_event(payload, "skip", reason="challenge_mcp_disabled")
        return 0
    message = payload.get("last_assistant_message")
    if not isinstance(message, str) or not message.strip():
        log_event(payload, "skip", reason="missing_last_assistant_message")
        return 0
    flags = extract_flags_from_text(message)
    log_event(payload, "scan_stop_message", detected_flags=flags)
    return auto_submit_flags(flags, context, state, allow_additional_context=False, source_payload=payload)


def main() -> int:
    raw_input = sys.stdin.read()
    if not raw_input.strip():
        return 0

    try:
        payload = json.loads(raw_input)
    except json.JSONDecodeError:
        return 0

    context = read_challenge_context()
    state = load_state()
    event = event_name(payload)
    log_event(
        payload,
        "hook_invoked",
        challenge_mcp_enabled=context["enabled"],
        mismatch_errors=context["mismatch_errors"],
    )

    if event == "PreToolUse":
        return handle_pre_tool_use(payload, context, state)
    if event == "PostToolUse":
        return handle_post_tool_use(payload, context, state)
    if event == "PostToolUseFailure":
        return handle_post_tool_use_failure(payload, context, state)
    if event in {"Stop", "SubagentStop", "StopFailure"}:
        return handle_stop_like(payload, context, state)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
