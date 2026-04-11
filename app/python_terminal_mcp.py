from __future__ import annotations

import argparse
import atexit
import errno
import hashlib
import json
import os
import pty
import re
import select
import shlex
import signal
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, Optional

try:
    from fastmcp import FastMCP
except ImportError:  # pragma: no cover - optional at runtime
    FastMCP = None


DEFAULT_STARTUP_TIMEOUT_SECONDS = 15
DEFAULT_WAIT_TIMEOUT_SECONDS = 15
DEFAULT_IDLE_OUTPUT_TIMEOUT_SECONDS = 60
DEFAULT_HARD_TIMEOUT_SECONDS = 1800

DEFAULT_MAX_OUTPUT_MESSAGES = 200
DEFAULT_MAX_TOTAL_OUTPUT_BYTES = 256 * 1024
DEFAULT_MAX_SINGLE_OUTPUT_BYTES = 16 * 1024
DEFAULT_OUTPUT_PAGE_SIZE = 100


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def monotonic_now() -> float:
    return time.monotonic()


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def json_default(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, set):
        return sorted(value)
    return str(value)


@dataclass
class RuntimeRecord:
    runtime_key: str
    scope: str
    owner_id: str
    agent_id: str
    group_id: Optional[str]
    root_dir: str
    workspace_dir: str
    created_at: str
    last_seen: str
    member_agent_ids: set[str] = field(default_factory=set, repr=False)
    lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def to_public_dict(self, session_count: int = 0, terminal_count: int = 0) -> dict[str, Any]:
        with self.lock:
            return {
                "runtime_key": self.runtime_key,
                "scope": self.scope,
                "owner_id": self.owner_id,
                "agent_id": self.agent_id,
                "group_id": self.group_id,
                "root_dir": self.root_dir,
                "workspace_dir": self.workspace_dir,
                "created_at": self.created_at,
                "last_seen": self.last_seen,
                "member_agent_ids": sorted(self.member_agent_ids),
                "python_session_count": session_count,
                "terminal_count": terminal_count,
            }


@dataclass
class SessionRecord:
    runtime_key: str
    session_name: str
    workspace_dir: str
    artifact_dir: str
    process: subprocess.Popen[str]
    created_at: str
    last_seen: str
    runtime_state: str = "starting"
    busy: bool = False
    dirty_after_interrupt: bool = False
    active_execution_id: Optional[str] = None
    execution_count: int = 0
    backend: str = "python-subprocess-worker"
    ready_received: bool = False
    startup_error: Optional[str] = None
    startup_messages: list[str] = field(default_factory=list, repr=False)
    ready_event: threading.Event = field(default_factory=threading.Event, repr=False)
    lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "runtime_key": self.runtime_key,
            "session_name": self.session_name,
            "workspace_dir": self.workspace_dir,
            "artifact_dir": self.artifact_dir,
            "created_at": self.created_at,
            "last_seen": self.last_seen,
            "runtime_state": self.runtime_state,
            "busy": self.busy,
            "dirty_after_interrupt": self.dirty_after_interrupt,
            "active_execution_id": self.active_execution_id,
            "execution_count": self.execution_count,
            "backend": self.backend,
            "pid": self.process.pid,
        }


@dataclass
class ExecutionRecord:
    execution_id: str
    runtime_key: str
    agent_id: str
    group_id: Optional[str]
    session_name: str
    code: str
    wait_timeout_seconds: int
    hard_timeout_seconds: int
    idle_output_timeout_seconds: int
    background_on_timeout: bool
    output_log_path: str
    metadata_path: str
    status: str = "running"
    timed_out: bool = False
    backgrounded: bool = False
    start_time: str = field(default_factory=utcnow_iso)
    end_time: Optional[str] = None
    outputs: list[dict[str, Any]] = field(default_factory=list)
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    error_summary: Optional[str] = None
    total_output_messages: int = 0
    total_output_bytes: int = 0
    output_preview_truncated: bool = False
    last_output_at: str = field(default_factory=utcnow_iso)
    last_output_monotonic: float = field(default_factory=monotonic_now)
    interrupt_requested: bool = False
    done_event: threading.Event = field(default_factory=threading.Event, repr=False)
    lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def to_public_dict(self) -> dict[str, Any]:
        with self.lock:
            idle_for_seconds = max(0.0, monotonic_now() - self.last_output_monotonic)
            return {
                "execution_id": self.execution_id,
                "runtime_key": self.runtime_key,
                "agent_id": self.agent_id,
                "group_id": self.group_id,
                "session_name": self.session_name,
                "status": self.status,
                "timed_out": self.timed_out,
                "backgrounded": self.backgrounded,
                "start_time": self.start_time,
                "end_time": self.end_time,
                "outputs": list(self.outputs),
                "artifacts": list(self.artifacts),
                "error_summary": self.error_summary,
                "wait_timeout_seconds": self.wait_timeout_seconds,
                "hard_timeout_seconds": self.hard_timeout_seconds,
                "idle_output_timeout_seconds": self.idle_output_timeout_seconds,
                "last_output_at": self.last_output_at,
                "idle_for_seconds": round(idle_for_seconds, 3),
                "idle_output_exceeded": idle_for_seconds >= self.idle_output_timeout_seconds,
                "total_output_messages": self.total_output_messages,
                "total_output_bytes": self.total_output_bytes,
                "output_log_path": self.output_log_path,
                "metadata_path": self.metadata_path,
            }


@dataclass
class TerminalRecord:
    terminal_id: str
    runtime_key: str
    agent_id: str
    group_id: Optional[str]
    name: str
    cwd: str
    shell: str
    wait_timeout_seconds: int
    hard_timeout_seconds: int
    output_log_path: str
    metadata_path: str
    workspace_dir: str
    env_overrides: dict[str, str]
    status: str = "running"
    timed_out: bool = False
    backgrounded: bool = False
    interactive: bool = True
    start_time: str = field(default_factory=utcnow_iso)
    end_time: Optional[str] = None
    outputs: list[dict[str, Any]] = field(default_factory=list)
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    error_summary: Optional[str] = None
    return_code: Optional[int] = None
    pid: Optional[int] = None
    total_output_messages: int = 0
    total_output_bytes: int = 0
    output_preview_truncated: bool = False
    last_output_at: str = field(default_factory=utcnow_iso)
    last_output_monotonic: float = field(default_factory=monotonic_now)
    done_event: threading.Event = field(default_factory=threading.Event, repr=False)
    lock: threading.RLock = field(default_factory=threading.RLock, repr=False)
    terminate_requested: bool = False
    pty_master_fd: Optional[int] = field(default=None, repr=False)
    pty_slave_name: Optional[str] = None
    process: Any = field(default=None, repr=False)

    def to_public_dict(self) -> dict[str, Any]:
        with self.lock:
            idle_for_seconds = max(0.0, monotonic_now() - self.last_output_monotonic)
            return {
                "terminal_id": self.terminal_id,
                "runtime_key": self.runtime_key,
                "agent_id": self.agent_id,
                "group_id": self.group_id,
                "name": self.name,
                "cwd": self.cwd,
                "workspace_dir": self.workspace_dir,
                "shell": self.shell,
                "status": self.status,
                "timed_out": self.timed_out,
                "backgrounded": self.backgrounded,
                "interactive": self.interactive,
                "start_time": self.start_time,
                "end_time": self.end_time,
                "outputs": list(self.outputs),
                "artifacts": list(self.artifacts),
                "error_summary": self.error_summary,
                "return_code": self.return_code,
                "pid": self.pid,
                "pty_slave_name": self.pty_slave_name,
                "total_output_messages": self.total_output_messages,
                "total_output_bytes": self.total_output_bytes,
                "last_output_at": self.last_output_at,
                "idle_for_seconds": round(idle_for_seconds, 3),
                "output_log_path": self.output_log_path,
                "metadata_path": self.metadata_path,
                "wait_timeout_seconds": self.wait_timeout_seconds,
                "hard_timeout_seconds": self.hard_timeout_seconds,
                "env_overrides": dict(self.env_overrides),
            }


class PythonTerminalExecutorV2:
    def __init__(
        self,
        root_dir: str = "runtime_v2",
        startup_timeout_seconds: int = DEFAULT_STARTUP_TIMEOUT_SECONDS,
        wait_timeout_seconds: int = DEFAULT_WAIT_TIMEOUT_SECONDS,
        idle_output_timeout_seconds: int = DEFAULT_IDLE_OUTPUT_TIMEOUT_SECONDS,
        hard_timeout_seconds: int = DEFAULT_HARD_TIMEOUT_SECONDS,
        max_output_messages: int = DEFAULT_MAX_OUTPUT_MESSAGES,
        max_total_output_bytes: int = DEFAULT_MAX_TOTAL_OUTPUT_BYTES,
        max_single_output_bytes: int = DEFAULT_MAX_SINGLE_OUTPUT_BYTES,
        python_executable: Optional[str] = None,
        workspace_dir: Optional[str] = None,
    ) -> None:
        self.root_dir = Path(root_dir).resolve()
        self.shared_workspace_dir: Optional[Path] = None
        self.startup_timeout_seconds = startup_timeout_seconds
        self.wait_timeout_seconds = wait_timeout_seconds
        self.idle_output_timeout_seconds = idle_output_timeout_seconds
        self.hard_timeout_seconds = hard_timeout_seconds
        self.max_output_messages = max_output_messages
        self.max_total_output_bytes = max_total_output_bytes
        self.max_single_output_bytes = max_single_output_bytes
        self.python_executable = python_executable or sys.executable

        self.runtimes_root = self.root_dir / "runtimes"
        self.executions_root = self.root_dir / "executions"
        self.terminals_root = self.root_dir / "terminals"
        self.audit_log_path = self.root_dir / "audit" / "audit.jsonl"
        self.worker_script_path = Path(__file__).with_name("python_session_worker.py")

        self.runtimes: dict[str, RuntimeRecord] = {}
        self.sessions: dict[tuple[str, str], SessionRecord] = {}
        self.executions: dict[str, ExecutionRecord] = {}
        self.terminals: dict[str, TerminalRecord] = {}
        self._state_lock = threading.RLock()
        self._audit_lock = threading.Lock()
        self._signal_installed = False

        self.configure_runtime(root_dir, workspace_dir=workspace_dir)
        self._install_cleanup_hooks()

    def configure_runtime(self, root_dir: str, workspace_dir: Optional[str] = None) -> None:
        self.root_dir = Path(root_dir).resolve()
        self.runtimes_root = self.root_dir / "runtimes"
        self.executions_root = self.root_dir / "executions"
        self.terminals_root = self.root_dir / "terminals"
        self.audit_log_path = self.root_dir / "audit" / "audit.jsonl"
        configured_workspace_dir = workspace_dir or os.environ.get("PYTHON_TERMINAL_MCP_WORKSPACE_DIR")
        self.shared_workspace_dir = Path(configured_workspace_dir).expanduser().resolve() if configured_workspace_dir else None
        for path in (self.runtimes_root, self.executions_root, self.terminals_root, self.audit_log_path.parent):
            path.mkdir(parents=True, exist_ok=True)
        if self.shared_workspace_dir is not None:
            self.shared_workspace_dir.mkdir(parents=True, exist_ok=True)

    def _install_cleanup_hooks(self) -> None:
        if self._signal_installed:
            return
        atexit.register(self.close_all_sessions)
        atexit.register(self.close_all_terminals)
        self._signal_installed = True

    @staticmethod
    def _sanitize_name(value: str) -> str:
        sanitized = re.sub(r"[^\w\-.]", "_", value).strip("._")
        return sanitized or "default"

    def _append_jsonl(self, path: Path, payload: dict[str, Any]) -> None:
        ensure_parent(path)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False, default=json_default) + "\n")

    def _write_json(self, path: Path, payload: dict[str, Any]) -> None:
        ensure_parent(path)
        with path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, default=json_default)

    def _audit(self, event: str, **payload: Any) -> None:
        with self._audit_lock:
            self._append_jsonl(self.audit_log_path, {"timestamp": utcnow_iso(), "event": event, **payload})

    def _validate_agent_id(self, agent_id: str) -> Optional[str]:
        if not str(agent_id or "").strip():
            return "agent_id is required."
        return None

    def _runtime_identity(self, agent_id: str, group_id: Optional[str]) -> tuple[str, str, str]:
        if group_id:
            owner_id = self._sanitize_name(group_id)
            return f"group:{owner_id}", "group", owner_id
        owner_id = self._sanitize_name(agent_id)
        return f"agent:{owner_id}", "agent", owner_id

    def _runtime_storage_dir(self, scope: str, owner_id: str) -> Path:
        container = "groups" if scope == "group" else "agents"
        return self.runtimes_root / container / owner_id

    def _execution_dir(self, execution_id: str) -> Path:
        path = self.executions_root / execution_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _terminal_dir(self, terminal_id: str) -> Path:
        path = self.terminals_root / terminal_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _session_storage_dir(self, runtime: RuntimeRecord, session_name: str) -> Path:
        path = Path(runtime.root_dir) / "python_sessions" / self._sanitize_name(session_name)
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _resolve_runtime(self, agent_id: str, group_id: Optional[str]) -> tuple[str, Optional[RuntimeRecord]]:
        runtime_key, _, _ = self._runtime_identity(agent_id, group_id)
        return runtime_key, self.runtimes.get(runtime_key)

    def _ensure_runtime(self, agent_id: str, group_id: Optional[str]) -> RuntimeRecord:
        runtime_key, scope, owner_id = self._runtime_identity(agent_id, group_id)
        with self._state_lock:
            runtime = self.runtimes.get(runtime_key)
            if runtime is not None:
                with runtime.lock:
                    runtime.last_seen = utcnow_iso()
                    runtime.member_agent_ids.add(agent_id)
                return runtime

            runtime_dir = self._runtime_storage_dir(scope, owner_id)
            workspace_dir = self.shared_workspace_dir or (runtime_dir / "workspace")
            workspace_dir.mkdir(parents=True, exist_ok=True)
            runtime = RuntimeRecord(
                runtime_key=runtime_key,
                scope=scope,
                owner_id=owner_id,
                agent_id=agent_id,
                group_id=group_id,
                root_dir=str(runtime_dir.resolve()),
                workspace_dir=str(workspace_dir.resolve()),
                created_at=utcnow_iso(),
                last_seen=utcnow_iso(),
            )
            runtime.member_agent_ids.add(agent_id)
            self.runtimes[runtime_key] = runtime
            self._audit(
                "runtime_created",
                runtime_key=runtime_key,
                scope=scope,
                owner_id=owner_id,
                agent_id=agent_id,
                group_id=group_id,
                workspace_dir=runtime.workspace_dir,
            )
            return runtime

    @staticmethod
    def _resolve_cwd(runtime: RuntimeRecord, cwd: Optional[str]) -> str:
        if not cwd:
            return runtime.workspace_dir
        path = Path(cwd).expanduser()
        if path.is_absolute():
            return str(path.resolve())
        return str((Path(runtime.workspace_dir) / path).resolve())

    def _write_execution_metadata(self, record: ExecutionRecord) -> None:
        self._write_json(Path(record.metadata_path), record.to_public_dict())

    def _write_terminal_metadata(self, record: TerminalRecord) -> None:
        self._write_json(Path(record.metadata_path), record.to_public_dict())

    def _create_artifact(
        self,
        base_dir: Path,
        collection: list[dict[str, Any]],
        kind: str,
        suffix: str,
        content: str,
    ) -> dict[str, Any]:
        artifact_id = uuid.uuid4().hex
        artifact_path = base_dir / f"{kind}_{artifact_id}{suffix}"
        ensure_parent(artifact_path)
        with artifact_path.open("w", encoding="utf-8") as handle:
            handle.write(content)
        artifact = {
            "artifact_id": artifact_id,
            "type": kind,
            "path": str(artifact_path.resolve()),
            "bytes": len(content.encode("utf-8", errors="replace")),
            "created_at": utcnow_iso(),
        }
        collection.append(artifact)
        return artifact

    def _preview_output(
        self,
        base_dir: Path,
        collection: list[dict[str, Any]],
        output: dict[str, Any],
    ) -> tuple[dict[str, Any], int]:
        serialized = json.dumps(output, ensure_ascii=False, default=json_default)
        encoded = serialized.encode("utf-8", errors="replace")
        if len(encoded) <= self.max_single_output_bytes:
            return output, len(encoded)

        if output.get("type") == "stream":
            text = output.get("text", "")
            artifact = self._create_artifact(base_dir, collection, "stream", ".txt", text)
            preview = dict(output)
            preview["text"] = text[:1024] + ("\n...[truncated]" if len(text) > 1024 else "")
            preview["artifact"] = artifact
            preview_size = len(json.dumps(preview, ensure_ascii=False, default=json_default).encode("utf-8"))
            return preview, preview_size

        artifact = self._create_artifact(base_dir, collection, "output", ".json", serialized)
        preview = {
            "type": output.get("type", "output"),
            "artifact": artifact,
            "summary": "Output externalized because it exceeded the inline size limit.",
        }
        preview_size = len(json.dumps(preview, ensure_ascii=False, default=json_default).encode("utf-8"))
        return preview, preview_size

    def _append_execution_output(self, record: ExecutionRecord, output: dict[str, Any]) -> None:
        execution_dir = self._execution_dir(record.execution_id)
        payload = {"timestamp": utcnow_iso(), **output}
        with record.lock:
            self._append_jsonl(Path(record.output_log_path), payload)
            preview, preview_size = self._preview_output(execution_dir, record.artifacts, output)
            record.total_output_messages += 1
            record.total_output_bytes += preview_size
            record.last_output_at = utcnow_iso()
            record.last_output_monotonic = monotonic_now()
            under_message_limit = len(record.outputs) < self.max_output_messages
            under_byte_limit = record.total_output_bytes <= self.max_total_output_bytes
            if under_message_limit and under_byte_limit:
                record.outputs.append(preview)
            elif not record.output_preview_truncated:
                record.output_preview_truncated = True
                record.outputs.append(
                    {
                        "type": "system",
                        "text": "Output preview truncated. Use python_output() for the full stream.",
                    }
                )
            self._write_execution_metadata(record)

    def _append_terminal_output(self, record: TerminalRecord, output: dict[str, Any]) -> None:
        terminal_dir = self._terminal_dir(record.terminal_id)
        payload = {"timestamp": utcnow_iso(), **output}
        with record.lock:
            self._append_jsonl(Path(record.output_log_path), payload)
            preview, preview_size = self._preview_output(terminal_dir, record.artifacts, output)
            record.total_output_messages += 1
            record.total_output_bytes += preview_size
            record.last_output_at = utcnow_iso()
            record.last_output_monotonic = monotonic_now()
            under_message_limit = len(record.outputs) < self.max_output_messages
            under_byte_limit = record.total_output_bytes <= self.max_total_output_bytes
            if under_message_limit and under_byte_limit:
                record.outputs.append(preview)
            elif not record.output_preview_truncated:
                record.output_preview_truncated = True
                record.outputs.append(
                    {
                        "type": "system",
                        "text": "Output preview truncated. Use terminal_read() for the full stream.",
                    }
                )
            self._write_terminal_metadata(record)

    def _load_output_page(self, path: Path, cursor: int = 0, limit: int = DEFAULT_OUTPUT_PAGE_SIZE) -> dict[str, Any]:
        items: list[dict[str, Any]] = []
        next_cursor = cursor
        if not path.exists():
            return {"items": items, "cursor": cursor, "next_cursor": cursor, "has_more": False}

        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle):
                if line_number < cursor:
                    continue
                if len(items) >= limit:
                    break
                next_cursor = line_number + 1
                items.append(json.loads(line))

        has_more = False
        with path.open("r", encoding="utf-8") as handle:
            for line_number, _ in enumerate(handle):
                if line_number >= next_cursor:
                    has_more = True
                    break

        return {"items": items, "cursor": cursor, "next_cursor": next_cursor, "has_more": has_more}

    def _session_key(self, runtime_key: str, session_name: str) -> tuple[str, str]:
        return runtime_key, self._sanitize_name(session_name)

    def _spawn_session_worker(self, runtime: RuntimeRecord, session_name: str) -> SessionRecord:
        if not self.worker_script_path.exists():
            raise RuntimeError(f"Worker script not found: {self.worker_script_path}")

        sanitized_name = self._sanitize_name(session_name)
        session_dir = self._session_storage_dir(runtime, sanitized_name)
        artifact_dir = session_dir / "artifacts"
        artifact_dir.mkdir(parents=True, exist_ok=True)

        process = subprocess.Popen(
            [self.python_executable, "-u", str(self.worker_script_path), "--cwd", runtime.workspace_dir],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            start_new_session=True,
        )
        if process.stdin is None or process.stdout is None or process.stderr is None:
            raise RuntimeError("Failed to create worker pipes.")

        session = SessionRecord(
            runtime_key=runtime.runtime_key,
            session_name=sanitized_name,
            workspace_dir=runtime.workspace_dir,
            artifact_dir=str(artifact_dir.resolve()),
            process=process,
            created_at=utcnow_iso(),
            last_seen=utcnow_iso(),
        )

        threading.Thread(
            target=self._worker_stdout_reader,
            args=(session,),
            name=f"v2-python-worker-stdout-{runtime.runtime_key}-{sanitized_name}",
            daemon=True,
        ).start()
        threading.Thread(
            target=self._worker_stderr_reader,
            args=(session,),
            name=f"v2-python-worker-stderr-{runtime.runtime_key}-{sanitized_name}",
            daemon=True,
        ).start()
        threading.Thread(
            target=self._worker_monitor,
            args=(session,),
            name=f"v2-python-worker-monitor-{runtime.runtime_key}-{sanitized_name}",
            daemon=True,
        ).start()

        if not session.ready_event.wait(self.startup_timeout_seconds):
            self._terminate_session_process(session, force=True)
            try:
                session.process.wait(timeout=1)
            except Exception:
                pass
            self._close_popen_streams(session.process)
            raise RuntimeError(
                self._build_startup_error(
                    session,
                    fallback=(
                        f"Python worker for runtime {runtime.runtime_key!r} session {sanitized_name!r} "
                        f"did not become ready in {self.startup_timeout_seconds}s."
                    ),
                )
            )

        if not session.ready_received or session.process.poll() is not None or session.runtime_state != "idle":
            try:
                session.process.wait(timeout=1)
            except Exception:
                pass
            self._close_popen_streams(session.process)
            raise RuntimeError(
                self._build_startup_error(
                    session,
                    fallback=(
                        f"Python worker for runtime {runtime.runtime_key!r} session {sanitized_name!r} "
                        "exited before signaling readiness."
                    ),
                )
            )

        self.sessions[self._session_key(runtime.runtime_key, sanitized_name)] = session
        self._audit(
            "python_session_created",
            runtime_key=runtime.runtime_key,
            session_name=sanitized_name,
            workspace_dir=runtime.workspace_dir,
            artifact_dir=session.artifact_dir,
            pid=process.pid,
        )
        return session

    def _is_session_alive(self, session: SessionRecord) -> bool:
        alive = session.process.poll() is None
        if not alive:
            session.runtime_state = "dead"
        return alive

    def _build_startup_error(self, session: SessionRecord, fallback: str) -> str:
        with session.lock:
            if session.startup_error:
                return session.startup_error
        return fallback

    def _ensure_session(self, agent_id: str, group_id: Optional[str], session_name: str, restart_dirty: bool = False) -> SessionRecord:
        runtime = self._ensure_runtime(agent_id, group_id)
        session_key = self._session_key(runtime.runtime_key, session_name)
        with self._state_lock:
            session = self.sessions.get(session_key)
            if session is None:
                return self._spawn_session_worker(runtime, session_name)
            session.last_seen = utcnow_iso()
            if restart_dirty and session.dirty_after_interrupt and not session.busy:
                self._close_session_locked(session_key, force=True)
                return self._spawn_session_worker(runtime, session_name)
            if self._is_session_alive(session):
                return session
            self.sessions.pop(session_key, None)
            return self._spawn_session_worker(runtime, session_name)

    def _worker_stdout_reader(self, session: SessionRecord) -> None:
        stdout = session.process.stdout
        assert stdout is not None
        for raw_line in stdout:
            line = raw_line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                self._audit("worker_protocol_error", runtime_key=session.runtime_key, session_name=session.session_name, raw_line=line)
                continue
            self._handle_worker_message(session, message)

    def _worker_stderr_reader(self, session: SessionRecord) -> None:
        stderr = session.process.stderr
        assert stderr is not None
        for raw_line in stderr:
            line = raw_line.rstrip("\n")
            if not line:
                continue
            with session.lock:
                if not session.ready_received:
                    session.startup_messages.append(line)
                    session.startup_messages = session.startup_messages[-10:]
                    session.startup_error = "Python worker failed during startup:\n" + "\n".join(session.startup_messages)
                active_execution_id = session.active_execution_id
            if active_execution_id and active_execution_id in self.executions:
                self._append_execution_output(
                    self.executions[active_execution_id],
                    {"type": "stream", "name": "worker-stderr", "text": line + "\n"},
                )
            self._audit(
                "worker_stderr",
                runtime_key=session.runtime_key,
                session_name=session.session_name,
                text=line,
            )

    def _handle_worker_message(self, session: SessionRecord, message: dict[str, Any]) -> None:
        msg_type = message.get("type")
        if msg_type == "worker_ready":
            with session.lock:
                session.runtime_state = "idle"
                session.last_seen = utcnow_iso()
                session.ready_received = True
                session.startup_error = None
                session.ready_event.set()
            return

        if msg_type == "session_stream":
            with session.lock:
                active_execution_id = session.active_execution_id
            if active_execution_id and active_execution_id in self.executions:
                self._append_execution_output(
                    self.executions[active_execution_id],
                    {
                        "type": "stream",
                        "name": message.get("name", "session"),
                        "text": message.get("text", ""),
                    },
                )
            else:
                self._audit(
                    "python_session_stream",
                    runtime_key=session.runtime_key,
                    session_name=session.session_name,
                    name=message.get("name", "session"),
                    text=message.get("text", ""),
                )
            return

        execution_id = message.get("execution_id")
        if not execution_id:
            self._audit(
                "worker_message_without_execution",
                runtime_key=session.runtime_key,
                session_name=session.session_name,
                message=message,
            )
            return
        record = self.executions.get(execution_id)
        if record is None:
            self._audit(
                "worker_message_unknown_execution",
                runtime_key=session.runtime_key,
                session_name=session.session_name,
                execution_id=execution_id,
            )
            return

        if msg_type == "stream":
            self._append_execution_output(
                record,
                {"type": "stream", "name": message.get("name", "stdout"), "text": message.get("text", "")},
            )
            return

        if msg_type == "execute_result":
            self._append_execution_output(
                record,
                {"type": "execute_result", "data": dict(message.get("data", {}))},
            )
            return

        if msg_type == "error":
            self._append_execution_output(
                record,
                {
                    "type": "error",
                    "ename": message.get("ename", ""),
                    "evalue": message.get("evalue", ""),
                    "traceback": list(message.get("traceback", [])),
                },
            )
            return

        if msg_type == "execution_finished":
            status = message.get("status", "failed")
            if record.timed_out and status == "interrupted":
                status = "timed_out"
            self._mark_execution_finished(session, record, status=status, error_summary=message.get("error_summary"))
            return

        self._audit(
            "worker_message_unknown_type",
            runtime_key=session.runtime_key,
            session_name=session.session_name,
            message=message,
        )

    def _worker_monitor(self, session: SessionRecord) -> None:
        return_code = session.process.wait()
        with session.lock:
            session.runtime_state = "dead"
            session.ready_event.set()
        active_execution_id = session.active_execution_id
        if active_execution_id:
            record = self.executions.get(active_execution_id)
            if record and not record.done_event.is_set():
                status = "timed_out" if record.timed_out else "kernel_lost"
                summary = record.error_summary or f"Python worker exited unexpectedly with code {return_code}."
                self._mark_execution_finished(session, record, status=status, error_summary=summary)
        self._audit(
            "python_session_worker_exited",
            runtime_key=session.runtime_key,
            session_name=session.session_name,
            return_code=return_code,
        )

    def _mark_execution_finished(
        self,
        session: SessionRecord,
        record: ExecutionRecord,
        status: str,
        error_summary: Optional[str] = None,
    ) -> None:
        with record.lock:
            if record.done_event.is_set():
                return
            if record.timed_out and status == "interrupted":
                status = "timed_out"
            record.status = status
            record.error_summary = error_summary
            record.end_time = utcnow_iso()
            self._write_execution_metadata(record)
            record.done_event.set()
        with session.lock:
            if session.active_execution_id == record.execution_id:
                session.busy = False
                session.active_execution_id = None
            session.last_seen = utcnow_iso()
            if status in {"interrupted", "timed_out"}:
                session.dirty_after_interrupt = True
            if self._is_session_alive(session):
                session.runtime_state = "idle"
        self._audit(
            "python_execution_finished",
            execution_id=record.execution_id,
            runtime_key=record.runtime_key,
            agent_id=record.agent_id,
            group_id=record.group_id,
            session_name=record.session_name,
            status=status,
            timed_out=record.timed_out,
            error_summary=error_summary,
        )

    def _send_to_worker(self, session: SessionRecord, payload: dict[str, Any]) -> None:
        stdin = session.process.stdin
        if stdin is None:
            raise RuntimeError("Worker stdin is unavailable.")
        stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
        stdin.flush()

    def _execution_timeout_watcher(self, session: SessionRecord, record: ExecutionRecord) -> None:
        if record.done_event.wait(record.hard_timeout_seconds):
            return
        with record.lock:
            if record.done_event.is_set():
                return
            record.timed_out = True
            record.error_summary = f"Execution exceeded hard timeout ({record.hard_timeout_seconds}s)."
            self._write_execution_metadata(record)
        with session.lock:
            session.dirty_after_interrupt = True
        self._interrupt_session_process(session)
        if record.done_event.wait(2):
            return
        self._terminate_session_process(session, force=True)

    def _interrupt_session_process(self, session: SessionRecord) -> bool:
        if session.process.poll() is not None:
            return False
        try:
            os.killpg(session.process.pid, signal.SIGINT)
        except ProcessLookupError:
            return False
        return True

    def _terminate_session_process(self, session: SessionRecord, force: bool) -> bool:
        if session.process.poll() is not None:
            return False
        sig = signal.SIGKILL if force else signal.SIGTERM
        try:
            os.killpg(session.process.pid, sig)
        except ProcessLookupError:
            return False
        return True

    @staticmethod
    def _close_popen_streams(proc: subprocess.Popen[str]) -> None:
        for stream_name in ("stdin", "stdout", "stderr"):
            stream = getattr(proc, stream_name, None)
            if stream is None:
                continue
            try:
                stream.close()
            except Exception:
                pass

    def python_exec(
        self,
        agent_id: str,
        code: str,
        session_name: str = "default",
        group_id: Optional[str] = None,
        wait_timeout_seconds: Optional[int] = None,
        hard_timeout_seconds: Optional[int] = None,
        background_on_timeout: bool = True,
    ) -> dict[str, Any]:
        error = self._validate_agent_id(agent_id)
        if error:
            return {
                "execution_id": None,
                "agent_id": agent_id,
                "group_id": group_id,
                "session_name": session_name,
                "status": "failed",
                "timed_out": False,
                "backgrounded": False,
                "start_time": utcnow_iso(),
                "end_time": utcnow_iso(),
                "outputs": [],
                "artifacts": [],
                "error_summary": error,
            }

        try:
            session = self._ensure_session(agent_id, group_id, session_name, restart_dirty=True)
        except Exception as exc:
            return {
                "execution_id": None,
                "agent_id": agent_id,
                "group_id": group_id,
                "session_name": session_name,
                "status": "failed",
                "timed_out": False,
                "backgrounded": False,
                "start_time": utcnow_iso(),
                "end_time": utcnow_iso(),
                "outputs": [],
                "artifacts": [],
                "error_summary": f"Failed to prepare python session: {exc}",
            }

        wait_timeout = wait_timeout_seconds if wait_timeout_seconds is not None else 1
        hard_timeout = hard_timeout_seconds or self.hard_timeout_seconds
        session_name_sanitized = self._sanitize_name(session_name)

        with session.lock:
            if session.busy:
                return {
                    "execution_id": None,
                    "runtime_key": session.runtime_key,
                    "agent_id": agent_id,
                    "group_id": group_id,
                    "session_name": session_name_sanitized,
                    "status": "failed",
                    "timed_out": False,
                    "backgrounded": False,
                    "start_time": utcnow_iso(),
                    "end_time": utcnow_iso(),
                    "outputs": [],
                    "artifacts": [],
                    "error_summary": f"Python session {session_name_sanitized!r} is busy with execution {session.active_execution_id}.",
                }
            session.busy = True
            session.active_execution_id = uuid.uuid4().hex
            session.execution_count += 1
            session.last_seen = utcnow_iso()
            session.runtime_state = "running"
            execution_id = session.active_execution_id

        execution_dir = self._execution_dir(execution_id)
        record = ExecutionRecord(
            execution_id=execution_id,
            runtime_key=session.runtime_key,
            agent_id=agent_id,
            group_id=group_id,
            session_name=session_name_sanitized,
            code=code,
            wait_timeout_seconds=wait_timeout,
            hard_timeout_seconds=hard_timeout,
            idle_output_timeout_seconds=self.idle_output_timeout_seconds,
            background_on_timeout=background_on_timeout,
            output_log_path=str((execution_dir / "outputs.jsonl").resolve()),
            metadata_path=str((execution_dir / "metadata.json").resolve()),
        )
        self.executions[execution_id] = record
        self._write_execution_metadata(record)
        self._audit(
            "python_execution_submitted",
            execution_id=execution_id,
            runtime_key=session.runtime_key,
            agent_id=agent_id,
            group_id=group_id,
            session_name=session_name_sanitized,
            wait_timeout_seconds=wait_timeout,
            hard_timeout_seconds=hard_timeout,
        )

        try:
            self._send_to_worker(
                session,
                {"command": "execute", "execution_id": execution_id, "code": code},
            )
        except Exception as exc:
            self._mark_execution_finished(session, record, status="failed", error_summary=f"Failed to send code: {exc!r}")
            return record.to_public_dict()

        threading.Thread(
            target=self._execution_timeout_watcher,
            args=(session, record),
            name=f"v2-execution-timeout-{execution_id}",
            daemon=True,
        ).start()

        if record.done_event.wait(wait_timeout):
            return record.to_public_dict()

        if background_on_timeout:
            with record.lock:
                record.backgrounded = True
                self._write_execution_metadata(record)
            self._audit(
                "python_execution_backgrounded",
                execution_id=execution_id,
                runtime_key=session.runtime_key,
                agent_id=agent_id,
                group_id=group_id,
                session_name=session_name_sanitized,
            )
            return record.to_public_dict()

        self.python_interrupt(execution_id)
        record.done_event.wait(2)
        return record.to_public_dict()

    def python_get(self, execution_id: str) -> dict[str, Any]:
        record = self.executions.get(execution_id)
        if record is None:
            return {
                "execution_id": execution_id,
                "status": "failed",
                "error_summary": "Execution not found.",
                "outputs": [],
                "artifacts": [],
            }
        return record.to_public_dict()

    def python_output(self, execution_id: str, cursor: int = 0, limit: int = DEFAULT_OUTPUT_PAGE_SIZE) -> dict[str, Any]:
        record = self.executions.get(execution_id)
        if record is None:
            return {
                "execution_id": execution_id,
                "cursor": cursor,
                "next_cursor": cursor,
                "has_more": False,
                "items": [],
                "error_summary": "Execution not found.",
            }
        page = self._load_output_page(Path(record.output_log_path), cursor=cursor, limit=limit)
        page["execution_id"] = execution_id
        page["status"] = record.status
        return page

    def python_interrupt(self, execution_id: str) -> bool:
        record = self.executions.get(execution_id)
        if record is None:
            return False
        session = self.sessions.get(self._session_key(record.runtime_key, record.session_name))
        if session is None:
            return False
        with record.lock:
            record.interrupt_requested = True
        with session.lock:
            session.dirty_after_interrupt = True
        self._audit(
            "python_execution_interrupt_requested",
            execution_id=execution_id,
            runtime_key=record.runtime_key,
            agent_id=record.agent_id,
            group_id=record.group_id,
            session_name=record.session_name,
        )
        return self._interrupt_session_process(session)

    def _close_session_locked(self, session_key: tuple[str, str], force: bool = False) -> bool:
        session = self.sessions.get(session_key)
        if session is None:
            return False
        with session.lock:
            if session.busy and not force:
                return False
            active_execution_id = session.active_execution_id

        if active_execution_id and force:
            self.python_interrupt(active_execution_id)
            record = self.executions.get(active_execution_id)
            if record:
                record.done_event.wait(2)

        try:
            self._send_to_worker(session, {"command": "shutdown"})
        except Exception:
            pass
        time.sleep(0.2)
        if session.process.poll() is None:
            self._terminate_session_process(session, force=True)
        try:
            session.process.wait(timeout=2)
        except Exception:
            pass
        self._close_popen_streams(session.process)
        self.sessions.pop(session_key, None)
        self._audit(
            "python_session_closed",
            runtime_key=session.runtime_key,
            session_name=session.session_name,
            forced=force,
        )
        return True

    def python_restart(self, agent_id: str, session_name: str = "default", group_id: Optional[str] = None) -> bool:
        error = self._validate_agent_id(agent_id)
        if error:
            return False
        runtime = self._ensure_runtime(agent_id, group_id)
        session_key = self._session_key(runtime.runtime_key, session_name)
        with self._state_lock:
            self._close_session_locked(session_key, force=True)
            self._spawn_session_worker(runtime, session_name)
        self._audit(
            "python_session_restarted",
            runtime_key=runtime.runtime_key,
            agent_id=agent_id,
            group_id=group_id,
            session_name=self._sanitize_name(session_name),
        )
        return True

    def python_session_info(self, agent_id: str, session_name: str = "default", group_id: Optional[str] = None) -> dict[str, Any]:
        error = self._validate_agent_id(agent_id)
        if error:
            return {"agent_id": agent_id, "group_id": group_id, "session_name": session_name, "error_summary": error}
        runtime_key, runtime = self._resolve_runtime(agent_id, group_id)
        if runtime is None:
            return {
                "runtime_key": runtime_key,
                "agent_id": agent_id,
                "group_id": group_id,
                "session_name": self._sanitize_name(session_name),
                "error_summary": "Runtime not found.",
            }
        session = self.sessions.get(self._session_key(runtime.runtime_key, session_name))
        if session is None:
            return {
                "runtime_key": runtime.runtime_key,
                "agent_id": agent_id,
                "group_id": group_id,
                "session_name": self._sanitize_name(session_name),
                "workspace_dir": runtime.workspace_dir,
                "error_summary": "Python session not found.",
            }
        with session.lock:
            data = session.to_public_dict()
        data["agent_id"] = agent_id
        data["group_id"] = group_id
        return data

    def close_all_sessions(self) -> None:
        for session_key in list(self.sessions.keys()):
            self._close_session_locked(session_key, force=True)

    @staticmethod
    def _close_pty_master(record: TerminalRecord) -> None:
        with record.lock:
            fd = record.pty_master_fd
            record.pty_master_fd = None
        if fd is None:
            return
        try:
            os.close(fd)
        except OSError:
            pass

    def _pty_reader(self, record: TerminalRecord) -> None:
        proc = record.process
        fd = record.pty_master_fd
        if proc is None or fd is None:
            return
        try:
            while True:
                if proc.poll() is not None:
                    ready, _, _ = select.select([fd], [], [], 0.05)
                    if not ready:
                        break
                else:
                    ready, _, _ = select.select([fd], [], [], 0.1)
                    if not ready:
                        continue
                try:
                    chunk = os.read(fd, 4096)
                except OSError as exc:
                    if exc.errno in {errno.EIO, errno.EBADF}:
                        break
                    raise
                if not chunk:
                    break
                self._append_terminal_output(
                    record,
                    {
                        "type": "stream",
                        "name": "terminal",
                        "text": chunk.decode("utf-8", errors="replace"),
                    },
                )
        finally:
            self._close_pty_master(record)

    def _terminal_watcher(self, record: TerminalRecord) -> None:
        deadline = monotonic_now() + record.hard_timeout_seconds
        proc = record.process
        assert proc is not None

        while True:
            return_code = proc.poll()
            if return_code is not None:
                with record.lock:
                    record.return_code = return_code
                    record.end_time = utcnow_iso()
                    if record.terminate_requested and return_code != 0 and not record.timed_out:
                        record.status = "interrupted"
                        record.error_summary = "Terminal terminated by request."
                    elif record.timed_out:
                        record.status = "timed_out"
                    elif return_code == 0:
                        record.status = "succeeded"
                    else:
                        record.status = "failed"
                        record.error_summary = record.error_summary or f"Terminal exited with code {return_code}."
                    self._write_terminal_metadata(record)
                    record.done_event.set()
                self._close_pty_master(record)
                self._audit(
                    "terminal_finished",
                    terminal_id=record.terminal_id,
                    runtime_key=record.runtime_key,
                    agent_id=record.agent_id,
                    group_id=record.group_id,
                    status=record.status,
                    return_code=return_code,
                )
                return

            if monotonic_now() >= deadline:
                with record.lock:
                    record.timed_out = True
                    record.error_summary = f"Terminal exceeded hard timeout ({record.hard_timeout_seconds}s) and was terminated."
                    self._write_terminal_metadata(record)
                self._terminate_terminal_record(record, force=True)
                time.sleep(0.1)

            time.sleep(0.1)

    def _terminate_terminal_record(self, record: TerminalRecord, force: bool) -> bool:
        proc = record.process
        if proc is None or proc.poll() is not None:
            return False
        sig = signal.SIGKILL if force else signal.SIGTERM
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            return False
        return True

    def terminal_open(
        self,
        agent_id: str,
        name: Optional[str] = None,
        group_id: Optional[str] = None,
        cwd: Optional[str] = None,
        shell: Optional[str] = None,
        env: Optional[dict[str, str]] = None,
        wait_timeout_seconds: Optional[int] = None,
        hard_timeout_seconds: Optional[int] = None,
    ) -> dict[str, Any]:
        error = self._validate_agent_id(agent_id)
        if error:
            return {
                "terminal_id": None,
                "agent_id": agent_id,
                "group_id": group_id,
                "status": "failed",
                "timed_out": False,
                "backgrounded": False,
                "start_time": utcnow_iso(),
                "end_time": utcnow_iso(),
                "outputs": [],
                "artifacts": [],
                "error_summary": error,
            }

        runtime = self._ensure_runtime(agent_id, group_id)
        terminal_id = uuid.uuid4().hex
        terminal_name = self._sanitize_name(name or f"terminal-{terminal_id[:8]}")
        wait_timeout = wait_timeout_seconds or self.wait_timeout_seconds
        hard_timeout = hard_timeout_seconds or self.hard_timeout_seconds
        effective_cwd = self._resolve_cwd(runtime, cwd)
        shell_command = shell or os.environ.get("SHELL") or "/bin/bash"
        argv = shlex.split(shell_command)
        if not argv:
            argv = ["/bin/bash"]
        if len(argv) == 1:
            argv.append("-i")

        env_map = dict(os.environ)
        env_overrides = {str(key): str(value) for key, value in (env or {}).items()}
        env_map.update(env_overrides)

        terminal_dir = self._terminal_dir(terminal_id)
        master_fd, slave_fd = pty.openpty()
        slave_name = os.ttyname(slave_fd)
        try:
            proc = subprocess.Popen(
                argv,
                cwd=effective_cwd,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                text=False,
                start_new_session=True,
                env=env_map,
            )
        finally:
            os.close(slave_fd)

        record = TerminalRecord(
            terminal_id=terminal_id,
            runtime_key=runtime.runtime_key,
            agent_id=agent_id,
            group_id=group_id,
            name=terminal_name,
            cwd=effective_cwd,
            shell=" ".join(argv),
            wait_timeout_seconds=wait_timeout,
            hard_timeout_seconds=hard_timeout,
            output_log_path=str((terminal_dir / "outputs.jsonl").resolve()),
            metadata_path=str((terminal_dir / "metadata.json").resolve()),
            workspace_dir=runtime.workspace_dir,
            env_overrides=env_overrides,
            pid=proc.pid,
            pty_master_fd=master_fd,
            pty_slave_name=slave_name,
            process=proc,
        )
        self.terminals[terminal_id] = record
        self._write_terminal_metadata(record)
        self._audit(
            "terminal_opened",
            terminal_id=terminal_id,
            runtime_key=runtime.runtime_key,
            agent_id=agent_id,
            group_id=group_id,
            name=terminal_name,
            cwd=effective_cwd,
            shell=record.shell,
            pid=proc.pid,
        )

        threading.Thread(
            target=self._pty_reader,
            args=(record,),
            name=f"v2-terminal-reader-{terminal_id}",
            daemon=True,
        ).start()
        threading.Thread(
            target=self._terminal_watcher,
            args=(record,),
            name=f"v2-terminal-watcher-{terminal_id}",
            daemon=True,
        ).start()

        if record.done_event.wait(wait_timeout):
            return record.to_public_dict()

        with record.lock:
            record.backgrounded = True
            self._write_terminal_metadata(record)
        self._audit(
            "terminal_backgrounded",
            terminal_id=terminal_id,
            runtime_key=runtime.runtime_key,
            agent_id=agent_id,
            group_id=group_id,
        )
        return record.to_public_dict()

    def terminal_info(self, terminal_id: str) -> dict[str, Any]:
        record = self.terminals.get(terminal_id)
        if record is None:
            return {
                "terminal_id": terminal_id,
                "status": "failed",
                "error_summary": "Terminal not found.",
                "outputs": [],
                "artifacts": [],
            }
        return record.to_public_dict()

    def terminal_read(self, terminal_id: str, cursor: int = 0, limit: int = DEFAULT_OUTPUT_PAGE_SIZE) -> dict[str, Any]:
        record = self.terminals.get(terminal_id)
        if record is None:
            return {
                "terminal_id": terminal_id,
                "cursor": cursor,
                "next_cursor": cursor,
                "has_more": False,
                "items": [],
                "error_summary": "Terminal not found.",
            }
        page = self._load_output_page(Path(record.output_log_path), cursor=cursor, limit=limit)
        page["terminal_id"] = terminal_id
        page["status"] = record.status
        return page

    def terminal_write(
        self,
        terminal_id: str,
        text: str,
        append_newline: bool = False,
        wait_timeout_seconds: float = 0.2,
        limit: int = DEFAULT_OUTPUT_PAGE_SIZE,
    ) -> dict[str, Any]:
        record = self.terminals.get(terminal_id)
        if record is None:
            return {
                "ok": False,
                "terminal_id": terminal_id,
                "bytes_written": 0,
                "error_summary": "Terminal not found.",
                "output": {"items": [], "cursor": 0, "next_cursor": 0, "has_more": False},
            }
        payload = text + ("\n" if append_newline else "")
        with record.lock:
            start_cursor = record.total_output_messages
            proc = record.process
            fd = record.pty_master_fd
        if proc is None or proc.poll() is not None:
            return {
                "ok": False,
                "terminal_id": terminal_id,
                "bytes_written": 0,
                "error_summary": "Terminal is not running.",
                "output": self.terminal_read(terminal_id, cursor=start_cursor, limit=limit),
            }

        try:
            if fd is None:
                return {
                    "ok": False,
                    "terminal_id": terminal_id,
                    "bytes_written": 0,
                    "error_summary": "Terminal PTY is unavailable.",
                    "output": self.terminal_read(terminal_id, cursor=start_cursor, limit=limit),
                }
            bytes_written = os.write(fd, payload.encode("utf-8", errors="replace"))
        except Exception as exc:
            return {
                "ok": False,
                "terminal_id": terminal_id,
                "bytes_written": 0,
                "error_summary": f"Failed to write terminal input: {exc!r}",
                "output": self.terminal_read(terminal_id, cursor=start_cursor, limit=limit),
            }

        if wait_timeout_seconds > 0:
            time.sleep(wait_timeout_seconds)
        return {
            "ok": True,
            "terminal_id": terminal_id,
            "bytes_written": bytes_written,
            "status": self.terminal_info(terminal_id).get("status"),
            "output": self.terminal_read(terminal_id, cursor=start_cursor, limit=limit),
        }

    def terminal_interrupt(self, terminal_id: str) -> bool:
        record = self.terminals.get(terminal_id)
        if record is None:
            return False
        proc = record.process
        if proc is None or proc.poll() is not None:
            return False
        try:
            os.killpg(proc.pid, signal.SIGINT)
        except ProcessLookupError:
            return False
        self._audit(
            "terminal_interrupt_requested",
            terminal_id=terminal_id,
            runtime_key=record.runtime_key,
            agent_id=record.agent_id,
            group_id=record.group_id,
        )
        return True

    def terminal_close(self, terminal_id: str, force: bool = False) -> bool:
        record = self.terminals.get(terminal_id)
        if record is None:
            return False
        with record.lock:
            if record.status != "running":
                return True
            record.terminate_requested = True
        success = self._terminate_terminal_record(record, force=force)
        if success:
            self._audit(
                "terminal_close_requested",
                terminal_id=terminal_id,
                runtime_key=record.runtime_key,
                agent_id=record.agent_id,
                group_id=record.group_id,
                force=force,
            )
            record.done_event.wait(2)
        return success

    def close_all_terminals(self) -> None:
        for terminal_id in list(self.terminals.keys()):
            self.terminal_close(terminal_id, force=True)

    def list_agent_runtimes(self, verbose: bool = False) -> list[Any]:
        if not verbose:
            return sorted(self.runtimes.keys())
        items: list[dict[str, Any]] = []
        for runtime_key in sorted(self.runtimes.keys()):
            runtime = self.runtimes[runtime_key]
            session_count = sum(1 for (key, _), _session in self.sessions.items() if key == runtime_key)
            terminal_count = sum(1 for terminal in self.terminals.values() if terminal.runtime_key == runtime_key)
            items.append(runtime.to_public_dict(session_count=session_count, terminal_count=terminal_count))
        return items

    def cleanup_agent_runtime(self, agent_id: str, group_id: Optional[str] = None, force: bool = False) -> bool:
        error = self._validate_agent_id(agent_id)
        if error:
            return False
        runtime_key, runtime = self._resolve_runtime(agent_id, group_id)
        if runtime is None:
            return False

        session_keys = [key for key in self.sessions.keys() if key[0] == runtime_key]
        terminal_ids = [terminal_id for terminal_id, record in self.terminals.items() if record.runtime_key == runtime_key]

        if not force:
            for session_key in session_keys:
                session = self.sessions.get(session_key)
                if session and session.busy:
                    return False
            for terminal_id in terminal_ids:
                record = self.terminals.get(terminal_id)
                if record and record.status == "running":
                    return False

        for session_key in session_keys:
            self._close_session_locked(session_key, force=force)
        for terminal_id in terminal_ids:
            self.terminal_close(terminal_id, force=True if force else False)
            record = self.terminals.get(terminal_id)
            if force or record is None or record.status != "running":
                self.terminals.pop(terminal_id, None)

        self.runtimes.pop(runtime_key, None)
        self._audit(
            "runtime_cleaned_up",
            runtime_key=runtime_key,
            agent_id=agent_id,
            group_id=group_id,
            force=force,
        )
        return True


python_terminal_executor_v2 = PythonTerminalExecutorV2()
mcp = FastMCP("Python Terminal Executor V2") if FastMCP is not None else None


if mcp is not None:
    @mcp.tool(output_schema=None)
    def python_exec(
        agent_id: Annotated[str, "Required isolated agent ID. Same agent_id shares only its own private runtime unless group_id is set."],
        code: Annotated[str, "Python code to run in a persistent worker process."],
        session_name: Annotated[str, "Logical Python session name within the runtime."] = "default",
        group_id: Annotated[Optional[str], "Optional explicit shared runtime group ID."] = None,
        wait_timeout_seconds: Annotated[Optional[int], "Seconds to wait before returning running/backgrounded status."] = None,
        hard_timeout_seconds: Annotated[Optional[int], "Maximum lifetime for the execution before interrupting the worker."] = None,
        background_on_timeout: Annotated[bool, "Leave long-running code in the background after wait timeout when true."] = True,
    ) -> dict[str, Any]:
        return python_terminal_executor_v2.python_exec(
            agent_id=agent_id,
            code=code,
            session_name=session_name,
            group_id=group_id,
            wait_timeout_seconds=wait_timeout_seconds,
            hard_timeout_seconds=hard_timeout_seconds,
            background_on_timeout=background_on_timeout,
        )


    @mcp.tool(output_schema=None)
    def python_get(execution_id: Annotated[str, "Execution ID returned by python_exec()."]) -> dict[str, Any]:
        return python_terminal_executor_v2.python_get(execution_id)


    @mcp.tool(output_schema=None)
    def python_output(
        execution_id: Annotated[str, "Execution ID returned by python_exec()."],
        cursor: Annotated[Optional[int], "Output cursor from the previous page."] = None,
        limit: Annotated[Optional[int], "Maximum number of output entries to return."] = None,
    ) -> dict[str, Any]:
        return python_terminal_executor_v2.python_output(
            execution_id=execution_id,
            cursor=cursor or 0,
            limit=limit or DEFAULT_OUTPUT_PAGE_SIZE,
        )


    @mcp.tool(output_schema=None)
    def python_interrupt(execution_id: Annotated[str, "Execution to interrupt."]) -> bool:
        return python_terminal_executor_v2.python_interrupt(execution_id)


    @mcp.tool(output_schema=None)
    def python_restart(
        agent_id: Annotated[str, "Required isolated agent ID."],
        session_name: Annotated[str, "Logical Python session name within the runtime."] = "default",
        group_id: Annotated[Optional[str], "Optional explicit shared runtime group ID."] = None,
    ) -> bool:
        return python_terminal_executor_v2.python_restart(agent_id=agent_id, session_name=session_name, group_id=group_id)


    @mcp.tool(output_schema=None)
    def python_session_info(
        agent_id: Annotated[str, "Required isolated agent ID."],
        session_name: Annotated[str, "Logical Python session name within the runtime."] = "default",
        group_id: Annotated[Optional[str], "Optional explicit shared runtime group ID."] = None,
    ) -> dict[str, Any]:
        return python_terminal_executor_v2.python_session_info(agent_id=agent_id, session_name=session_name, group_id=group_id)


    @mcp.tool(output_schema=None)
    def terminal_open(
        agent_id: Annotated[str, "Required isolated agent ID."],
        name: Annotated[Optional[str], "Optional display name for this terminal."] = None,
        group_id: Annotated[Optional[str], "Optional explicit shared runtime group ID."] = None,
        cwd: Annotated[Optional[str], "Working directory. Relative paths resolve under the runtime workspace."] = None,
        shell: Annotated[Optional[str], "Shell command or executable to launch."] = None,
        env: Annotated[Optional[dict[str, str]], "Additional environment variables for this terminal only."] = None,
        wait_timeout_seconds: Annotated[Optional[int], "Seconds to wait before returning running/backgrounded status."] = None,
        hard_timeout_seconds: Annotated[Optional[int], "Maximum lifetime for the terminal before terminating it."] = None,
    ) -> dict[str, Any]:
        return python_terminal_executor_v2.terminal_open(
            agent_id=agent_id,
            name=name,
            group_id=group_id,
            cwd=cwd,
            shell=shell,
            env=env,
            wait_timeout_seconds=wait_timeout_seconds,
            hard_timeout_seconds=hard_timeout_seconds,
        )


    @mcp.tool(output_schema=None)
    def terminal_info(terminal_id: Annotated[str, "Terminal ID returned by terminal_open()."]) -> dict[str, Any]:
        return python_terminal_executor_v2.terminal_info(terminal_id)


    @mcp.tool(output_schema=None)
    def terminal_read(
        terminal_id: Annotated[str, "Terminal ID returned by terminal_open()."],
        cursor: Annotated[Optional[int], "Output cursor from the previous page."] = None,
        limit: Annotated[Optional[int], "Maximum number of output entries to return."] = None,
    ) -> dict[str, Any]:
        return python_terminal_executor_v2.terminal_read(
            terminal_id=terminal_id,
            cursor=cursor or 0,
            limit=limit or DEFAULT_OUTPUT_PAGE_SIZE,
        )


    @mcp.tool(output_schema=None)
    def terminal_write(
        terminal_id: Annotated[str, "Terminal ID returned by terminal_open()."],
        text: Annotated[str, "Text to write to the terminal PTY."],
        append_newline: Annotated[bool, "Append a trailing newline before sending."] = False,
        wait_timeout_seconds: Annotated[Optional[float], "How long to wait after writing before reading fresh output."] = None,
        limit: Annotated[Optional[int], "Maximum number of output chunks to return."] = None,
    ) -> dict[str, Any]:
        return python_terminal_executor_v2.terminal_write(
            terminal_id=terminal_id,
            text=text,
            append_newline=append_newline,
            wait_timeout_seconds=wait_timeout_seconds or 0.2,
            limit=limit or DEFAULT_OUTPUT_PAGE_SIZE,
        )


    @mcp.tool(output_schema=None)
    def terminal_interrupt(terminal_id: Annotated[str, "Terminal to interrupt with SIGINT."]) -> bool:
        return python_terminal_executor_v2.terminal_interrupt(terminal_id)


    @mcp.tool(output_schema=None)
    def terminal_close(
        terminal_id: Annotated[str, "Terminal to close."],
        force: Annotated[bool, "Use SIGKILL instead of SIGTERM."] = False,
    ) -> bool:
        return python_terminal_executor_v2.terminal_close(terminal_id, force=force)


    @mcp.tool(output_schema=None)
    def list_agent_runtimes(verbose: Annotated[bool, "Return runtime metadata when true."] = False) -> list[Any]:
        return python_terminal_executor_v2.list_agent_runtimes(verbose=verbose)


    @mcp.tool(output_schema=None)
    def cleanup_agent_runtime(
        agent_id: Annotated[str, "Required isolated agent ID."],
        group_id: Annotated[Optional[str], "Optional explicit shared runtime group ID."] = None,
        force: Annotated[bool, "Force cleanup even if sessions or terminals are still running."] = False,
    ) -> bool:
        return python_terminal_executor_v2.cleanup_agent_runtime(agent_id=agent_id, group_id=group_id, force=force)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8010)
    parser.add_argument("--host", type=str, default="127.0.0.1")
    parser.add_argument("--allow-remote", action="store_true", help="Allow binding to non-local hosts.")
    parser.add_argument("--runtime-dir", type=str, default="runtime_v2")
    parser.add_argument("--workspace-dir", type=str, default=os.environ.get("PYTHON_TERMINAL_MCP_WORKSPACE_DIR"))
    args = parser.parse_args()

    if args.host not in {"127.0.0.1", "localhost", "::1"} and not args.allow_remote:
        raise SystemExit("Refusing to bind a non-local host without --allow-remote.")

    python_terminal_executor_v2.configure_runtime(args.runtime_dir, workspace_dir=args.workspace_dir)

    if mcp is None:
        raise SystemExit("fastmcp is not installed. Install dependencies from requirements.txt before running the server.")
    mcp.run(transport="streamable-http", host=args.host, port=args.port)


if __name__ == "__main__":
    main()
