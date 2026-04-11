from __future__ import annotations

import argparse
import ast
import io
import json
import os
import sys
import threading
import traceback
from threading import Lock
from typing import Any


EMIT_LOCK = Lock()
THREAD_STATE = threading.local()
CONTROL_STDIN = sys.stdin
GLOBAL_NAMESPACE: dict[str, Any] = {
    "__name__": "__main__",
    "__builtins__": __builtins__,
}


def emit(payload: dict[str, Any]) -> None:
    with EMIT_LOCK:
        sys.__stdout__.write(json.dumps(payload, ensure_ascii=False) + "\n")
        sys.__stdout__.flush()


class StreamProxy(io.TextIOBase):
    def __init__(self, name: str) -> None:
        self.name = name

    def write(self, text: str) -> int:
        if not text:
            return 0
        execution_id = getattr(THREAD_STATE, "execution_id", None)
        if execution_id is None:
            emit({"type": "session_stream", "name": self.name, "text": text})
            return len(text)
        emit(
            {
                "type": "stream",
                "execution_id": execution_id,
                "name": self.name,
                "text": text,
            }
        )
        return len(text)

    def flush(self) -> None:
        return None


class DisabledStdin(io.TextIOBase):
    def _raise(self) -> None:
        raise EOFError("Interactive stdin is disabled in this automation worker.")

    def read(self, size: int = -1) -> str:
        self._raise()

    def readline(self, size: int = -1) -> str:
        self._raise()

    def readlines(self, hint: int = -1) -> list[str]:
        self._raise()

    def readable(self) -> bool:
        return False

    def isatty(self) -> bool:
        return False


ORIGINAL_THREAD_INIT = threading.Thread.__init__
ORIGINAL_THREAD_RUN = threading.Thread.run


def patch_thread_context_propagation() -> None:
    def patched_init(self, *args, **kwargs):
        ORIGINAL_THREAD_INIT(self, *args, **kwargs)
        self._mcp_execution_id = getattr(THREAD_STATE, "execution_id", None)

    def patched_run(self, *args, **kwargs):
        previous = getattr(THREAD_STATE, "execution_id", None)
        execution_id = getattr(self, "_mcp_execution_id", None)
        if execution_id is None:
            if hasattr(THREAD_STATE, "execution_id"):
                del THREAD_STATE.execution_id
        else:
            THREAD_STATE.execution_id = execution_id
        try:
            return ORIGINAL_THREAD_RUN(self, *args, **kwargs)
        finally:
            if previous is None:
                if hasattr(THREAD_STATE, "execution_id"):
                    del THREAD_STATE.execution_id
            else:
                THREAD_STATE.execution_id = previous

    threading.Thread.__init__ = patched_init
    threading.Thread.run = patched_run


def eval_last_expression(tree: ast.Module, execution_id: str) -> None:
    if not tree.body:
        return
    last_stmt = tree.body[-1]
    if not isinstance(last_stmt, ast.Expr):
        exec(compile(tree, "<mcp-exec>", "exec"), GLOBAL_NAMESPACE)
        return

    prefix = ast.Module(body=tree.body[:-1], type_ignores=[])
    if prefix.body:
        exec(compile(prefix, "<mcp-exec>", "exec"), GLOBAL_NAMESPACE)

    result = eval(compile(ast.Expression(last_stmt.value), "<mcp-exec>", "eval"), GLOBAL_NAMESPACE)
    if result is not None:
        emit(
            {
                "type": "execute_result",
                "execution_id": execution_id,
                "data": {"text/plain": repr(result)},
            }
        )


def run_code(execution_id: str, code: str) -> None:
    previous_execution_id = getattr(THREAD_STATE, "execution_id", None)
    previous_stdin = sys.stdin
    THREAD_STATE.execution_id = execution_id
    sys.stdin = DisabledStdin()
    try:
        tree = ast.parse(code, mode="exec")
        eval_last_expression(tree, execution_id)
    except KeyboardInterrupt:
        emit(
            {
                "type": "execution_finished",
                "execution_id": execution_id,
                "status": "interrupted",
                "error_summary": "Execution interrupted.",
            }
        )
        return
    except BaseException as exc:
        emit(
            {
                "type": "error",
                "execution_id": execution_id,
                "ename": exc.__class__.__name__,
                "evalue": str(exc),
                "traceback": traceback.format_exc().splitlines(),
            }
        )
        emit(
            {
                "type": "execution_finished",
                "execution_id": execution_id,
                "status": "failed",
                "error_summary": f"{exc.__class__.__name__}: {exc}",
            }
        )
        return
    finally:
        sys.stdin = previous_stdin
        if previous_execution_id is None:
            if hasattr(THREAD_STATE, "execution_id"):
                del THREAD_STATE.execution_id
        else:
            THREAD_STATE.execution_id = previous_execution_id

    emit({"type": "execution_finished", "execution_id": execution_id, "status": "succeeded"})


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cwd", type=str, required=True)
    args = parser.parse_args()

    os.makedirs(args.cwd, exist_ok=True)
    os.chdir(args.cwd)
    patch_thread_context_propagation()
    sys.stdout = StreamProxy("stdout")
    sys.stderr = StreamProxy("stderr")

    emit({"type": "worker_ready", "pid": os.getpid(), "cwd": os.getcwd()})

    for line in CONTROL_STDIN:
        if not line.strip():
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            emit({"type": "session_stream", "name": "stderr", "text": f"Invalid control message: {exc}\n"})
            continue

        command = message.get("command")
        if command == "shutdown":
            return
        if command == "execute":
            run_code(message["execution_id"], message["code"])
            continue
        emit({"type": "session_stream", "name": "stderr", "text": f"Unknown worker command: {command!r}\n"})


if __name__ == "__main__":
    main()
