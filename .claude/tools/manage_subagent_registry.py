#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_REGISTRY_PATH = "reports/subagent_registry.json"
ROLE_ALIASES = {
    "observation": "observation-subagent",
    "observation-subagent": "observation-subagent",
    "exploitation": "exploitation-subagent",
    "exploitation-subagent": "exploitation-subagent",
}
STATUS_ALIASES = {
    "in_progress": "running",
    "running": "running",
    "resume": "running",
    "paused": "waiting",
    "pending": "waiting",
    "waiting": "waiting",
    "done": "completed",
    "complete": "completed",
    "completed": "completed",
    "success": "completed",
    "failed": "failed",
    "blocked": "blocked",
    "needs_more_observation": "needs_more_observation",
}


def collapse_text(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def normalize_role(value: Any) -> str:
    role = collapse_text(value).lower()
    return ROLE_ALIASES.get(role, role)


def normalize_status(value: Any, action: Any = "") -> str:
    status = collapse_text(value).lower().replace("-", "_")
    if status:
        return STATUS_ALIASES.get(status, status)
    action_text = collapse_text(action).lower()
    if action_text in {"start", "resume"}:
        return "running"
    if action_text in {"stop", "finish", "complete"}:
        return "completed"
    return ""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Maintain the lightweight subagent owner registry.")
    parser.add_argument("--registry", default=DEFAULT_REGISTRY_PATH, help="Path to reports/subagent_registry.json")
    parser.add_argument("--role", default="", help="Role name, canonical or legacy alias")
    parser.add_argument("--action", default="", help="Legacy no-op action name such as start/stop")
    parser.add_argument("--owner-id", "--owner_id", default="", help="Claude agentId if known")
    parser.add_argument("--vector-slug", "--vector_slug", default="", help="Stable vector slug, e.g. auth_login or upload_stage1")
    parser.add_argument(
        "--detail-report",
        "--detail_report",
        "--detail-path",
        "--detail_path",
        default="",
        help="Path to reports/exploitation/exploitation_<slug>.json",
    )
    parser.add_argument("--stage", default="", help="Current stage, e.g. checkpoint, stage1, stage2, followup")
    parser.add_argument("--status", default="", help="Current status, e.g. running, waiting, completed, blocked")
    parser.add_argument("--next-action", "--next_action", default="", help="Short next action or handoff note")
    parser.add_argument("--repair-in-place", "--repair_in_place", action="store_true", help="Coerce registry into canonical shape")
    parser.add_argument("--print-summary", "--print_summary", action="store_true", help="Print a compact JSON summary")
    args = parser.parse_args()
    args.role = normalize_role(args.role)
    args.status = normalize_status(args.status, args.action)
    if not args.repair_in_place and not args.role:
        parser.error("Either --role or --repair-in-place is required.")
    if args.role not in {"observation-subagent", "exploitation-subagent", ""}:
        parser.error("argument --role: expected observation-subagent or exploitation-subagent")
    if args.role == "exploitation-subagent" and not collapse_text(args.vector_slug) and not collapse_text(args.detail_report):
        parser.error("exploitation-subagent requires --vector-slug or --detail-report.")
    return args


def normalize_slug(value: Any) -> str:
    text = collapse_text(value).lower()
    text = re.sub(r"[^a-z0-9._-]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("._-")
    return text or "unknown"


def normalize_workspace_path(value: Any) -> str:
    text = collapse_text(value)
    prefix = "/home/kali/workspace/"
    if text.startswith(prefix):
        text = text[len(prefix) :]
    return text


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def empty_registry() -> dict[str, Any]:
    return {
        "observation_owner": {},
        "exploitation_owners": [],
    }


def merge_registries(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    merged = empty_registry()
    existing_observation = existing.get("observation_owner")
    incoming_observation = incoming.get("observation_owner")
    if isinstance(existing_observation, dict) and has_meaningful_entry(existing_observation):
        merged["observation_owner"] = compact_entry(existing_observation)
    if isinstance(incoming_observation, dict) and has_meaningful_entry(incoming_observation):
        merged["observation_owner"] = compact_entry(incoming_observation)

    seen: set[tuple[str, str, str]] = set()
    for collection in (existing.get("exploitation_owners"), incoming.get("exploitation_owners")):
        if not isinstance(collection, list):
            continue
        for item in collection:
            if not isinstance(item, dict):
                continue
            entry = compact_entry(item)
            key = entry_key(entry)
            if key in seen or not has_meaningful_entry(entry):
                continue
            seen.add(key)
            merged["exploitation_owners"].append(entry)
    return merged


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        decoder = json.JSONDecoder()
        index = 0
        merged = empty_registry()
        recovered = False
        while index < len(text):
            while index < len(text) and text[index].isspace():
                index += 1
            if index >= len(text):
                break
            try:
                chunk, index = decoder.raw_decode(text, index)
            except json.JSONDecodeError:
                break
            if isinstance(chunk, dict):
                merged = merge_registries(merged, coerce_registry(chunk))
                recovered = True
        return merged if recovered else {}


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temp_path, path)


def registry_lock_path(path: Path) -> Path:
    return path.with_name(f"{path.name}.lock")


def lock_registry(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_handle = registry_lock_path(path).open("a+", encoding="utf-8")
    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
    return lock_handle


def compact_entry(entry: dict[str, Any]) -> dict[str, Any]:
    ordered_keys = (
        "owner_id",
        "role",
        "vector_slug",
        "detail_report",
        "stage",
        "status",
        "next_action",
        "updated_at",
    )
    return {key: entry[key] for key in ordered_keys if entry.get(key) not in (None, "", [], {})}


def has_meaningful_entry(entry: dict[str, Any]) -> bool:
    return any(
        collapse_text(entry.get(key))
        for key in ("owner_id", "vector_slug", "detail_report", "stage", "status", "next_action")
    )


def coerce_registry(payload: dict[str, Any]) -> dict[str, Any]:
    registry = empty_registry()
    observation_owner = payload.get("observation_owner")
    if isinstance(observation_owner, dict) and has_meaningful_entry(observation_owner):
        registry["observation_owner"] = compact_entry(
                {
                    **observation_owner,
                    "role": "observation-subagent",
                    "vector_slug": normalize_slug(observation_owner.get("vector_slug") or "observation"),
                    "detail_report": normalize_workspace_path(observation_owner.get("detail_report")),
                    "status": normalize_status(observation_owner.get("status")),
                }
            )

    owners = payload.get("exploitation_owners")
    if isinstance(owners, list):
        seen: set[tuple[str, str, str]] = set()
        for item in owners:
            if not isinstance(item, dict):
                continue
            entry = compact_entry(
                {
                    **item,
                    "role": "exploitation-subagent",
                    "vector_slug": normalize_slug(item.get("vector_slug") or Path(collapse_text(item.get("detail_report"))).stem),
                    "detail_report": normalize_workspace_path(item.get("detail_report")),
                    "status": normalize_status(item.get("status")),
                }
            )
            key = (
                collapse_text(entry.get("vector_slug")),
                collapse_text(entry.get("detail_report")),
                collapse_text(entry.get("owner_id")),
            )
            if key in seen or not has_meaningful_entry(entry):
                continue
            seen.add(key)
            registry["exploitation_owners"].append(entry)
    return registry


def upsert_observation(registry: dict[str, Any], args: argparse.Namespace) -> None:
    current = registry.get("observation_owner")
    if not isinstance(current, dict):
        current = {}
    current.update(
        compact_entry(
            {
                "owner_id": collapse_text(args.owner_id),
                "role": "observation-subagent",
                "vector_slug": normalize_slug(args.vector_slug or "observation"),
                "stage": collapse_text(args.stage),
                "status": normalize_status(args.status, args.action),
                "next_action": collapse_text(args.next_action),
                "updated_at": now_iso(),
            }
        )
    )
    registry["observation_owner"] = compact_entry(current)


def entry_key(entry: dict[str, Any]) -> tuple[str, str, str]:
    vector_slug = normalize_slug(entry.get("vector_slug")) if entry.get("vector_slug") else ""
    detail_report = normalize_workspace_path(entry.get("detail_report"))
    owner_id = collapse_text(entry.get("owner_id"))
    return (
        vector_slug or collapse_text(entry.get("vector_slug")),
        detail_report or collapse_text(entry.get("detail_report")),
        owner_id or collapse_text(entry.get("owner_id")),
    )


def upsert_exploitation(registry: dict[str, Any], args: argparse.Namespace) -> None:
    owners = registry.get("exploitation_owners")
    if not isinstance(owners, list):
        owners = []
    vector_slug = normalize_slug(args.vector_slug or Path(collapse_text(args.detail_report)).stem)
    detail_report = normalize_workspace_path(args.detail_report)
    incoming = compact_entry(
        {
            "owner_id": collapse_text(args.owner_id),
            "role": "exploitation-subagent",
            "vector_slug": vector_slug,
            "detail_report": detail_report,
            "stage": collapse_text(args.stage),
            "status": normalize_status(args.status, args.action),
            "next_action": collapse_text(args.next_action),
            "updated_at": now_iso(),
        }
    )
    incoming_key = entry_key(incoming)
    updated = False
    for index, item in enumerate(owners):
        if not isinstance(item, dict):
            continue
        item_key = entry_key(item)
        same_vector = incoming_key[0] and incoming_key[0] == item_key[0]
        same_report = incoming_key[1] and incoming_key[1] == item_key[1]
        same_owner = incoming_key[2] and incoming_key[2] == item_key[2]
        fallback_same_vector = same_vector and not incoming_key[1] and not item_key[1] and not incoming_key[2] and not item_key[2]
        if same_owner or same_report or fallback_same_vector:
            merged = {**item, **incoming}
            owners[index] = compact_entry(merged)
            updated = True
            break
    if not updated:
        owners.append(incoming)
    registry["exploitation_owners"] = [compact_entry(item) for item in owners if isinstance(item, dict)]


def summary(registry: dict[str, Any]) -> dict[str, Any]:
    owners = registry.get("exploitation_owners")
    if not isinstance(owners, list):
        owners = []
    return {
        "observation_owner": registry.get("observation_owner") or {},
        "exploitation_count": len(owners),
        "exploitation_vectors": [
            {
                "vector_slug": item.get("vector_slug"),
                "status": item.get("status"),
                "detail_report": item.get("detail_report"),
            }
            for item in owners
            if isinstance(item, dict)
        ],
    }


def main() -> None:
    args = parse_args()
    registry_path = Path(args.registry)
    lock_handle = lock_registry(registry_path)
    try:
        registry = coerce_registry(load_json(registry_path))
        if not args.repair_in_place:
            if args.role == "observation-subagent":
                upsert_observation(registry, args)
            elif args.role == "exploitation-subagent":
                upsert_exploitation(registry, args)
        write_json(registry_path, registry)
    finally:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
        lock_handle.close()
    if args.print_summary:
        print(json.dumps(summary(registry), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
