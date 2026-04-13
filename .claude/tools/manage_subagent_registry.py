#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_REGISTRY_PATH = "reports/subagent_registry.json"
SCHEMA_VERSION = 2
ROLE_ALIASES = {
    "observation": "observation-subagent",
    "observation-subagent": "observation-subagent",
    "exploitation": "exploitation-subagent",
    "exploitation-subagent": "exploitation-subagent",
}
GENERIC_OWNER_IDS = set(ROLE_ALIASES) | set(ROLE_ALIASES.values()) | {
    "main",
    "main-agent",
    "main_agent",
    "observation-agent",
    "observation_agent",
    "exploitation-agent",
    "exploitation_agent",
}
OWNER_ID_PLACEHOLDER_MARKERS = (
    "<owner_id",
    "owner_id if provided",
    "owner_id if known",
    "<target owner",
    "<assigned owner",
    "<owner id",
)
OWNER_STATUS_ALIASES = {
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
PROPOSAL_STATUS_ALIASES = {
    "open": "proposed",
    "proposed": "proposed",
    "accepted": "accepted",
    "dismissed": "dismissed",
    "resolved": "resolved",
}
PROPOSAL_KINDS = {
    "fact_challenge",
    "parameter_challenge",
    "decisive_payload_family",
    "bridge_gap",
}
MAIN_DECISIONS = {
    "accept_revalidate",
    "dismiss",
    "continue_same_owner",
    "replace_owner",
    "prioritize_family",
}


def collapse_text(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def normalize_role(value: Any) -> str:
    role = collapse_text(value).lower()
    return ROLE_ALIASES.get(role, role)


def normalize_owner_identifier(value: Any) -> str:
    text = collapse_text(value)
    if not text:
        return ""
    lowered = text.lower()
    if lowered in GENERIC_OWNER_IDS:
        return ""
    if any(marker in lowered for marker in OWNER_ID_PLACEHOLDER_MARKERS):
        return ""
    return text


def normalize_owner_status(value: Any, action: Any = "") -> str:
    status = collapse_text(value).lower().replace("-", "_")
    if status:
        return OWNER_STATUS_ALIASES.get(status, status)
    action_text = collapse_text(action).lower()
    if action_text in {"start", "resume"}:
        return "running"
    if action_text in {"stop", "finish", "complete"}:
        return "completed"
    return ""


def normalize_proposal_status(value: Any) -> str:
    status = collapse_text(value).lower().replace("-", "_")
    if not status:
        return ""
    return PROPOSAL_STATUS_ALIASES.get(status, status)


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


def parse_jsonish(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    text = collapse_text(value)
    if not text:
        return ""
    if text[:1] in "[{":
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text
    return text


def registry_lock_path(path: Path) -> Path:
    return path.with_name(f"{path.name}.lock")


def lock_registry(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_handle = registry_lock_path(path).open("a+", encoding="utf-8")
    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
    return lock_handle


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temp_path, path)


def empty_registry() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "observation_owner": {},
        "exploitation_owners": [],
        "proposal_queue": [],
    }


def compact_owner(entry: dict[str, Any]) -> dict[str, Any]:
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


def compact_proposal(entry: dict[str, Any]) -> dict[str, Any]:
    ordered_keys = (
        "id",
        "kind",
        "status",
        "raised_by_owner_id",
        "target_owner_id",
        "assigned_owner_id",
        "vector_slug",
        "report_ref",
        "exact_inputs",
        "expected_observation",
        "actual_observation",
        "artifact_refs",
        "main_decision",
        "resolution",
        "created_at",
        "updated_at",
    )
    compacted: dict[str, Any] = {}
    for key in ordered_keys:
        value = entry.get(key)
        if value in (None, "", [], {}):
            continue
        compacted[key] = value
    return compacted


def has_meaningful_owner(entry: dict[str, Any]) -> bool:
    return any(
        collapse_text(entry.get(key))
        for key in ("owner_id", "vector_slug", "detail_report", "stage", "status", "next_action")
    )


def has_meaningful_proposal(entry: dict[str, Any]) -> bool:
    return any(
        collapse_text(entry.get(key))
        for key in ("id", "kind", "status", "raised_by_owner_id", "target_owner_id", "vector_slug", "report_ref")
    )


def owner_key(entry: dict[str, Any]) -> tuple[str, str, str]:
    return (
        normalize_slug(entry.get("vector_slug")) if entry.get("vector_slug") else "",
        normalize_workspace_path(entry.get("detail_report")),
        normalize_owner_identifier(entry.get("owner_id")),
    )


def proposal_fingerprint(entry: dict[str, Any]) -> tuple[str, str, str, str, str]:
    return (
        collapse_text(entry.get("kind")).lower(),
        collapse_text(entry.get("target_owner_id")),
        normalize_slug(entry.get("vector_slug")) if entry.get("vector_slug") else "",
        normalize_workspace_path(entry.get("report_ref")),
        json.dumps(entry.get("exact_inputs", ""), ensure_ascii=False, sort_keys=True),
    )


def coerce_owner(entry: Any, role: str) -> dict[str, Any]:
    if not isinstance(entry, dict):
        return {}
    normalized = compact_owner(
        {
            **entry,
            "role": role,
            "vector_slug": normalize_slug(entry.get("vector_slug") or ("observation" if role == "observation-subagent" else entry.get("vector_slug"))),
            "detail_report": normalize_workspace_path(entry.get("detail_report")),
            "status": normalize_owner_status(entry.get("status"), entry.get("action")),
            "owner_id": normalize_owner_identifier(entry.get("owner_id")),
            "stage": collapse_text(entry.get("stage")),
            "next_action": collapse_text(entry.get("next_action")),
            "updated_at": collapse_text(entry.get("updated_at")),
        }
    )
    return normalized if has_meaningful_owner(normalized) else {}


def coerce_proposal(entry: Any) -> dict[str, Any]:
    if not isinstance(entry, dict):
        return {}
    proposal = compact_proposal(
        {
            **entry,
            "id": collapse_text(entry.get("id")),
            "kind": collapse_text(entry.get("kind")).lower(),
            "status": normalize_proposal_status(entry.get("status") or "proposed"),
            "raised_by_owner_id": normalize_owner_identifier(entry.get("raised_by_owner_id")),
            "target_owner_id": normalize_owner_identifier(entry.get("target_owner_id")),
            "assigned_owner_id": normalize_owner_identifier(entry.get("assigned_owner_id")),
            "vector_slug": normalize_slug(entry.get("vector_slug")) if collapse_text(entry.get("vector_slug")) else "",
            "report_ref": normalize_workspace_path(entry.get("report_ref")),
            "exact_inputs": parse_jsonish(entry.get("exact_inputs")),
            "expected_observation": parse_jsonish(entry.get("expected_observation")),
            "actual_observation": parse_jsonish(entry.get("actual_observation")),
            "artifact_refs": [
                normalize_workspace_path(item) or collapse_text(item)
                for item in (entry.get("artifact_refs") if isinstance(entry.get("artifact_refs"), list) else [entry.get("artifact_refs")])
                if collapse_text(item)
            ],
            "main_decision": collapse_text(entry.get("main_decision")),
            "resolution": parse_jsonish(entry.get("resolution")),
            "created_at": collapse_text(entry.get("created_at")),
            "updated_at": collapse_text(entry.get("updated_at")),
        }
    )
    if proposal.get("kind") and proposal["kind"] not in PROPOSAL_KINDS:
        proposal["kind"] = proposal["kind"]
    return proposal if has_meaningful_proposal(proposal) else {}


def merge_registries(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    merged = empty_registry()

    for candidate in (existing.get("observation_owner"), incoming.get("observation_owner")):
        owner = coerce_owner(candidate, "observation-subagent")
        if owner:
            merged["observation_owner"] = owner

    seen_owners: set[tuple[str, str, str]] = set()
    for collection in (existing.get("exploitation_owners"), incoming.get("exploitation_owners")):
        if not isinstance(collection, list):
            continue
        for item in collection:
            owner = coerce_owner(item, "exploitation-subagent")
            if not owner:
                continue
            key = owner_key(owner)
            if key in seen_owners:
                continue
            seen_owners.add(key)
            merged["exploitation_owners"].append(owner)

    proposal_map: dict[str, dict[str, Any]] = {}
    fingerprint_map: dict[tuple[str, str, str, str, str], str] = {}
    for collection in (existing.get("proposal_queue"), incoming.get("proposal_queue")):
        if not isinstance(collection, list):
            continue
        for item in collection:
            proposal = coerce_proposal(item)
            if not proposal:
                continue
            proposal_id = collapse_text(proposal.get("id"))
            fingerprint = proposal_fingerprint(proposal)
            matched_id = proposal_id or fingerprint_map.get(fingerprint, "")
            if matched_id and matched_id in proposal_map:
                merged_entry = {**proposal_map[matched_id], **proposal}
                proposal_map[matched_id] = compact_proposal(merged_entry)
                continue
            if not proposal_id:
                proposal_id = f"prop_{len(proposal_map) + 1:03d}"
                proposal["id"] = proposal_id
            proposal_map[proposal_id] = proposal
            fingerprint_map[fingerprint] = proposal_id

    merged["proposal_queue"] = sorted(
        (compact_proposal(item) for item in proposal_map.values() if has_meaningful_proposal(item)),
        key=lambda item: (
            {"proposed": 0, "accepted": 1, "dismissed": 2, "resolved": 3}.get(collapse_text(item.get("status")).lower(), 99),
            collapse_text(item.get("created_at")),
            collapse_text(item.get("id")),
        ),
    )
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


def coerce_registry(payload: dict[str, Any]) -> dict[str, Any]:
    registry = empty_registry()
    observation_owner = payload.get("observation_owner")
    coerced_observation = coerce_owner(observation_owner, "observation-subagent")
    if coerced_observation:
        registry["observation_owner"] = coerced_observation

    owners = payload.get("exploitation_owners")
    if isinstance(owners, list):
        seen: set[tuple[str, str, str]] = set()
        for item in owners:
            owner = coerce_owner(item, "exploitation-subagent")
            if not owner:
                continue
            key = owner_key(owner)
            if key in seen:
                continue
            seen.add(key)
            registry["exploitation_owners"].append(owner)

    queue = payload.get("proposal_queue")
    if isinstance(queue, list):
        seen_ids: set[str] = set()
        for item in queue:
            proposal = coerce_proposal(item)
            if not proposal:
                continue
            proposal_id = collapse_text(proposal.get("id"))
            if proposal_id and proposal_id in seen_ids:
                continue
            if proposal_id:
                seen_ids.add(proposal_id)
            registry["proposal_queue"].append(proposal)

    return registry


def next_proposal_id(registry: dict[str, Any]) -> str:
    highest = 0
    pattern = re.compile(r"^prop_(\d+)$", flags=re.IGNORECASE)
    for item in registry.get("proposal_queue", []):
        if not isinstance(item, dict):
            continue
        match = pattern.match(collapse_text(item.get("id")))
        if match:
            highest = max(highest, int(match.group(1)))
    return f"prop_{highest + 1:03d}"


def upsert_owner(registry: dict[str, Any], args: argparse.Namespace) -> None:
    now = now_iso()
    role = normalize_role(args.role)
    owner = compact_owner(
        {
            "owner_id": normalize_owner_identifier(args.owner_id),
            "role": role,
            "vector_slug": normalize_slug(args.vector_slug or ("observation" if role == "observation-subagent" else args.vector_slug)),
            "detail_report": normalize_workspace_path(args.detail_report),
            "stage": collapse_text(args.stage),
            "status": normalize_owner_status(args.status, args.action),
            "next_action": collapse_text(args.next_action),
            "updated_at": now,
        }
    )
    if role == "observation-subagent":
        current = registry.get("observation_owner")
        if not isinstance(current, dict):
            current = {}
        registry["observation_owner"] = compact_owner({**current, **owner})
        return

    owners = registry.get("exploitation_owners")
    if not isinstance(owners, list):
        owners = []
    incoming_key = owner_key(owner)
    updated = False
    for index, item in enumerate(owners):
        if not isinstance(item, dict):
            continue
        existing_key = owner_key(item)
        same_owner = incoming_key[2] and incoming_key[2] == existing_key[2]
        same_report = incoming_key[1] and incoming_key[1] == existing_key[1]
        same_vector = incoming_key[0] and incoming_key[0] == existing_key[0] and not incoming_key[1] and not existing_key[1]
        if same_owner or same_report or same_vector:
            owners[index] = compact_owner({**item, **owner})
            updated = True
            break
    if not updated:
        owners.append(owner)
    registry["exploitation_owners"] = [compact_owner(item) for item in owners if isinstance(item, dict)]


def raise_proposal(registry: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    queue = registry.get("proposal_queue")
    if not isinstance(queue, list):
        queue = []
    proposal = compact_proposal(
        {
            "id": collapse_text(getattr(args, "proposal_id", "")) or next_proposal_id(registry),
            "kind": collapse_text(args.kind).lower(),
            "status": normalize_proposal_status(getattr(args, "status", "") or "proposed") or "proposed",
            "raised_by_owner_id": normalize_owner_identifier(getattr(args, "raised_by_owner_id", "")),
            "target_owner_id": normalize_owner_identifier(getattr(args, "target_owner_id", "")),
            "assigned_owner_id": normalize_owner_identifier(getattr(args, "assigned_owner_id", "")),
            "vector_slug": normalize_slug(getattr(args, "vector_slug", "")) if collapse_text(getattr(args, "vector_slug", "")) else "",
            "report_ref": normalize_workspace_path(getattr(args, "report_ref", "")),
            "exact_inputs": parse_jsonish(getattr(args, "exact_inputs", "")),
            "expected_observation": parse_jsonish(getattr(args, "expected_observation", "")),
            "actual_observation": parse_jsonish(getattr(args, "actual_observation", "")),
            "artifact_refs": [normalize_workspace_path(item) or collapse_text(item) for item in (getattr(args, "artifact_refs", []) or []) if collapse_text(item)],
            "created_at": now_iso(),
            "updated_at": now_iso(),
        }
    )
    fingerprint = proposal_fingerprint(proposal)
    for index, item in enumerate(queue):
        if not isinstance(item, dict):
            continue
        existing = coerce_proposal(item)
        if not existing:
            continue
        if collapse_text(existing.get("id")) == proposal["id"] or proposal_fingerprint(existing) == fingerprint:
            merged = compact_proposal({**existing, **proposal, "created_at": existing.get("created_at") or proposal.get("created_at"), "updated_at": now_iso()})
            queue[index] = merged
            registry["proposal_queue"] = queue
            return merged
    queue.append(proposal)
    registry["proposal_queue"] = queue
    return proposal


def find_proposal(queue: list[dict[str, Any]], proposal_id: str) -> tuple[int, dict[str, Any]] | tuple[int, None]:
    wanted = collapse_text(proposal_id)
    for index, item in enumerate(queue):
        if not isinstance(item, dict):
            continue
        if collapse_text(item.get("id")) == wanted:
            return index, item
    return -1, None


def decide_proposal(registry: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    queue = registry.get("proposal_queue")
    if not isinstance(queue, list):
        queue = []
    index, item = find_proposal(queue, args.proposal_id)
    if item is None:
        raise SystemExit(f"Unknown proposal id: {args.proposal_id}")
    decision = collapse_text(args.decision)
    if decision and decision not in MAIN_DECISIONS:
        raise SystemExit(f"Unsupported decision: {decision}")
    status = "dismissed" if decision == "dismiss" else "accepted"
    updated = compact_proposal(
        {
            **item,
            "status": status,
            "assigned_owner_id": normalize_owner_identifier(getattr(args, "assigned_owner_id", "")) or item.get("assigned_owner_id"),
            "main_decision": decision or item.get("main_decision"),
            "updated_at": now_iso(),
        }
    )
    queue[index] = updated
    registry["proposal_queue"] = queue
    return updated


def resolve_proposal(registry: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    queue = registry.get("proposal_queue")
    if not isinstance(queue, list):
        queue = []
    index, item = find_proposal(queue, args.proposal_id)
    if item is None:
        raise SystemExit(f"Unknown proposal id: {args.proposal_id}")
    updated = compact_proposal(
        {
            **item,
            "status": "resolved",
            "assigned_owner_id": normalize_owner_identifier(getattr(args, "assigned_owner_id", "")) or item.get("assigned_owner_id"),
            "resolution": parse_jsonish(getattr(args, "resolution", "")) or item.get("resolution"),
            "updated_at": now_iso(),
        }
    )
    queue[index] = updated
    registry["proposal_queue"] = queue
    return updated


def summary(registry: dict[str, Any]) -> dict[str, Any]:
    owners = registry.get("exploitation_owners")
    if not isinstance(owners, list):
        owners = []
    queue = registry.get("proposal_queue")
    if not isinstance(queue, list):
        queue = []
    open_proposals = [
        item for item in queue if isinstance(item, dict) and collapse_text(item.get("status")).lower() in {"proposed", "accepted"}
    ]
    return {
        "schema_version": registry.get("schema_version", SCHEMA_VERSION),
        "observation_owner": registry.get("observation_owner") or {},
        "exploitation_count": len(owners),
        "exploitation_vectors": [
            {
                "vector_slug": item.get("vector_slug"),
                "status": item.get("status"),
                "detail_report": item.get("detail_report"),
                "owner_id": item.get("owner_id"),
            }
            for item in owners
            if isinstance(item, dict)
        ],
        "open_proposal_count": len(open_proposals),
        "open_proposals": [
            {
                "id": item.get("id"),
                "kind": item.get("kind"),
                "status": item.get("status"),
                "vector_slug": item.get("vector_slug"),
                "target_owner_id": item.get("target_owner_id"),
                "report_ref": item.get("report_ref"),
            }
            for item in open_proposals
        ],
    }


def build_legacy_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Maintain the lightweight subagent owner registry.")
    parser.add_argument("--registry", default=DEFAULT_REGISTRY_PATH, help="Path to reports/subagent_registry.json")
    parser.add_argument("--role", default="", help="Role name, canonical or legacy alias")
    parser.add_argument("--action", default="", help="Legacy no-op action name such as start/stop")
    parser.add_argument("--owner-id", "--owner_id", default="", help="Claude agentId / exact SendMessage target if known")
    parser.add_argument("--vector-slug", "--vector_slug", default="", help="Stable vector slug")
    parser.add_argument(
        "--detail-report",
        "--detail_report",
        "--detail-path",
        "--detail_path",
        default="",
        help="Path to reports/exploitation/exploitation_<slug>.json",
    )
    parser.add_argument("--stage", default="", help="Current stage")
    parser.add_argument("--status", default="", help="Current status")
    parser.add_argument("--next-action", "--next_action", default="", help="Short next action")
    parser.add_argument("--repair-in-place", "--repair_in_place", action="store_true", help="Coerce registry into canonical shape")
    parser.add_argument("--print-summary", "--print_summary", action="store_true", help="Print a compact JSON summary")
    return parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Maintain the v2 subagent owner registry and proposal queue.")
    parser.add_argument("--registry", default=DEFAULT_REGISTRY_PATH, help="Path to reports/subagent_registry.json")
    subparsers = parser.add_subparsers(dest="entity")

    owner_parser = subparsers.add_parser("owner", help="Manage owner entries")
    owner_sub = owner_parser.add_subparsers(dest="operation")
    owner_upsert = owner_sub.add_parser("upsert", help="Create or update an owner entry")
    owner_upsert.add_argument("--role", required=True, help="observation-subagent or exploitation-subagent")
    owner_upsert.add_argument("--action", default="", help="Legacy action alias")
    owner_upsert.add_argument("--owner-id", "--owner_id", default="", dest="owner_id")
    owner_upsert.add_argument("--vector-slug", "--vector_slug", default="", dest="vector_slug")
    owner_upsert.add_argument("--detail-report", "--detail_report", "--detail-path", "--detail_path", default="", dest="detail_report")
    owner_upsert.add_argument("--stage", default="")
    owner_upsert.add_argument("--status", default="")
    owner_upsert.add_argument("--next-action", "--next_action", default="", dest="next_action")

    proposal_parser = subparsers.add_parser("proposal", help="Manage proposal queue entries")
    proposal_sub = proposal_parser.add_subparsers(dest="operation")
    proposal_raise = proposal_sub.add_parser("raise", help="Raise or refresh a proposal")
    proposal_raise.add_argument("--proposal-id", default="", dest="proposal_id")
    proposal_raise.add_argument("--kind", required=True)
    proposal_raise.add_argument("--status", default="proposed")
    proposal_raise.add_argument("--raised-by-owner-id", default="", dest="raised_by_owner_id")
    proposal_raise.add_argument("--target-owner-id", default="", dest="target_owner_id")
    proposal_raise.add_argument("--assigned-owner-id", default="", dest="assigned_owner_id")
    proposal_raise.add_argument("--vector-slug", default="", dest="vector_slug")
    proposal_raise.add_argument("--report-ref", default="", dest="report_ref")
    proposal_raise.add_argument("--exact-inputs", default="", dest="exact_inputs")
    proposal_raise.add_argument("--expected-observation", default="", dest="expected_observation")
    proposal_raise.add_argument("--actual-observation", default="", dest="actual_observation")
    proposal_raise.add_argument("--artifact-ref", action="append", dest="artifact_refs", default=[])

    proposal_decide = proposal_sub.add_parser("decide", help="Record main decision for a proposal")
    proposal_decide.add_argument("--proposal-id", required=True, dest="proposal_id")
    proposal_decide.add_argument("--decision", required=True)
    proposal_decide.add_argument("--assigned-owner-id", default="", dest="assigned_owner_id")

    proposal_resolve = proposal_sub.add_parser("resolve", help="Resolve a proposal")
    proposal_resolve.add_argument("--proposal-id", required=True, dest="proposal_id")
    proposal_resolve.add_argument("--resolution", required=True)
    proposal_resolve.add_argument("--assigned-owner-id", default="", dest="assigned_owner_id")

    subparsers.add_parser("repair", help="Repair registry in place")
    subparsers.add_parser("summary", help="Print compact registry summary")
    return parser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    argv = list(sys.argv[1:] if argv is None else argv)
    command_tokens = {"owner", "proposal", "repair", "summary"}
    command_mode = any(token in command_tokens for token in argv)
    if command_mode and "--registry" in argv:
        index = argv.index("--registry")
        if index + 1 < len(argv) and index > 0:
            registry_pair = [argv.pop(index), argv.pop(index)]
            argv = [*registry_pair, *argv]
    if not argv or (argv[0].startswith("-") and not command_mode):
        legacy_parser = build_legacy_parser()
        args = legacy_parser.parse_args(argv)
        args.registry = args.registry
        args.role = normalize_role(args.role)
        args.status = normalize_owner_status(args.status, args.action)
        args.legacy_mode = True
        if not args.repair_in_place and not args.role and not args.print_summary:
            legacy_parser.error("Either --role, --repair-in-place, or --print-summary is required.")
        if args.role not in {"observation-subagent", "exploitation-subagent", ""}:
            legacy_parser.error("argument --role: expected observation-subagent or exploitation-subagent")
        if args.role == "exploitation-subagent" and not collapse_text(args.vector_slug) and not collapse_text(args.detail_report):
            legacy_parser.error("exploitation-subagent requires --vector-slug or --detail-report.")
        return args

    parser = build_parser()
    args = parser.parse_args(argv)
    args.legacy_mode = False
    if args.entity == "owner" and args.operation == "upsert":
        args.role = normalize_role(args.role)
        args.status = normalize_owner_status(args.status, args.action)
        if args.role not in {"observation-subagent", "exploitation-subagent"}:
            parser.error("owner upsert requires canonical role")
        if args.role == "exploitation-subagent" and not collapse_text(args.vector_slug) and not collapse_text(args.detail_report):
            parser.error("owner upsert for exploitation requires --vector-slug or --detail-report")
    if args.entity == "proposal" and args.operation == "raise":
        if collapse_text(args.kind).lower() not in PROPOSAL_KINDS:
            parser.error(f"proposal raise requires --kind in {sorted(PROPOSAL_KINDS)}")
    return args


def main() -> None:
    args = parse_args()
    registry_path = Path(args.registry)
    lock_handle = lock_registry(registry_path)
    try:
        registry = coerce_registry(load_json(registry_path))
        if args.legacy_mode:
            if getattr(args, "repair_in_place", False):
                write_json(registry_path, registry)
            elif getattr(args, "print_summary", False):
                write_json(registry_path, registry)
            else:
                upsert_owner(registry, args)
                write_json(registry_path, registry)
        else:
            if args.entity == "repair":
                write_json(registry_path, registry)
            elif args.entity == "summary":
                write_json(registry_path, registry)
            elif args.entity == "owner" and args.operation == "upsert":
                upsert_owner(registry, args)
                write_json(registry_path, registry)
            elif args.entity == "proposal" and args.operation == "raise":
                raise_proposal(registry, args)
                write_json(registry_path, registry)
            elif args.entity == "proposal" and args.operation == "decide":
                decide_proposal(registry, args)
                write_json(registry_path, registry)
            elif args.entity == "proposal" and args.operation == "resolve":
                resolve_proposal(registry, args)
                write_json(registry_path, registry)
            else:
                raise SystemExit("Unsupported command")
    finally:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
        lock_handle.close()

    if getattr(args, "print_summary", False) or (not args.legacy_mode and args.entity == "summary"):
        print(json.dumps(summary(registry), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
