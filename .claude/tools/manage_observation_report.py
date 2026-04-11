#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Merge incremental observation data into the canonical report.")
    parser.add_argument("--report", required=True, help="Path to reports/observation_report.json")
    parser.add_argument("--update", required=True, help="Path to the current observation delta JSON")
    return parser.parse_args()


def empty_report() -> dict[str, Any]:
    return {
        "target": {
            "scope": [],
            "entrypoints": [],
            "ports": [],
            "technologies": [],
        },
        "surface_map": {
            "pages": [],
            "routes": [],
            "api_endpoints": [],
            "forms": [],
            "parameters": [],
            "cookies": [],
            "headers": {},
            "tokens": [],
            "files": {},
            "javascript_leads": [],
            "auth_surfaces": [],
            "upload_points": [],
            "download_points": [],
        },
        "evidence": [],
        "hypotheses": [],
        "negative_findings": [],
        "unknowns": [],
        "recommended_next_step": {},
    }


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def collapse_text(value: Any) -> str:
    if value is None:
        return ""
    return re.sub(r"\s+", " ", str(value)).strip()


def normalize_url(value: str) -> str:
    split = urlsplit(value.strip())
    scheme = split.scheme.lower()
    hostname = (split.hostname or "").lower()
    port = split.port
    netloc = hostname
    if port is not None and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{hostname}:{port}"
    path = re.sub(r"/{2,}", "/", split.path or "/")
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    query_items = parse_qsl(split.query, keep_blank_values=True)
    query = urlencode(sorted(query_items))
    return urlunsplit((scheme, netloc, path or "/", query, ""))


def normalize_path(value: Any) -> str:
    text = collapse_text(value)
    if not text:
        return ""
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", text):
        return normalize_url(text)
    text = re.sub(r"/{2,}", "/", text)
    if text != "/" and text.endswith("/"):
        text = text.rstrip("/")
    return text


def normalize_name(value: Any) -> str:
    return collapse_text(value).lower()


def normalize_scalar(value: Any) -> str:
    if isinstance(value, str):
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value.strip()):
            return normalize_url(value)
        return collapse_text(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def unique_list(items: list[Any], normalizer) -> list[Any]:
    merged: list[Any] = []
    seen: set[str] = set()
    for item in items:
        key = normalizer(item)
        if not key or key in seen:
            continue
        seen.add(key)
        merged.append(item)
    return merged


def merge_scalar_lists(existing: list[Any], incoming: list[Any], normalizer) -> list[Any]:
    return unique_list([*existing, *incoming], normalizer)


def merge_string(existing: Any, incoming: Any) -> Any:
    existing_text = collapse_text(existing)
    incoming_text = collapse_text(incoming)
    if not existing_text and incoming_text:
        return incoming
    if not incoming_text:
        return existing
    if len(incoming_text) > len(existing_text):
        return incoming
    return existing


def merge_headers(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(existing)
    lowercase_map = {normalize_name(key): key for key in merged}
    for key, value in incoming.items():
        normalized = normalize_name(key)
        if normalized in lowercase_map:
            target_key = lowercase_map[normalized]
            merged[target_key] = merge_string(merged[target_key], value)
        else:
            merged[key] = value
    return merged


def merge_dict_values(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(existing)
    for key, value in incoming.items():
        if key not in merged:
            merged[key] = copy.deepcopy(value)
            continue
        current = merged[key]
        if isinstance(current, list) and isinstance(value, list):
            merged[key] = merge_scalar_lists(current, value, normalize_path)
        elif isinstance(current, dict) and isinstance(value, dict):
            merged[key] = merge_dict_values(current, value)
        else:
            merged[key] = merge_string(current, value)
    return merged


def next_identifier(existing_items: list[dict[str, Any]], prefix: str) -> str:
    highest = 0
    pattern = re.compile(rf"^{re.escape(prefix)}-(\d+)$")
    for item in existing_items:
        match = pattern.match(str(item.get("id", "")))
        if match:
            highest = max(highest, int(match.group(1)))
    return f"{prefix}-{highest + 1}"


def merge_generic_record(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(existing)
    for key, value in incoming.items():
        if key not in merged or merged[key] in (None, "", [], {}):
            merged[key] = copy.deepcopy(value)
            continue
        current = merged[key]
        if isinstance(current, list) and isinstance(value, list):
            merged[key] = merge_scalar_lists(current, value, normalize_scalar)
        elif isinstance(current, dict) and isinstance(value, dict):
            merged[key] = merge_dict_values(current, value)
        elif current != value:
            merged[key] = merge_string(current, value)
    return merged


def evidence_key(item: dict[str, Any]) -> str:
    return "|".join(
        [
            normalize_name(item.get("type")),
            normalize_scalar(item.get("source")),
            normalize_scalar(item.get("summary") or item.get("content") or item.get("details")),
        ]
    )


def hypothesis_key(item: dict[str, Any]) -> str:
    return "|".join([normalize_name(item.get("family")), normalize_name(item.get("claim"))])


def page_key(item: Any) -> str:
    if isinstance(item, dict):
        return normalize_path(item.get("path") or item.get("url") or item.get("endpoint"))
    return normalize_path(item)


def route_key(item: Any) -> str:
    return normalize_path(item)


def api_key(item: dict[str, Any]) -> str:
    return "|".join([normalize_name(item.get("method") or "GET"), normalize_path(item.get("path") or item.get("endpoint"))])


def form_key(item: dict[str, Any]) -> str:
    return "|".join([normalize_name(item.get("method") or "GET"), normalize_path(item.get("action"))])


def parameter_key(item: dict[str, Any]) -> str:
    route = item.get("endpoint") or item.get("route") or item.get("path") or ""
    return "|".join([normalize_name(item.get("location")), normalize_path(route), normalize_name(item.get("name"))])


def cookie_key(item: dict[str, Any]) -> str:
    return normalize_name(item.get("name"))


def token_key(item: Any) -> str:
    if isinstance(item, dict):
        return normalize_name(item.get("name") or item.get("type") or item.get("value"))
    return normalize_name(item)


def js_lead_key(item: dict[str, Any]) -> str:
    return normalize_path(item.get("file") or item.get("path"))


def auth_surface_key(item: dict[str, Any]) -> str:
    return "|".join([normalize_path(item.get("endpoint")), normalize_name(item.get("type"))])


def upload_download_key(item: dict[str, Any]) -> str:
    return "|".join(
        [
            normalize_path(item.get("endpoint") or item.get("path")),
            normalize_name(item.get("method")),
            normalize_name(item.get("field_name") or item.get("name")),
        ]
    )


def negative_finding_key(item: Any) -> str:
    if isinstance(item, dict):
        return normalize_scalar(
            {
                "path": normalize_path(item.get("path") or item.get("endpoint")),
                "status_code": item.get("status_code"),
                "note": collapse_text(item.get("note")),
            }
        )
    return normalize_name(item)


def merge_record_list(
    existing: list[dict[str, Any]],
    incoming: list[dict[str, Any]],
    *,
    key_fn,
    id_prefix: str | None = None,
    merge_fn=merge_generic_record,
) -> list[dict[str, Any]]:
    merged = [copy.deepcopy(item) for item in existing]
    index = {key_fn(item): position for position, item in enumerate(merged) if key_fn(item)}
    for item in incoming:
        key = key_fn(item)
        if key and key in index:
            position = index[key]
            original_id = merged[position].get("id")
            merged[position] = merge_fn(merged[position], item)
            if original_id:
                merged[position]["id"] = original_id
        else:
            new_item = copy.deepcopy(item)
            if id_prefix and not new_item.get("id"):
                new_item["id"] = next_identifier(merged, id_prefix)
            merged.append(new_item)
            if key:
                index[key] = len(merged) - 1
    return merged


def merge_hypothesis(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    merged = merge_generic_record(existing, incoming)
    merged["basis"] = merge_scalar_lists(existing.get("basis", []), incoming.get("basis", []), normalize_scalar)
    merged["minimal_checks"] = merge_scalar_lists(
        existing.get("minimal_checks", []),
        incoming.get("minimal_checks", []),
        normalize_scalar,
    )
    for field in ("confidence", "status", "notes"):
        if collapse_text(incoming.get(field)):
            merged[field] = incoming[field]
    return merged


def merge_files(existing: Any, incoming: Any) -> Any:
    if isinstance(existing, dict) and isinstance(incoming, dict):
        merged: dict[str, Any] = copy.deepcopy(existing)
        for key, value in incoming.items():
            current = merged.get(key, [])
            if isinstance(current, list) and isinstance(value, list):
                merged[key] = merge_scalar_lists(current, value, normalize_path)
            elif isinstance(current, dict) and isinstance(value, dict):
                merged[key] = merge_files(current, value)
            elif key not in merged:
                merged[key] = copy.deepcopy(value)
        return merged
    if isinstance(existing, list) and isinstance(incoming, list):
        return merge_scalar_lists(existing, incoming, normalize_path)
    if not existing:
        return copy.deepcopy(incoming)
    return existing


def merge_surface_map(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(existing)
    merged["pages"] = merge_record_list(existing.get("pages", []), incoming.get("pages", []), key_fn=page_key)
    merged["routes"] = merge_scalar_lists(existing.get("routes", []), incoming.get("routes", []), route_key)
    merged["api_endpoints"] = merge_record_list(existing.get("api_endpoints", []), incoming.get("api_endpoints", []), key_fn=api_key)
    merged["forms"] = merge_record_list(existing.get("forms", []), incoming.get("forms", []), key_fn=form_key)
    merged["parameters"] = merge_record_list(existing.get("parameters", []), incoming.get("parameters", []), key_fn=parameter_key)
    merged["cookies"] = merge_record_list(existing.get("cookies", []), incoming.get("cookies", []), key_fn=cookie_key)
    merged["headers"] = merge_headers(existing.get("headers", {}), incoming.get("headers", {}))
    merged["tokens"] = merge_scalar_lists(existing.get("tokens", []), incoming.get("tokens", []), token_key)
    merged["files"] = merge_files(existing.get("files", {}), incoming.get("files", {}))
    merged["javascript_leads"] = merge_record_list(
        existing.get("javascript_leads", []),
        incoming.get("javascript_leads", []),
        key_fn=js_lead_key,
    )
    merged["auth_surfaces"] = merge_record_list(
        existing.get("auth_surfaces", []),
        incoming.get("auth_surfaces", []),
        key_fn=auth_surface_key,
    )
    merged["upload_points"] = merge_record_list(
        existing.get("upload_points", []),
        incoming.get("upload_points", []),
        key_fn=upload_download_key,
    )
    merged["download_points"] = merge_record_list(
        existing.get("download_points", []),
        incoming.get("download_points", []),
        key_fn=upload_download_key,
    )
    return merged


def merge_target(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(existing)
    merged["scope"] = merge_scalar_lists(existing.get("scope", []), incoming.get("scope", []), normalize_url)
    merged["entrypoints"] = merge_scalar_lists(
        existing.get("entrypoints", []),
        incoming.get("entrypoints", []),
        normalize_url,
    )
    merged["ports"] = merge_scalar_lists(existing.get("ports", []), incoming.get("ports", []), normalize_scalar)
    merged["technologies"] = merge_scalar_lists(
        existing.get("technologies", []),
        incoming.get("technologies", []),
        normalize_name,
    )
    return merged


def merge_report(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    report = empty_report()
    report.update(copy.deepcopy(existing))
    report["target"] = merge_target(report.get("target", {}), incoming.get("target", {}))
    report["surface_map"] = merge_surface_map(report.get("surface_map", {}), incoming.get("surface_map", {}))
    report["evidence"] = merge_record_list(
        report.get("evidence", []),
        incoming.get("evidence", []),
        key_fn=evidence_key,
        id_prefix="ev",
    )
    report["hypotheses"] = merge_record_list(
        report.get("hypotheses", []),
        incoming.get("hypotheses", []),
        key_fn=hypothesis_key,
        id_prefix="h",
        merge_fn=merge_hypothesis,
    )
    report["negative_findings"] = merge_scalar_lists(
        report.get("negative_findings", []),
        incoming.get("negative_findings", []),
        negative_finding_key,
    )
    report["unknowns"] = merge_scalar_lists(report.get("unknowns", []), incoming.get("unknowns", []), normalize_name)

    incoming_next = incoming.get("recommended_next_step") or {}
    if incoming_next:
        priority = incoming_next.get("priority_hypothesis")
        known_ids = {item.get("id") for item in report.get("hypotheses", [])}
        if not priority or priority in known_ids:
            report["recommended_next_step"] = copy.deepcopy(incoming_next)

    return report


def main() -> int:
    args = parse_args()
    report_path = Path(args.report)
    update_path = Path(args.update)

    existing = load_json(report_path) if report_path.exists() else empty_report()
    update = load_json(update_path)
    if not isinstance(update, dict):
        raise SystemExit("Update payload must be a JSON object.")

    merged = merge_report(existing, update)
    write_json(report_path, merged)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
