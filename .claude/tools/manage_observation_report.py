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
    parser.add_argument("--update", help="Path to the current observation delta JSON")
    parser.add_argument(
        "--repair-in-place",
        action="store_true",
        help="Coerce the current observation report into the canonical schema in place.",
    )
    args = parser.parse_args()
    if not args.update and not args.repair_in_place:
        parser.error("Either --update or --repair-in-place is required.")
    return args


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


CANONICAL_ROOT_KEYS = {
    "target",
    "surface_map",
    "evidence",
    "hypotheses",
    "negative_findings",
    "unknowns",
    "recommended_next_step",
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


def normalize_url(value: Any) -> str:
    text = collapse_text(value)
    if not text:
        return ""
    split = urlsplit(text)
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
    if isinstance(value, dict):
        for key in ("path", "url", "endpoint", "entrypoint", "href", "action", "file"):
            normalized = normalize_path(value.get(key))
            if normalized:
                return normalized
        return ""
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


def ensure_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def target_url_from_item(item: Any) -> str:
    if isinstance(item, dict):
        for key in ("url", "entrypoint", "endpoint", "path", "href", "uri", "location"):
            normalized = normalize_path(item.get(key))
            if normalized:
                return normalized
        return ""
    return normalize_path(item)


def coerce_target_urls(value: Any) -> list[str]:
    urls = [url for item in ensure_list(value) if (url := target_url_from_item(item))]
    return unique_list(urls, normalize_path)


def target_port_from_item(item: Any) -> Any:
    if isinstance(item, dict):
        for key in ("port", "number", "value"):
            if item.get(key) not in (None, ""):
                return item[key]
        return None
    return item


def coerce_target_ports(value: Any) -> list[Any]:
    ports = [port for item in ensure_list(value) if (port := target_port_from_item(item)) not in (None, "")]
    return unique_list(ports, normalize_scalar)


def coerce_target_technologies(value: Any) -> list[str]:
    technologies: list[str] = []

    def visit(item: Any) -> None:
        if isinstance(item, dict):
            for child in item.values():
                visit(child)
            return
        if isinstance(item, list):
            for child in item:
                visit(child)
            return
        text = collapse_text(item)
        if text:
            technologies.append(text)

    visit(value)
    return unique_list(technologies, normalize_name)


def is_canonical_report(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    if not CANONICAL_ROOT_KEYS.issubset(value.keys()):
        return False
    if not isinstance(value.get("target"), dict):
        return False
    if not isinstance(value.get("surface_map"), dict):
        return False
    if not isinstance(value.get("evidence"), list):
        return False
    if not isinstance(value.get("hypotheses"), list):
        return False
    if not isinstance(value.get("negative_findings"), list):
        return False
    if not isinstance(value.get("unknowns"), list):
        return False
    if not isinstance(value.get("recommended_next_step"), dict):
        return False
    return True


def add_note_evidence(report: dict[str, Any], *, note_type: str, source: str, summary: str, details: Any = None) -> None:
    item: dict[str, Any] = {
        "type": note_type,
        "source": source,
        "summary": collapse_text(summary),
    }
    if details not in (None, "", [], {}):
        item["details"] = copy.deepcopy(details)
    report["evidence"].append(item)


def coerce_reference_list(value: Any) -> list[str]:
    references: list[str] = []
    for item in ensure_list(value):
        if isinstance(item, dict):
            family = collapse_text(item.get("family") or item.get("type") or item.get("category"))
            claim = collapse_text(item.get("claim") or item.get("description") or item.get("title") or item.get("summary"))
            identifier = collapse_text(item.get("id"))
            if family and claim:
                references.append(f"{family}: {claim}")
            elif claim:
                references.append(claim)
            elif identifier:
                references.append(identifier)
            continue
        text = collapse_text(item)
        if text:
            references.append(text)
    return list(dict.fromkeys(references))


def coerce_hypothesis(item: Any) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        text = collapse_text(item)
        if not text:
            return None
        return {"claim": text}

    claim = collapse_text(item.get("claim") or item.get("description") or item.get("title") or item.get("summary"))
    if not claim:
        return None

    hypothesis: dict[str, Any] = {"claim": claim}
    if collapse_text(item.get("id")):
        hypothesis["id"] = item["id"]
    family = collapse_text(item.get("family") or item.get("type") or item.get("category") or item.get("vector"))
    if family:
        hypothesis["family"] = family
    confidence = collapse_text(item.get("confidence"))
    if confidence:
        hypothesis["confidence"] = confidence
    status = collapse_text(item.get("status"))
    if status:
        hypothesis["status"] = status

    basis: list[str] = []
    for key in ("basis", "evidence"):
        value = item.get(key)
        if isinstance(value, list):
            basis.extend(collapse_text(entry) for entry in value if collapse_text(entry))
        elif collapse_text(value):
            basis.append(collapse_text(value))
    if basis:
        hypothesis["basis"] = list(dict.fromkeys(basis))

    minimal_checks: list[str] = []
    for key in ("minimal_checks", "next_steps", "recommendations"):
        value = item.get(key)
        if isinstance(value, list):
            minimal_checks.extend(collapse_text(entry) for entry in value if collapse_text(entry))
        elif collapse_text(value):
            minimal_checks.append(collapse_text(value))
    if minimal_checks:
        hypothesis["minimal_checks"] = list(dict.fromkeys(minimal_checks))

    combines_with: list[str] = []
    for key in ("combines_with", "related_hypotheses", "related_to", "combination_hints"):
        combines_with.extend(coerce_reference_list(item.get(key)))
    if combines_with:
        hypothesis["combines_with"] = list(dict.fromkeys(combines_with))

    notes = collapse_text(item.get("notes") or item.get("note"))
    if notes:
        hypothesis["notes"] = notes
    return hypothesis


def coerce_endpoint_record(path_value: Any, payload: Any) -> tuple[str, dict[str, Any]] | None:
    if isinstance(payload, dict):
        record = copy.deepcopy(payload)
    else:
        record = {}

    path = normalize_path(path_value or record.get("path") or record.get("endpoint") or record.get("url"))
    if not path:
        return None

    normalized: dict[str, Any] = {"path": path}
    method = collapse_text(record.get("method") or "GET")
    if method:
        normalized["method"] = method.upper()

    status_code = record.get("status_code", record.get("status"))
    if status_code not in (None, ""):
        normalized["status_code"] = status_code

    for source_key, target_key in (
        ("location", "location"),
        ("server", "server"),
        ("content_type", "content_type"),
        ("content-length", "content_length"),
        ("content_length", "content_length"),
        ("title", "title"),
        ("note", "note"),
        ("description", "description"),
    ):
        value = collapse_text(record.get(source_key))
        if value:
            normalized[target_key] = value

    kind = "api_endpoints" if path.startswith("/api") or "json" in collapse_text(record.get("content_type")).lower() else "pages"
    return kind, normalized


def extend_endpoints(report: dict[str, Any], value: Any) -> None:
    if isinstance(value, dict):
        for path, payload in value.items():
            normalized = coerce_endpoint_record(path, payload)
            if not normalized:
                continue
            bucket, record = normalized
            report["surface_map"][bucket].append(record)
    elif isinstance(value, list):
        for item in value:
            normalized = coerce_endpoint_record(None, item)
            if not normalized:
                continue
            bucket, record = normalized
            report["surface_map"][bucket].append(record)


def coerce_to_canonical(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return empty_report()

    report = empty_report()

    for key in CANONICAL_ROOT_KEYS:
        value = payload.get(key)
        if key not in payload:
            continue
        if key in {"surface_map", "recommended_next_step"} and isinstance(value, dict):
            report[key] = copy.deepcopy(value)
        elif key in {"evidence", "hypotheses", "negative_findings", "unknowns"} and isinstance(value, list):
            report[key] = copy.deepcopy(value)

    target_value = payload.get("target")
    if isinstance(target_value, str):
        normalized_target = normalize_path(target_value)
        if normalized_target:
            report["target"]["scope"].append(normalized_target)
            report["target"]["entrypoints"].append(normalized_target)

    if isinstance(target_value, dict):
        for field, coercer, normalizer in (
            ("scope", coerce_target_urls, normalize_url),
            ("entrypoints", coerce_target_urls, normalize_url),
            ("ports", coerce_target_ports, normalize_scalar),
            ("technologies", coerce_target_technologies, normalize_name),
        ):
            report["target"][field] = merge_scalar_lists(
                report["target"].get(field, []),
                coercer(target_value.get(field)),
                normalizer,
            )

    findings = payload.get("findings") if isinstance(payload.get("findings"), dict) else {}

    technologies = []
    technologies.extend(ensure_list(payload.get("tech_stack")))
    technologies.extend(ensure_list(findings.get("tech_stack")))
    technologies.extend(ensure_list(payload.get("technologies")))
    report["target"]["technologies"] = merge_scalar_lists(
        report["target"]["technologies"],
        coerce_target_technologies(technologies),
        normalize_name,
    )

    extend_endpoints(report, payload.get("endpoints"))
    extend_endpoints(report, findings.get("endpoints"))

    for negative_group in (
        payload.get("negative_findings"),
        findings.get("negative_findings"),
    ):
        report["negative_findings"].extend(ensure_list(negative_group))

    for artifact_group, source_name in (
        (payload.get("artifacts"), "legacy.artifacts"),
        (findings.get("artifacts"), "legacy.findings.artifacts"),
    ):
        for artifact in ensure_list(artifact_group):
            if isinstance(artifact, dict):
                path = collapse_text(artifact.get("path") or artifact.get("artifact") or artifact.get("file"))
                summary = collapse_text(artifact.get("description") or artifact.get("summary") or path or "Legacy observation artifact")
                add_note_evidence(report, note_type="artifact", source=source_name, summary=summary, details=artifact)
            else:
                text = collapse_text(artifact)
                if text:
                    add_note_evidence(report, note_type="artifact", source=source_name, summary=text)

    for hypothesis_group in (
        payload.get("hypotheses"),
        findings.get("hypotheses"),
    ):
        for item in ensure_list(hypothesis_group):
            normalized = coerce_hypothesis(item)
            if normalized:
                report["hypotheses"].append(normalized)

    for list_key, source_name, note_type in (
        ("known_facts", "legacy.findings.known_facts", "legacy_fact"),
        ("technical_constraints", "legacy.findings.technical_constraints", "technical_constraint"),
        ("tooling_issues", "legacy.findings.tooling_issues", "tooling_issue"),
        ("blockers", "legacy.findings.blockers", "blocker"),
    ):
        for item in ensure_list(findings.get(list_key)):
            if isinstance(item, dict):
                summary = collapse_text(item.get("title") or item.get("description") or item.get("note") or json.dumps(item, ensure_ascii=False))
                add_note_evidence(report, note_type=note_type, source=source_name, summary=summary, details=item)
            else:
                text = collapse_text(item)
                if text:
                    add_note_evidence(report, note_type=note_type, source=source_name, summary=text)

    for key, source_name in (
        ("status", "legacy.status"),
        ("phase", "legacy.phase"),
        ("generated_at", "legacy.generated_at"),
        ("timestamp", "legacy.timestamp"),
    ):
        value = collapse_text(payload.get(key))
        if value:
            add_note_evidence(report, note_type="legacy_note", source=source_name, summary=value)

    if isinstance(payload.get("metadata"), dict) and payload["metadata"]:
        add_note_evidence(
            report,
            note_type="legacy_metadata",
            source="legacy.metadata",
            summary="Legacy observation metadata preserved during repair",
            details=payload["metadata"],
        )

    recommended_next_step = payload.get("recommended_next_step")
    if isinstance(recommended_next_step, dict):
        report["recommended_next_step"] = copy.deepcopy(recommended_next_step)
    else:
        next_steps: list[str] = []
        for key in ("recommendation", "recommended_next_step", "next_steps"):
            value = payload.get(key)
            if isinstance(value, list):
                next_steps.extend(collapse_text(item) for item in value if collapse_text(item))
            elif collapse_text(value):
                next_steps.append(collapse_text(value))
        if not next_steps and isinstance(payload.get("summary"), dict):
            summary_next_steps = payload["summary"].get("next_steps")
            if isinstance(summary_next_steps, list):
                next_steps.extend(collapse_text(item) for item in summary_next_steps if collapse_text(item))
        if next_steps:
            first_hypothesis_id = ""
            for item in report["hypotheses"]:
                hypothesis_id = collapse_text(item.get("id"))
                if hypothesis_id:
                    first_hypothesis_id = hypothesis_id
                    break
            report["recommended_next_step"] = {
                "action": next_steps[0],
                "notes": next_steps,
                **({"priority_hypothesis": first_hypothesis_id} if first_hypothesis_id else {}),
            }

    return merge_report(empty_report(), report)


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


def coerce_javascript_lead(item: Any) -> dict[str, Any] | None:
    if isinstance(item, dict):
        normalized = copy.deepcopy(item)
        path = normalize_path(normalized.get("file") or normalized.get("path") or normalized.get("url"))
        if not path:
            return None
        if not collapse_text(normalized.get("path")):
            normalized["path"] = path
        return normalized
    path = normalize_path(item)
    if not path:
        return None
    return {"path": path}


def js_lead_key(item: Any) -> str:
    normalized = coerce_javascript_lead(item)
    if not normalized:
        return ""
    return normalize_path(normalized.get("file") or normalized.get("path"))


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
    existing: list[Any],
    incoming: list[Any],
    *,
    key_fn,
    id_prefix: str | None = None,
    merge_fn=merge_generic_record,
    coerce_item=None,
) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    for item in existing:
        normalized = coerce_item(item) if coerce_item else (copy.deepcopy(item) if isinstance(item, dict) else None)
        if isinstance(normalized, dict):
            merged.append(normalized)
    index = {key_fn(item): position for position, item in enumerate(merged) if key_fn(item)}
    for item in incoming:
        item = coerce_item(item) if coerce_item else item
        if not isinstance(item, dict):
            continue
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
    basis = merge_scalar_lists(existing.get("basis", []), incoming.get("basis", []), normalize_scalar)
    minimal_checks = merge_scalar_lists(
        existing.get("minimal_checks", []),
        incoming.get("minimal_checks", []),
        normalize_scalar,
    )
    combines_with = merge_scalar_lists(
        existing.get("combines_with", []),
        incoming.get("combines_with", []),
        normalize_scalar,
    )
    if basis:
        merged["basis"] = basis
    else:
        merged.pop("basis", None)
    if minimal_checks:
        merged["minimal_checks"] = minimal_checks
    else:
        merged.pop("minimal_checks", None)
    if combines_with:
        merged["combines_with"] = combines_with
    else:
        merged.pop("combines_with", None)
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
        coerce_item=coerce_javascript_lead,
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
    merged["scope"] = merge_scalar_lists(
        coerce_target_urls(existing.get("scope", [])),
        coerce_target_urls(incoming.get("scope", [])),
        normalize_url,
    )
    merged["entrypoints"] = merge_scalar_lists(
        coerce_target_urls(existing.get("entrypoints", [])),
        coerce_target_urls(incoming.get("entrypoints", [])),
        normalize_url,
    )
    merged["ports"] = merge_scalar_lists(
        coerce_target_ports(existing.get("ports", [])),
        coerce_target_ports(incoming.get("ports", [])),
        normalize_scalar,
    )
    merged["technologies"] = merge_scalar_lists(
        coerce_target_technologies(existing.get("technologies", [])),
        coerce_target_technologies(incoming.get("technologies", [])),
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

    report["evidence"] = ensure_unique_ids(report.get("evidence", []), "ev")
    report["hypotheses"] = ensure_unique_ids(report.get("hypotheses", []), "h")
    return report


def ensure_unique_ids(items: list[dict[str, Any]], prefix: str) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    used: set[str] = set()
    highest = 0
    pattern = re.compile(rf"^{re.escape(prefix)}[-_]?(\d+)$", re.IGNORECASE)

    for item in items:
        current_id = collapse_text(item.get("id"))
        match = pattern.match(current_id)
        if match:
            highest = max(highest, int(match.group(1)))

    for item in items:
        current = copy.deepcopy(item)
        current_id = collapse_text(current.get("id"))
        if not current_id or current_id in used:
            highest += 1
            current["id"] = f"{prefix}_{highest:03d}"
        used.add(collapse_text(current.get("id")))
        normalized.append(current)
    return normalized


def main() -> int:
    args = parse_args()
    report_path = Path(args.report)
    existing = coerce_to_canonical(load_json(report_path) if report_path.exists() else empty_report())

    if args.repair_in_place:
        write_json(report_path, existing)
        return 0

    update_path = Path(args.update)
    update = load_json(update_path)
    if not isinstance(update, dict):
        raise SystemExit("Update payload must be a JSON object.")

    merged = merge_report(existing, coerce_to_canonical(update))
    write_json(report_path, merged)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
