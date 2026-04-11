#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import mimetypes
import re
from pathlib import Path
from typing import Any


DEFAULT_KEYWORDS = (
    "flag",
    "secret",
    "token",
    "password",
    "passwd",
    "admin",
    "debug",
    "upload",
    "template",
    "render",
    "include",
)

VENDOR_MARKERS = (
    "bootstrap",
    "jquery",
    "react",
    "vue",
    "angular",
    "tailwind",
    "webpack",
    "vite",
    "vendor",
    ".min.js",
    ".min.css",
    "chunk.",
    "bundle.",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Summarize a large or vendor-like artifact without flooding model context.")
    parser.add_argument("--path", required=True, help="Artifact path to summarize")
    parser.add_argument("--status", help="Optional HTTP status code or fetch status")
    parser.add_argument("--content-type", dest="content_type", help="Optional content type")
    parser.add_argument("--keyword", action="append", default=[], help="Keyword to look for; can be repeated")
    parser.add_argument("--max-preview-lines", type=int, default=20, help="Maximum preview lines to emit")
    parser.add_argument("--max-line-length", type=int, default=220, help="Maximum characters per preview line")
    return parser.parse_args()


def collapse_text(value: Any) -> str:
    if value is None:
        return ""
    return re.sub(r"\s+", " ", str(value)).strip()


def truncate_text(value: str, *, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[: max(0, limit - 1)] + "…"


def is_vendor_like(path: Path, text_sample: str) -> bool:
    name_blob = f"{path.name.lower()} {path.as_posix().lower()} {text_sample[:4000].lower()}"
    return any(marker in name_blob for marker in VENDOR_MARKERS)


def looks_minified(text: str) -> bool:
    lines = text.splitlines()
    if not lines:
        return False
    long_lines = sum(1 for line in lines[:40] if len(line) >= 320)
    return long_lines >= 3 or (len(lines) <= 6 and any(len(line) >= 800 for line in lines))


def decode_text(raw: bytes) -> tuple[str, bool]:
    for encoding in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return raw.decode(encoding), True
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace"), False


def extract_keyword_hits(text: str, keywords: list[str]) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    lowered = text.lower()
    for keyword in keywords:
        normalized = collapse_text(keyword).lower()
        if not normalized:
            continue
        count = lowered.count(normalized)
        if count:
            hits.append({"keyword": normalized, "count": count})
    hits.sort(key=lambda item: (-int(item["count"]), item["keyword"]))
    return hits


def build_preview(text: str, *, keywords: list[str], max_preview_lines: int, max_line_length: int, suppress_preview: bool) -> list[str]:
    if suppress_preview:
        return []

    lines = [collapse_text(line) for line in text.splitlines()]
    lines = [line for line in lines if line]
    if not lines:
        return []

    keyword_set = [collapse_text(item).lower() for item in keywords if collapse_text(item)]
    prioritized: list[str] = []
    if keyword_set:
        for line in lines:
            lowered = line.lower()
            if any(keyword in lowered for keyword in keyword_set):
                prioritized.append(truncate_text(line, limit=max_line_length))
                if len(prioritized) >= max_preview_lines:
                    return prioritized

    for line in lines:
        candidate = truncate_text(line, limit=max_line_length)
        if candidate in prioritized:
            continue
        prioritized.append(candidate)
        if len(prioritized) >= max_preview_lines:
            break
    return prioritized


def build_summary(*, path: Path, content_type: str, vendor_like: bool, minified: bool, keyword_hits: list[dict[str, Any]], preview: list[str]) -> str:
    parts: list[str] = []
    if vendor_like:
        parts.append("vendor-like asset")
    elif content_type.startswith("text/html"):
        parts.append("HTML artifact")
    elif "javascript" in content_type or path.suffix.lower() == ".js":
        parts.append("JavaScript artifact")
    elif "css" in content_type or path.suffix.lower() == ".css":
        parts.append("CSS artifact")
    else:
        parts.append("artifact")

    if minified:
        parts.append("minified")
    if keyword_hits:
        top = ", ".join(f"{item['keyword']} x{item['count']}" for item in keyword_hits[:4])
        parts.append(f"keyword hits: {top}")
    elif vendor_like:
        parts.append("no target keyword hits")
    elif preview:
        parts.append(f"{len(preview)} preview lines kept")
    return "; ".join(parts)


def main() -> int:
    args = parse_args()
    path = Path(args.path)
    if not path.exists() or not path.is_file():
        raise SystemExit(f"Artifact not found: {path}")

    raw = path.read_bytes()
    sha256 = hashlib.sha256(raw).hexdigest()
    text, decoded_cleanly = decode_text(raw)
    content_type = collapse_text(args.content_type) or mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    keywords = list(dict.fromkeys([*DEFAULT_KEYWORDS, *args.keyword]))
    vendor_like = is_vendor_like(path, text)
    minified = looks_minified(text) if content_type.startswith("text/") or "javascript" in content_type or "json" in content_type else False
    keyword_hits = extract_keyword_hits(text[:500000], keywords)
    suppress_preview = vendor_like and not keyword_hits
    preview = build_preview(
        text,
        keywords=keywords,
        max_preview_lines=max(0, args.max_preview_lines),
        max_line_length=max(40, args.max_line_length),
        suppress_preview=suppress_preview,
    )
    payload = {
        "path": str(path),
        "status": collapse_text(args.status),
        "content_type": content_type,
        "bytes": len(raw),
        "sha256": sha256,
        "keyword_hits": keyword_hits,
        "summary": build_summary(
            path=path,
            content_type=content_type,
            vendor_like=vendor_like,
            minified=minified,
            keyword_hits=keyword_hits,
            preview=preview,
        ),
        "preview": preview,
    }
    if not payload["status"]:
        payload.pop("status")
    if not decoded_cleanly:
        payload["summary"] = f"{payload['summary']}; decoded with replacement characters"
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
