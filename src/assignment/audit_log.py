"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, dict] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store input and start time, keyed by request ID or user ID."""
        key = request_id if request_id is not None else user_id
        self._open[key] = {
            "user_id": user_id,
            "request_id": request_id,
            "input": text,
            "started_at": utc_now_iso(),
            "_start": perf_counter(),
        }

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Complete the matching interaction and append it to the audit log."""
        finished = perf_counter()
        key = request_id if request_id is not None else user_id
        entry = self._open.pop(key, None)
        if entry is None:
            entry = {
                "user_id": user_id,
                "request_id": request_id,
                "input": None,
                "started_at": None,
            }
        start = entry.pop("_start", None)
        entry.update(
            output=text,
            blocked=blocked,
            layer=layer,
            finished_at=utc_now_iso(),
            latency_ms=(finished - start) * 1000 if start is not None else None,
        )
        self.logs.append(entry)

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as file:
            json.dump(self.logs, file, indent=2)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
