from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

from .detectors import commit_checks, dependency_checks, dco_checks, file_checks, metadata_checks, secret_checks, workflow_checks
from .policy import Policy


def run_gateway(root: Path, event: dict[str, Any], policy: Policy) -> dict[str, Any]:
    pull_request = event.get("pull_request", event)
    metadata = {
        "title": pull_request.get("title"),
        "body": pull_request.get("body"),
        "draft": pull_request.get("draft", False),
        "bot": str((pull_request.get("user") or {}).get("type", "")).lower() == "bot",
        "fork": ((pull_request.get("head") or {}).get("repo") or {}).get("full_name") != ((pull_request.get("base") or {}).get("repo") or {}).get("full_name"),
        "first_time_contributor": False,
    }
    base, head = _commit_range(pull_request)
    paths = _changed_paths(root, base, head)
    file_records = []
    for path in paths:
        content = _blob(root, head, path)
        file_records.append({"path": path, "size": _blob_size(root, head, path), "binary": b"\0" in content[:8192], "content": content.decode("utf-8", errors="replace")})
    commits = _commits(root, base, head)
    workflows = [{"path": path, "content": _blob(root, head, path).decode("utf-8", errors="replace")} for path in _workflow_paths(root, head)]
    checks = metadata_checks(metadata)
    checks += dco_checks(commits, policy.values.get("dco", {}).get("required", True))
    checks += commit_checks(commits)
    checks += file_checks(file_records, policy.values.get("large_files", {}).get("warn_bytes", 5 * 1024 * 1024), policy.values.get("large_files", {}).get("fail_bytes", 50 * 1024 * 1024))
    checks += secret_checks(file_records)
    checks += workflow_checks(workflows)
    checks += dependency_checks(paths)
    return policy.apply(checks).to_dict()


def _commit_range(pull_request: dict[str, Any]) -> tuple[str, str]:
    base = ((pull_request.get("base") or {}).get("sha")) or os.environ.get("GITHUB_BASE_SHA")
    head = ((pull_request.get("head") or {}).get("sha")) or os.environ.get("GITHUB_HEAD_SHA")
    if not base or not head:
        raise ValueError("PR base and head SHAs are required")
    return base, head


def _changed_paths(root: Path, base: str, head: str) -> list[str]:
    result = subprocess.run(["git", "diff", "--name-only", base, head], cwd=root, capture_output=True, text=True, check=False)
    if result.returncode:
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _workflow_paths(root: Path, head: str) -> list[str]:
    result = subprocess.run(["git", "ls-tree", "-r", "--name-only", head, ".github/workflows"], cwd=root, capture_output=True, text=True, check=False)
    if result.returncode:
        return []
    return [path.strip() for path in result.stdout.splitlines() if Path(path).suffix in {".yml", ".yaml"}]


def _commits(root: Path, base: str, head: str) -> list[dict[str, Any]]:
    result = subprocess.run(["git", "log", "--format=%H%x1f%an%x1f%ae%x1f%cn%x1f%ce%x1f%B%x1e", f"{base}..{head}"], cwd=root, capture_output=True, text=True, check=False)
    commits = []
    for record in result.stdout.split("\x1e"):
        fields = record.strip("\n").split("\x1f", 5)
        if len(fields) == 6:
            commits.append({"sha": fields[0], "author": {"name": fields[1], "email": fields[2]}, "committer": {"name": fields[3], "email": fields[4]}, "message": fields[5]})
    return commits


def _blob(root: Path, head: str, path: str) -> bytes:
    result = subprocess.run(["git", "show", f"{head}:{path}"], cwd=root, capture_output=True, check=False)
    return result.stdout if result.returncode == 0 else b""


def _blob_size(root: Path, head: str, path: str) -> int:
    result = subprocess.run(["git", "cat-file", "-s", f"{head}:{path}"], cwd=root, capture_output=True, text=True, check=False)
    try:
        return int(result.stdout.strip()) if result.returncode == 0 else 0
    except ValueError:
        return 0


def load_event(path: Path | None = None) -> dict[str, Any]:
    event_path = path or Path(os.environ["GITHUB_EVENT_PATH"])
    return json.loads(event_path.read_text(encoding="utf-8"))