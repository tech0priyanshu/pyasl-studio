from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

from .detectors import commit_checks, dependency_checks, dco_checks, file_checks, metadata_checks, secret_checks, workflow_checks
from .models import CheckResult, Severity, Status
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
    paths = _changed_paths(root, pull_request)
    file_records = [{"path": path, "size": _file_size(root / path), "binary": _is_binary(root / path), "content": _safe_text(root / path)} for path in paths]
    commits = _commits(root, pull_request)
    workflows = [{"path": path, "content": _safe_text(root / path)} for path in paths if path.startswith(".github/workflows/") and Path(path).suffix in {".yml", ".yaml"}]
    checks = metadata_checks(metadata)
    checks += dco_checks(commits, policy.values.get("dco", {}).get("required", True))
    checks += commit_checks(commits)
    checks += file_checks(file_records, policy.values.get("large_files", {}).get("warn_bytes", 5 * 1024 * 1024), policy.values.get("large_files", {}).get("fail_bytes", 50 * 1024 * 1024))
    checks += secret_checks(file_records)
    checks += workflow_checks(workflows)
    checks += dependency_checks(paths)
    checks += _command_checks(root)
    return policy.apply(checks).to_dict()


def _changed_paths(root: Path, pull_request: dict[str, Any]) -> list[str]:
    base = ((pull_request.get("base") or {}).get("sha")) or os.environ.get("GITHUB_BASE_SHA", "HEAD~1")
    head = ((pull_request.get("head") or {}).get("sha")) or os.environ.get("GITHUB_SHA", "HEAD")
    result = subprocess.run(["git", "diff", "--name-only", base, head], cwd=root, capture_output=True, text=True, check=False)
    if result.returncode:
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _commits(root: Path, pull_request: dict[str, Any]) -> list[dict[str, Any]]:
    base = ((pull_request.get("base") or {}).get("sha")) or os.environ.get("GITHUB_BASE_SHA", "HEAD~1")
    result = subprocess.run(["git", "log", "--format=%H%x1f%an%x1f%ae%x1f%cn%x1f%ce%x1f%B%x1e", f"{base}..HEAD"], cwd=root, capture_output=True, text=True, check=False)
    commits = []
    for record in result.stdout.split("\x1e"):
        fields = record.strip("\n").split("\x1f", 5)
        if len(fields) == 6:
            commits.append({"sha": fields[0], "author": {"name": fields[1], "email": fields[2]}, "committer": {"name": fields[3], "email": fields[4]}, "message": fields[5]})
    return commits


def _command_checks(root: Path) -> list[CheckResult]:
    checks = []
    test_command = [os.environ.get("PYASL_GATEWAY_TEST_COMMAND", "python -m pytest")]
    default_build = "python tools/build.py" if (root / "tools" / "build.py").exists() else ""
    build_command = [os.environ.get("PYASL_GATEWAY_BUILD_COMMAND", default_build)]
    for check_id, name, command in (("TEST", "Tests", test_command[0]), ("BUILD", "Build", build_command[0])):
        parts = command.split()
        if not parts:
            checks.append(CheckResult(f"{check_id}-005", f"{name} command", check_id.lower(), Status.SKIP, message=f"{name} command could not be determined."))
            continue
        completed = subprocess.run(parts, cwd=root, capture_output=True, text=True, check=False)
        passed = completed.returncode == 0
        checks.append(CheckResult(f"{check_id}-001", f"{name} command", check_id.lower(), Status.PASS, message=f"Discovered `{command}`."))
        checks.append(CheckResult(f"{check_id}-003" if passed else f"{check_id}-004", f"{name} result", check_id.lower(), Status.PASS if passed else Status.FAIL, Severity.INFO if passed else Severity.HIGH, f"{name} passed." if passed else f"{name} failed with exit code {completed.returncode}.", remediation=f"Run `{command}` and fix the reported failures." if not passed else ""))
    return checks


def _file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _is_binary(path: Path) -> bool:
    try:
        return b"\0" in path.read_bytes()[:8192]
    except OSError:
        return False


def _safe_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def load_event(path: Path | None = None) -> dict[str, Any]:
    event_path = path or Path(os.environ["GITHUB_EVENT_PATH"])
    return json.loads(event_path.read_text(encoding="utf-8"))