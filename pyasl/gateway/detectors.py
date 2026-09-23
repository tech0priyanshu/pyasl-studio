from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable

from .models import CheckResult, Severity, Status

_MEANINGLESS = {"update", "changes", "fix", "test", "wip", "asdf", "untitled"}
_CREDENTIAL_NAME = re.compile(r"(^|/)(\.env(?:\..*)?|credentials?\..*|secret\..*|.*\.(?:pem|key))$", re.I)
_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
    re.compile(r"(?i)\bauthorization\s*:\s*bearer\s+[A-Za-z0-9._-]{16,}"),
)
_DEPENDENCY_FILES = {
    "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "requirements.txt",
    "pyproject.toml", "poetry.lock", "pom.xml", "build.gradle", "go.mod", "go.sum",
    "cargo.toml", "cargo.lock",
}


def metadata_checks(metadata: dict[str, Any]) -> list[CheckResult]:
    title = str(metadata.get("title") or "").strip()
    body = str(metadata.get("body") or "").strip()
    return [
        _result("PR-001", "PR title", "metadata", title and title.lower() not in _MEANINGLESS,
                "Title is present." if title else "PR title is empty.", "Provide a meaningful title."),
        _result("PR-002", "PR description", "metadata", body and body.lower() not in _MEANINGLESS,
                "Description is present." if body else "PR description is empty.", "Describe the change and its validation."),
        CheckResult("PR-003", "PR type", "metadata", Status.PASS, Severity.INFO,
                    "PR metadata classified.", [{key: metadata.get(key)} for key in ("draft", "bot", "fork", "first_time_contributor")]),
    ]


def dco_checks(commits: Iterable[dict[str, Any]], required: bool = True) -> list[CheckResult]:
    commits = list(commits)
    if not required:
        return [CheckResult("DCO-001", "DCO requirement", "dco", Status.SKIP, message="DCO is disabled by policy.")]
    missing: list[dict[str, str]] = []
    malformed: list[dict[str, str]] = []
    pattern = re.compile(r"^Signed-off-by:\s+([^<>\r\n]+?)\s+<([^<>\s@]+@[^<>\s@]+)>\s*$", re.I | re.M)
    for commit in commits:
        sha = str(commit.get("sha") or "unknown")[:12]
        message = str(commit.get("message") or "")
        trailers = re.findall(r"^Signed-off-by:.*$", message, re.I | re.M)
        if not trailers:
            missing.append({"sha": sha})
        elif not any(pattern.match(trailer) for trailer in trailers):
            malformed.append({"sha": sha})
    checks = [
        CheckResult("DCO-001", "DCO requirement", "dco", Status.PASS, message="DCO is required by policy."),
        CheckResult("DCO-002", "DCO sign-off", "dco", Status.FAIL if missing else Status.PASS,
                    Severity.HIGH if missing else Severity.INFO,
                    f"{len(missing)} commit(s) are missing DCO sign-off." if missing else "All introduced commits are signed off.",
                    missing, "Add a valid Signed-off-by trailer to each affected commit."),
        CheckResult("DCO-003", "DCO format", "dco", Status.FAIL if malformed else Status.PASS,
                    Severity.HIGH if malformed else Severity.INFO,
                    f"{len(malformed)} commit(s) have malformed DCO trailers." if malformed else "DCO trailers are valid.",
                    malformed, "Use Signed-off-by: Name <email>.")
    ]
    return checks


def commit_checks(commits: Iterable[dict[str, Any]], signatures_required: bool = False) -> list[CheckResult]:
    commits = list(commits)
    missing_author = [{"sha": str(c.get("sha", "unknown"))[:12]} for c in commits if not c.get("author")]
    missing_committer = [{"sha": str(c.get("sha", "unknown"))[:12]} for c in commits if not c.get("committer")]
    mismatches = []
    for commit in commits:
        author = commit.get("author") or {}
        committer = commit.get("committer") or {}
        if author and committer and author.get("email", "").lower() != committer.get("email", "").lower():
            mismatches.append({"sha": str(commit.get("sha", "unknown"))[:12], "reason": "author/committer differ"})
    signature_findings = [
        {"sha": str(c.get("sha", "unknown"))[:12]} for c in commits
        if signatures_required and not (c.get("verified") or c.get("signature_verified"))
    ]
    return [
        _result("COMMIT-001", "Author information", "integrity", not missing_author, "All commits have author information.", "Restore author metadata.", missing_author),
        _result("COMMIT-002", "Committer information", "integrity", not missing_committer, "All commits have committer information.", "Restore committer metadata.", missing_committer),
        CheckResult("COMMIT-003", "Author/committer mismatch", "integrity", Status.WARN if mismatches else Status.PASS,
                    Severity.MEDIUM if mismatches else Severity.INFO, "Suspicious author/committer differences found." if mismatches else "No suspicious mismatches found.", mismatches),
        CheckResult("COMMIT-004", "Commit signatures", "integrity", Status.FAIL if signature_findings else Status.PASS,
                    Severity.HIGH if signature_findings else Severity.INFO, "Required commit signatures are missing." if signature_findings else "Signature policy satisfied or not required.", signature_findings),
    ]


def file_checks(files: Iterable[dict[str, Any]], warn_bytes: int = 5 * 1024 * 1024, fail_bytes: int = 50 * 1024 * 1024) -> list[CheckResult]:
    files = list(files)
    large_warn = [{"path": f.get("path"), "bytes": f.get("size")} for f in files if warn_bytes < (f.get("size") or 0) <= fail_bytes]
    large_fail = [{"path": f.get("path"), "bytes": f.get("size")} for f in files if (f.get("size") or 0) > fail_bytes]
    binaries = [{"path": f.get("path")} for f in files if f.get("binary")]
    credentials = [{"path": f.get("path")} for f in files if _CREDENTIAL_NAME.search(str(f.get("path") or ""))]
    sensitive = [{"path": f.get("path")} for f in files if _sensitive_path(str(f.get("path") or ""))]
    return [
        CheckResult("FILE-001", "Large files", "files", Status.FAIL if large_fail else (Status.WARN if large_warn else Status.PASS),
                    Severity.HIGH if large_fail else Severity.MEDIUM if large_warn else Severity.INFO, "Large files detected.", large_fail or large_warn),
        CheckResult("FILE-002", "Binary files", "files", Status.WARN if binaries else Status.PASS, Severity.LOW, "Binary files changed." if binaries else "No binary files changed.", binaries),
        CheckResult("FILE-003", "Credential filenames", "files", Status.FAIL if credentials else Status.PASS, Severity.HIGH if credentials else Severity.INFO, "Potential credential file changed." if credentials else "No credential filenames detected.", credentials, "Remove credentials and use an approved secret store."),
        CheckResult("FILE-004", "Security-sensitive files", "files", Status.WARN if sensitive else Status.PASS, Severity.MEDIUM if sensitive else Severity.INFO, "Security-sensitive files changed." if sensitive else "No security-sensitive paths changed.", sensitive),
    ]


def secret_checks(files: Iterable[dict[str, Any]]) -> list[CheckResult]:
    findings = []
    for item in files:
        path = str(item.get("path") or "")
        content = str(item.get("content") or "")
        for line_number, line in enumerate(content.splitlines(), 1):
            if any(pattern.search(line) for pattern in _SECRET_PATTERNS):
                findings.append({"path": path, "line": line_number, "message": "Secret value redacted."})
    return [CheckResult("SECRET-001", "Secret scan", "security", Status.FAIL if findings else Status.PASS,
                        Severity.CRITICAL if findings else Severity.INFO,
                        "Potential credentials detected; values were redacted." if findings else "No potential credentials detected.",
                        findings, "Remove the credential, rotate it if exposed, and use the project secret store.")]


def workflow_checks(workflows: Iterable[dict[str, Any]]) -> list[CheckResult]:
    workflows = list(workflows)
    findings = []
    mutable = []
    third_party = []
    injection = []
    harden = []
    for workflow in workflows:
        path = str(workflow.get("path") or "workflow.yml")
        text = str(workflow.get("content") or "")
        privileged = "pull_request_target" in text or "permissions: write-all" in text or re.search(r"\b(?:contents|issues|pull-requests|actions|packages):\s*write", text)
        untrusted_checkout = bool(re.search(r"ref:\s*\$\{\{\s*(?:github\.event\.pull_request\.(?:head\.sha|head\.ref)|github\.head_ref)", text))
        executes = bool(re.search(r"(?m)^\s*-?\s*run:\s*(?:\||>|).*(?:npm|pip|python|make|bash|sh|go |cargo )", text))
        if "pull_request_target" in text and untrusted_checkout and executes:
            findings.append({"path": path, "reason": "privileged workflow checks out and executes PR-controlled code"})
        for line_number, line in enumerate(text.splitlines(), 1):
            match = re.search(r"uses:\s*([^\s#]+)@([^\s#]+)", line)
            if match and not re.fullmatch(r"[0-9a-fA-F]{40}", match.group(2)) and not match.group(1).startswith("./"):
                mutable.append({"path": path, "line": line_number, "action": match.group(1)})
            if match and not match.group(1).startswith("./"):
                third_party.append({"path": path, "line": line_number, "action": match.group(1)})
            if "run:" in line and "${{" in line and re.search(r"github\.event\.(?:pull_request|issue|comment)|github\.head_ref", line):
                injection.append({"path": path, "line": line_number, "message": "Untrusted expression reaches shell context."})
        if "step-security/harden-runner" in text:
            harden.append({"path": path, "configured": True, "immutable": bool(re.search(r"step-security/harden-runner@[0-9a-fA-F]{40}", text))})
    return [
        CheckResult("GHA-001", "Privileged workflow safety", "workflow", Status.FAIL if findings else Status.PASS, Severity.CRITICAL if findings else Severity.INFO, "Privileged workflow executes PR-controlled code." if findings else "No dangerous privileged workflow combination detected.", findings),
        CheckResult("GHA-002", "Workflow permissions", "workflow", Status.WARN if any("permissions:" in str(w.get("content")) for w in workflows) is False else Status.PASS, Severity.LOW, "Workflow permissions are implicit or absent." if not any("permissions:" in str(w.get("content")) for w in workflows) else "Workflow permissions are declared."),
        CheckResult("GHA-003", "Write permissions", "workflow", Status.WARN if any("write-all" in str(w.get("content")) for w in workflows) else Status.PASS, Severity.HIGH if any("write-all" in str(w.get("content")) for w in workflows) else Severity.INFO, "Broad write permissions detected." if any("write-all" in str(w.get("content")) for w in workflows) else "No write-all permission detected."),
        CheckResult("GHA-005", "Shell expression injection", "workflow", Status.FAIL if injection else Status.PASS, Severity.HIGH if injection else Severity.INFO, "Untrusted PR data reaches a shell command." if injection else "No unsafe shell interpolation detected.", injection),
        CheckResult("ACTION-001", "Third-party actions", "workflow", Status.PASS if third_party else Status.SKIP, Severity.INFO, f"{len(third_party)} third-party action reference(s) inspected." if third_party else "No third-party actions found.", third_party),
        CheckResult("ACTION-002", "Mutable action references", "workflow", Status.WARN if mutable else Status.PASS, Severity.MEDIUM if mutable else Severity.INFO, "Third-party actions use mutable references." if mutable else "Action references are immutable or none were found.", mutable),
        CheckResult("ACTION-003", "Immutable action references", "workflow", Status.PASS if third_party and not mutable else (Status.WARN if mutable else Status.SKIP), Severity.INFO if not mutable else Severity.MEDIUM, "Third-party actions are SHA pinned." if third_party and not mutable else "Some action references are mutable." if mutable else "No action references to inspect.", mutable),
        CheckResult("ACTION-004", "Action reference changes", "workflow", Status.SKIP, Severity.INFO, "Reference change comparison requires the GitHub API context."),
        CheckResult("SR-001", "Harden-Runner", "workflow", Status.PASS if harden else Status.SKIP, Severity.INFO, "Harden-Runner configured." if harden else "Harden-Runner is not configured.", harden),
    ]


def dependency_checks(changed_paths: Iterable[str]) -> list[CheckResult]:
    paths = [path for path in changed_paths if Path(path).name.lower() in _DEPENDENCY_FILES]
    return [CheckResult("DEP-001", "Dependency files", "dependencies", Status.WARN if paths else Status.PASS, Severity.LOW, "Dependency manifests changed." if paths else "No dependency manifests changed.", [{"path": path} for path in paths])]


def _sensitive_path(path: str) -> bool:
    return path.startswith(".github/workflows/") or Path(path).name.lower() in {"dockerfile", "pyproject.toml", "package.json", "requirements.txt"} or any(token in path.lower() for token in ("auth", "deploy", "security"))


def _result(check_id: str, name: str, category: str, passed: bool, message: str, remediation: str, evidence: list[dict[str, Any]] | None = None) -> CheckResult:
    return CheckResult(check_id, name, category, Status.PASS if passed else Status.FAIL, Severity.INFO if passed else Severity.MEDIUM, message, evidence or [], remediation if not passed else "")