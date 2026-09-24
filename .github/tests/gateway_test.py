import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pr_gateway import runner
from pr_gateway.detectors import commit_checks, dco_checks, file_checks, metadata_checks, secret_checks, workflow_checks
from pr_gateway.models import Status
from pr_gateway.policy import Policy


def test_metadata_meaningless_title_and_description_fail():
    checks = metadata_checks({"title": "WIP", "body": ""})
    assert checks[0].status == Status.FAIL
    assert checks[1].status == Status.FAIL
    assert checks[2].status == Status.PASS


def test_dco_valid_missing_and_malformed():
    valid = {"sha": "abc123", "message": "Change\n\nSigned-off-by: Dev User <dev@example.com>"}
    missing = {"sha": "def456", "message": "Change"}
    malformed = {"sha": "ghi789", "message": "Change\n\nSigned-off-by: bad"}
    checks = dco_checks([valid, missing, malformed])
    assert checks[1].status == Status.FAIL
    assert checks[1].evidence == [{"sha": "def456"}]
    assert checks[2].status == Status.FAIL


def test_commit_integrity_handles_mismatch_and_signature_policy():
    commit = {"sha": "abc", "author": {"email": "a@example.com"}, "committer": {"email": "b@example.com"}}
    checks = commit_checks([commit], signatures_required=True)
    assert checks[2].status == Status.WARN
    assert checks[3].status == Status.FAIL


def test_files_and_secret_scanner_redact_values():
    files = [{"path": ".env", "size": 10}, {"path": "large.bin", "size": 60 * 1024 * 1024, "binary": True}, {"path": "config.py", "content": "token = ghp_abcdefghijklmnopqrstuvwxyz123456"}]
    file_results = file_checks(files)
    assert file_results[0].status == Status.FAIL
    assert file_results[2].status == Status.FAIL
    secret_result = secret_checks(files)[0]
    assert secret_result.status == Status.FAIL
    assert "ghp_" not in str(secret_result.evidence)


def test_workflow_safe_and_dangerous_cases():
    safe = {"path": ".github/workflows/ci.yml", "content": "on: pull_request\npermissions: {contents: read}\n- uses: owner/action@0123456789abcdef0123456789abcdef01234567"}
    dangerous = {"path": ".github/workflows/deploy.yml", "content": "on: pull_request_target\npermissions: write-all\n- uses: actions/checkout@main\n  with:\n    ref: ${{ github.event.pull_request.head.sha }}\n- run: npm install"}
    assert workflow_checks([safe])[0].status == Status.PASS
    results = workflow_checks([dangerous])
    by_id = {result.check_id: result for result in results}
    assert by_id["GHA-001"].status == Status.FAIL
    assert by_id["GHA-003"].status == Status.WARN
    assert by_id["ACTION-002"].status == Status.WARN


def test_policy_separates_warning_from_blocking():
    result = Policy().apply(workflow_checks([{"path": "ci.yml", "content": "- uses: owner/action@main"}]))
    mutable = next(check for check in result.checks if check.check_id == "ACTION-002")
    assert mutable.status == Status.WARN
    assert mutable.blocking is False


def test_commits_use_pr_head_sha(monkeypatch):
    calls = []

    class Result:
        returncode = 0
        stdout = ""

    def fake_run(command, **kwargs):
        calls.append(command)
        return Result()

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    runner._commits(Path("."), "base-sha", "head-sha")

    assert calls[0][-1] == "base-sha..head-sha"