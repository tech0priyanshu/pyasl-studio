from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import CheckResult, GatewayResult, Status


DEFAULT_POLICY: dict[str, Any] = {
    "dco": {"required": True},
    "secrets": {"block": True},
    "dangerous_workflow": {"block": True},
    "mutable_actions": {"block": False},
    "harden_runner": {"required": False},
    "large_files": {"warn_bytes": 5 * 1024 * 1024, "fail_bytes": 50 * 1024 * 1024},
}


@dataclass
class Policy:
    values: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_POLICY))

    @classmethod
    def load(cls, path: Path | None = None) -> "Policy":
        values = _deep_merge(DEFAULT_POLICY, {})
        if path and path.exists():
            try:
                import yaml
            except ImportError as exc:
                raise RuntimeError("PyYAML is required to load a gateway policy file") from exc
            loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            values = _deep_merge(values, loaded.get("gateway", loaded))
        return cls(values)

    def apply(self, checks: list[CheckResult]) -> GatewayResult:
        for check in checks:
            check.blocking = self._blocks(check)
        return GatewayResult(checks)

    def _blocks(self, check: CheckResult) -> bool:
        if check.status in (Status.PASS, Status.SKIP):
            return False
        if check.status == Status.ERROR:
            return True
        if check.check_id.startswith("DCO-"):
            return bool(self.values.get("dco", {}).get("required", True))
        if check.check_id.startswith("SECRET-"):
            return bool(self.values.get("secrets", {}).get("block", True))
        if check.check_id in {"GHA-001", "GHA-005"}:
            return bool(self.values.get("dangerous_workflow", {}).get("block", True))
        if check.check_id.startswith("ACTION-"):
            return bool(self.values.get("mutable_actions", {}).get("block", False))
        if check.check_id == "SR-001":
            return bool(self.values.get("harden_runner", {}).get("required", False))
        return check.blocking


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result