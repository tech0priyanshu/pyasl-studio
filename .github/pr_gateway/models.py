from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class Status(StrEnum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    SKIP = "SKIP"
    ERROR = "ERROR"


class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class CheckResult:
    check_id: str
    name: str
    category: str
    status: Status
    severity: Severity = Severity.INFO
    message: str = ""
    evidence: list[dict[str, Any]] = field(default_factory=list)
    remediation: str = ""
    blocking: bool = False

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["status"] = self.status.value
        result["severity"] = self.severity.value
        return result


@dataclass
class GatewayResult:
    checks: list[CheckResult]

    @property
    def failures(self) -> list[CheckResult]:
        return [check for check in self.checks if check.blocking]

    @property
    def warnings(self) -> list[CheckResult]:
        return [check for check in self.checks if check.status == Status.WARN]

    @property
    def status(self) -> Status:
        if any(check.status == Status.ERROR for check in self.checks):
            return Status.ERROR
        return Status.FAIL if self.failures else (Status.WARN if self.warnings else Status.PASS)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "failures": len(self.failures),
            "warnings": len(self.warnings),
            "checks": [check.to_dict() for check in self.checks],
        }