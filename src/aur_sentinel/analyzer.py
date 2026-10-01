"""Pure static-analysis engine for PKGBUILD content."""

import re
from dataclasses import dataclass
from enum import StrEnum
from re import Pattern
from typing import Final


class RiskLevel(StrEnum):
    """Overall severity assigned to a scan report."""

    CLEAN = "clean"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class Rule:
    """A deterministic signature applied to PKGBUILD text."""

    rule_id: str
    description: str
    score: int
    pattern: Pattern[str]


@dataclass(frozen=True, slots=True)
class Finding:
    """A matched rule with its source location."""

    rule_id: str
    description: str
    score: int
    line: int
    evidence: str


@dataclass(frozen=True, slots=True)
class ScanReport:
    """Immutable result of analyzing one PKGBUILD."""

    score: int
    risk: RiskLevel
    findings: tuple[Finding, ...]


RULES: Final[tuple[Rule, ...]] = (
    Rule(
        rule_id="network.pipe-to-shell",
        description="Downloads remote content and pipes it directly to a shell",
        score=80,
        pattern=re.compile(r"(?:curl|wget)\b[^\n|;]*\|\s*(?:ba)?sh\b", re.IGNORECASE),
    ),
    Rule(
        rule_id="obfuscation.base64-exec",
        description="Decodes Base64 content before shell execution",
        score=55,
        pattern=re.compile(r"base64\s+(?:--decode|-d)\b[^\n;]*\|\s*(?:ba)?sh\b", re.IGNORECASE),
    ),
    Rule(
        rule_id="destruction.root-delete",
        description="Attempts recursive deletion from the filesystem root",
        score=100,
        pattern=re.compile(r"rm\s+-[^\n;]*r[^\n;]*f[^\n;]*\s+/(?:\s|;|$)", re.IGNORECASE),
    ),
    Rule(
        rule_id="persistence.ssh-key-access",
        description="Reads or modifies user SSH key material",
        score=60,
        pattern=re.compile(r"(?:\.ssh/|authorized_keys|id_(?:rsa|ed25519))", re.IGNORECASE),
    ),
    Rule(
        rule_id="execution.shared-memory",
        description="Executes content from a volatile shared-memory directory",
        score=45,
        pattern=re.compile(r"/dev/shm/[^\s;]+", re.IGNORECASE),  # noqa: S108
    ),
)

LOW_RISK_LIMIT: Final = 30
MEDIUM_RISK_LIMIT: Final = 60
HIGH_RISK_LIMIT: Final = 80


def _line_number(content: str, offset: int) -> int:
    return content.count("\n", 0, offset) + 1


def _risk_for_score(score: int) -> RiskLevel:
    if score == 0:
        return RiskLevel.CLEAN
    if score < LOW_RISK_LIMIT:
        return RiskLevel.LOW
    if score < MEDIUM_RISK_LIMIT:
        return RiskLevel.MEDIUM
    if score < HIGH_RISK_LIMIT:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def analyze_pkgbuild(content: str) -> ScanReport:
    """Analyze PKGBUILD source without executing it."""
    findings = tuple(
        Finding(
            rule_id=rule.rule_id,
            description=rule.description,
            score=rule.score,
            line=_line_number(content, match.start()),
            evidence=match.group(0).strip(),
        )
        for rule in RULES
        if (match := rule.pattern.search(content)) is not None
    )
    score = min(sum(finding.score for finding in findings), 100)
    return ScanReport(score=score, risk=_risk_for_score(score), findings=findings)
