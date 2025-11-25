
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class TargetConfig:
    base_url: str
    ip_or_host: str
    aws_profile: Optional[str] = None
    ldap_server: Optional[str] = None
    ldap_user: Optional[str] = None
    ldap_password: Optional[str] = None
    login_path: Optional[str] = None
    idor_path: Optional[str] = None
    jwt_cookie_name: str = "jwt"


@dataclass
class Issue:
    area: str
    severity: str
    title: str
    description: str
    remediation: str
    references: Optional[List[str]] = None


SEVERITY_SCORES = {
    "High": 4,
    "Medium": 2,
    "Low": 1,
    "Info": 0,
}


def issue_risk_score(issue: Issue) -> int:
    return SEVERITY_SCORES.get(issue.severity, 0)


def total_risk_score(issues: List[Issue]) -> int:
    return sum(issue_risk_score(i) for i in issues)
