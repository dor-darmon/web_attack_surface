
from typing import List

from fastapi import FastAPI
from pydantic import BaseModel

from config import TargetConfig, Issue, total_risk_score
from web_scanner import WebScanner
from network_scanner import NetworkScanner
from ad_scanner import ActiveDirectoryScanner
from cloud_scanner import CloudScanner
from attack_runner import AttackRunner


app = FastAPI(title="Attack Surface Auditor API")


class ScanRequest(BaseModel):
    base_url: str
    ip_or_host: str
    aws_profile: str | None = None
    ldap_server: str | None = None
    ldap_user: str | None = None
    ldap_password: str | None = None
    login_path: str | None = None
    idor_path: str | None = None
    fast_scan: bool = False
    cloud_only: bool = False


class IssueOut(BaseModel):
    area: str
    severity: str
    title: str
    description: str
    remediation: str
    references: List[str]


def build_config_from_request(req: ScanRequest) -> TargetConfig:
    return TargetConfig(
        base_url=req.base_url,
        ip_or_host=req.ip_or_host,
        aws_profile=req.aws_profile,
        ldap_server=req.ldap_server,
        ldap_user=req.ldap_user,
        ldap_password=req.ldap_password,
        login_path=req.login_path,
        idor_path=req.idor_path,
    )


def run_all(config: TargetConfig, fast_scan: bool, cloud_only: bool) -> List[Issue]:
    issues: List[Issue] = []

    if cloud_only:
        issues.extend(CloudScanner(config).run())
        return issues

    issues.extend(WebScanner(config).run())

    if not fast_scan:
        issues.extend(NetworkScanner(config).run())
        issues.extend(ActiveDirectoryScanner(config).run())
        issues.extend(CloudScanner(config).run())
        issues.extend(AttackRunner(config).run())

    return issues


@app.post("/scan")
def start_scan(req: ScanRequest):
    config = build_config_from_request(req)
    issues = run_all(config, fast_scan=req.fast_scan, cloud_only=req.cloud_only)
    return {
        "total": len(issues),
        "risk_score": total_risk_score(issues),
        "issues": [
            IssueOut(
                area=i.area,
                severity=i.severity,
                title=i.title,
                description=i.description,
                remediation=i.remediation,
                references=i.references or [],
            )
            for i in issues
        ],
    }
