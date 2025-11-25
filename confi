from dataclasses import dataclass
from typing import List


@dataclass
class TargetConfig:
    base_url: str
    ip_or_host: str
    aws_profile: str | None = None
    ldap_server: str | None = None
    ldap_user: str | None = None
    ldap_password: str | None = None


@dataclass
class Issue:
    area: str           # web, network, ad, cloud
    severity: str       # High, Medium, Low, Info
    title: str
    description: str
    remediation: str
    references: List[str] | None = None
