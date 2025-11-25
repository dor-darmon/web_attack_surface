
from typing import List, Optional
from urllib.parse import urljoin

import requests

from config import Issue, TargetConfig


class AttackRunner:
    def __init__(self, config: TargetConfig) -> None:
        self.config = config
        self.session = requests.Session()

    def run(self) -> List[Issue]:
        issues: List[Issue] = []
        brute_issue = self.bruteforce_login_demo()
        if brute_issue:
            issues.append(brute_issue)
        return issues

    def bruteforce_login_demo(self) -> Optional[Issue]:
        if not self.config.login_path:
            return None

        url = urljoin(self.config.base_url, self.config.login_path)
        usernames = ["admin", "test", "user"]
        passwords = ["123456", "password", "admin123", "qwerty"]

        successful = []
        try:
            for u in usernames:
                for p in passwords:
                    resp = self.session.post(
                        url,
                        data={"username": u, "password": p},
                        timeout=5,
                    )
                    if resp.status_code in (200, 302) and "login" not in resp.url.lower():
                        successful.append((u, p))
                        break
        except Exception:
            return None

        if successful:
            return Issue(
                area="attack",
                severity="High",
                title="Weak credentials allow simple brute force",
                description=(
                    "Tested a small password list on the login endpoint and "
                    "found at least one working weak credential pair."
                ),
                remediation=(
                    "Enforce strong password policies, implement rate limiting and "
                    "lockout after repeated failed logins. Consider multi factor authentication."
                ),
                references=[
                    "https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks"
                ],
            )
        return None
