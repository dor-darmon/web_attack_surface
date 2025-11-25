
from typing import List, Dict, Optional
from urllib.parse import urljoin

import requests

from config import Issue, TargetConfig


class WebScanner:
    def __init__(self, config: TargetConfig) -> None:
        self.config = config
        self.session = requests.Session()

    def run(self) -> List[Issue]:
        issues: List[Issue] = []
        headers_result = self.check_security_headers()
        issues.extend(headers_result)

        xss_result = self.check_reflected_xss_demo()
        if xss_result:
            issues.append(xss_result)

        csrf_issue = self.check_csrf_protection()
        if csrf_issue:
            issues.append(csrf_issue)

        cors_issues = self.check_cors()
        issues.extend(cors_issues)

        jwt_issue = self.check_jwt_cookie_usage()
        if jwt_issue:
            issues.append(jwt_issue)

        idor_issue = self.check_idor_demo()
        if idor_issue:
            issues.append(idor_issue)

        file_issues = self.check_exposed_files()
        issues.extend(file_issues)

        return issues

    def fetch_root(self) -> requests.Response:
        url = self.config.base_url.rstrip("/")
        resp = self.session.get(url, timeout=10)
        return resp

    def check_security_headers(self) -> List[Issue]:
        issues: List[Issue] = []
        resp = self.fetch_root()
        headers = {k.lower(): v for k, v in resp.headers.items()}

        required: Dict[str, str] = {
            "content-security-policy": "Content Security Policy missing",
            "x-frame-options": "Clickjacking protection header missing",
            "x-content-type-options": "X Content Type Options header missing",
            "referrer-policy": "Referrer Policy header missing",
            "strict-transport-security": "HSTS header missing",
        }

        for header_name, message in required.items():
            if header_name not in headers:
                issues.append(
                    Issue(
                        area="web",
                        severity="Medium",
                        title=message,
                        description=(
                            f"{header_name} header is not present on the root response. "
                            "Modern applications should send secure defaults."
                        ),
                        remediation=(
                            "Add this header with a secure value in the web server "
                            "or application configuration."
                        ),
                        references=[
                            "https://owasp.org/www-project-secure-headers/"
                        ],
                    )
                )

        return issues

    def check_reflected_xss_demo(self) -> Optional[Issue]:
        test_param = "xss_test_param"
        payload = "<svg onload=alert(1)>"
        url = self.config.base_url.rstrip("/") + "/"
        params = {test_param: payload}

        try:
            resp = self.session.get(url, params=params, timeout=10)
        except Exception:
            return None

        if payload in resp.text:
            return Issue(
                area="web",
                severity="High",
                title="Possible reflected XSS",
                description=(
                    "Application reflects unencoded input in the response. "
                    "This might lead to reflected Cross Site Scripting."
                ),
                remediation=(
                    "Encode output, validate input, and use security headers "
                    "such as Content Security Policy."
                ),
                references=[
                    "https://owasp.org/www-community/attacks/xss/",
                    "https://owasp.org/Top10/A03_2021-Injection/"
                ],
            )

        return None

    def check_csrf_protection(self) -> Optional[Issue]:
        if not self.config.login_path:
            return None

        url = urljoin(self.config.base_url, self.config.login_path)
        try:
            resp = self.session.get(url, timeout=10)
        except Exception:
            return None

        has_token = "csrf" in resp.text.lower()
        if not has_token:
            return Issue(
                area="web",
                severity="Medium",
                title="Possible missing CSRF protection",
                description=(
                    "Login or form page does not appear to include a CSRF token. "
                    "This may expose state changing requests to CSRF attacks."
                ),
                remediation=(
                    "Implement server side CSRF tokens, bind them to the session "
                    "and validate on each sensitive request."
                ),
                references=[
                    "https://owasp.org/www-community/attacks/csrf"
                ],
            )
        return None

    def check_cors(self) -> List[Issue]:
        issues: List[Issue] = []
        url = self.config.base_url.rstrip("/") + "/"
        try:
            resp = self.session.options(
                url,
                headers={"Origin": "http://evil.local"},
                timeout=10,
            )
        except Exception:
            return issues

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        if acao == "*" or "evil.local" in acao:
            issues.append(
                Issue(
                    area="web",
                    severity="Medium",
                    title="Overly permissive CORS configuration",
                    description=(
                        "CORS response for test origin is overly permissive. "
                        "This might allow untrusted origins to access sensitive APIs."
                    ),
                    remediation=(
                        "Limit Access Control Allow Origin to trusted domains only "
                        "and avoid wildcard usage for authenticated endpoints."
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/CORS_misconfiguration"
                    ],
                )
            )
        return issues

    def check_jwt_cookie_usage(self) -> Optional[Issue]:
        root = self.fetch_root()
        set_cookies = root.headers.get("Set-Cookie", "")
        if not set_cookies:
            return None

        if self.config.jwt_cookie_name not in set_cookies:
            return None

        cookie_value = set_cookies.lower()
        if "httponly" not in cookie_value or "secure" not in cookie_value:
            return Issue(
                area="web",
                severity="Medium",
                title="JWT cookie missing secure flags",
                description=(
                    "JWT is set in a cookie without HttpOnly and Secure flags. "
                    "This raises risk of theft through XSS or clear text transport."
                ),
                remediation=(
                    "Set JWT cookies with HttpOnly, Secure and SameSite attributes. "
                    "Consider short lived tokens and refresh tokens."
                ),
                references=[
                    "https://owasp.org/www-community/HttpOnly"
                ],
            )
        return None

    def check_idor_demo(self) -> Optional[Issue]:
        if not self.config.idor_path:
            return None

        base = self.config.base_url.rstrip("/")
        url1 = base + self.config.idor_path + "1"
        url2 = base + self.config.idor_path + "2"

        try:
            r1 = self.session.get(url1, timeout=10)
            r2 = self.session.get(url2, timeout=10)
        except Exception:
            return None

        if r1.status_code == 200 and r2.status_code == 200 and r1.text != r2.text:
            return Issue(
                area="web",
                severity="High",
                title="Possible IDOR pattern",
                description=(
                    "Changing a numeric identifier in the URL returns different content "
                    "without visible authorization checks. This indicates a possible IDOR."
                ),
                remediation=(
                    "Enforce authorization checks on server side for each object access "
                    "and avoid relying on user supplied identifiers alone."
                ),
                references=[
                    "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
                ],
            )
        return None

    def check_exposed_files(self) -> List[Issue]:
        issues: List[Issue] = []
        candidates = [
            ".git/config",
            "backup.zip",
            "db_backup.sql",
            ".env",
            "config.old",
        ]
        base = self.config.base_url.rstrip("/") + "/"

        for path in candidates:
            url = urljoin(base, path)
            try:
                resp = self.session.get(url, timeout=5)
            except Exception:
                continue

            if resp.status_code == 200 and len(resp.content) > 0:
                issues.append(
                    Issue(
                        area="web",
                        severity="High",
                        title=f"Possible exposed file: {path}",
                        description=(
                            f"Path {path} is accessible and returns content. "
                            "This may expose sensitive configuration or source code."
                        ),
                        remediation=(
                            "Block access to internal files using server configuration "
                            "and move backups and repository data out of the web root."
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/Path_Traversal"
                        ],
                    )
                )
        return issues
