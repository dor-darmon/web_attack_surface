
from typing import List
import subprocess

from config import Issue, TargetConfig


class NetworkScanner:
    def __init__(self, config: TargetConfig) -> None:
        self.config = config

    def run(self) -> List[Issue]:
        issues: List[Issue] = []
        issues.extend(self.run_nmap_basic())
        issues.extend(self.run_nmap_vuln_style())
        return issues

    def run_nmap_basic(self) -> List[Issue]:
        issues: List[Issue] = []
        target = self.config.ip_or_host

        try:
            result = subprocess.run(
                ["nmap", "-sV", "-T4", "-F", target],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except FileNotFoundError:
            issues.append(
                Issue(
                    area="network",
                    severity="Info",
                    title="Nmap not installed",
                    description=(
                        "Nmap command not found. Network scan skipped."
                    ),
                    remediation=(
                        "Install Nmap to enable port and service enumeration."
                    ),
                    references=["https://nmap.org/"],
                )
            )
            return issues
        except subprocess.TimeoutExpired:
            issues.append(
                Issue(
                    area="network",
                    severity="Low",
                    title="Nmap scan timeout",
                    description="Nmap scan exceeded timeout and stopped.",
                    remediation="Run a manual scan with tuned parameters.",
                    references=["https://nmap.org/book/man.html"],
                )
            )
            return issues

        output = result.stdout.lower()

        if "open" in output:
            issues.append(
                Issue(
                    area="network",
                    severity="Medium",
                    title="Open services detected",
                    description=(
                        "One or more ports are open. Review exposed services "
                        "and confirm they match business needs."
                    ),
                    remediation=(
                        "Limit exposed services, apply firewall rules, and "
                        "turn off unused services."
                    ),
                    references=[
                        "https://owasp.org/www-community/controls/Network_security_configuration"
                    ],
                )
            )

        if "ftp " in output or "telnet" in output:
            issues.append(
                Issue(
                    area="network",
                    severity="High",
                    title="Legacy clear text protocols",
                    description=(
                        "Legacy protocols such as FTP or Telnet detected. "
                        "These protocols send data in clear text."
                    ),
                    remediation=(
                        "Replace legacy services with secure alternatives "
                        "such as SFTP or SSH."
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/Man-in-the-middle_attack"
                    ],
                )
            )

        return issues

    def run_nmap_vuln_style(self) -> List[Issue]:
        issues: List[Issue] = []
        target = self.config.ip_or_host

        try:
            result = subprocess.run(
                ["nmap", "-sV", "--script", "default,safe", "-p", "1-1024", target],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        except Exception:
            return issues

        output = result.stdout.lower()
        if "ssl-cert" in output or "tls" in output:
            issues.append(
                Issue(
                    area="network",
                    severity="Low",
                    title="TLS configuration findings",
                    description=(
                        "Nmap ssl related scripts returned output. "
                        "Review TLS configuration and certificate details."
                    ),
                    remediation=(
                        "Enforce modern TLS versions and strong ciphers. "
                        "Use certificates from a trusted authority."
                    ),
                    references=[
                        "https://owasp.org/www-project-top-ten/"
                    ],
                )
            )
        return issues
