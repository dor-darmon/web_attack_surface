
import argparse
from typing import List

from config import TargetConfig, Issue, total_risk_score
from web_scanner import WebScanner
from network_scanner import NetworkScanner
from ad_scanner import ActiveDirectoryScanner
from cloud_scanner import CloudScanner
from attack_runner import AttackRunner
from report import render_report, save_report_html, save_report_json


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Web Attack Surface Auditor"
    )
    parser.add_argument(
        "--url",
        required=True,
        help="Base URL of the web application, for example https://target.local",
    )
    parser.add_argument(
        "--host",
        required=True,
        help="Target IP or host for network scan",
    )
    parser.add_argument(
        "--aws-profile",
        help="AWS profile name for cloud checks",
    )
    parser.add_argument(
        "--ldap-server",
        help="LDAP server for Active Directory checks",
    )
    parser.add_argument(
        "--ldap-user",
        help="LDAP bind user",
    )
    parser.add_argument(
        "--ldap-password",
        help="LDAP bind password",
    )
    parser.add_argument(
        "--login-path",
        help="Login path for CSRF and brute force demo, for example /login",
    )
    parser.add_argument(
        "--idor-path",
        help="IDOR demo path prefix, for example /item?id=",
    )
    parser.add_argument(
        "--output-html",
        default="audit_report.html",
        help="Output HTML report path",
    )
    parser.add_argument(
        "--output-json",
        default="audit_report.json",
        help="Output JSON report path",
    )
    parser.add_argument(
        "--fast-scan",
        action="store_true",
        help="Run a reduced quick scan",
    )
    parser.add_argument(
        "--cloud-only",
        action="store_true",
        help="Run cloud checks only",
    )
    return parser.parse_args()


def build_config(args: argparse.Namespace) -> TargetConfig:
    return TargetConfig(
        base_url=args.url,
        ip_or_host=args.host,
        aws_profile=args.aws_profile,
        ldap_server=args.ldap_server,
        ldap_user=args.ldap_user,
        ldap_password=args.ldap_password,
        login_path=args.login_path,
        idor_path=args.idor_path,
    )


def run_scanners(config: TargetConfig, fast_scan: bool, cloud_only: bool) -> List[Issue]:
    issues: List[Issue] = []

    if cloud_only:
        cloud_scanner = CloudScanner(config)
        issues.extend(cloud_scanner.run())
        return issues

    web_scanner = WebScanner(config)
    issues.extend(web_scanner.run())

    if not fast_scan:
        network_scanner = NetworkScanner(config)
        issues.extend(network_scanner.run())

        ad_scanner = ActiveDirectoryScanner(config)
        issues.extend(ad_scanner.run())

        cloud_scanner = CloudScanner(config)
        issues.extend(cloud_scanner.run())

        attack_runner = AttackRunner(config)
        issues.extend(attack_runner.run())

    return issues


def main() -> None:
    args = parse_args()
    config = build_config(args)

    print("[+] Running Web Attack Surface Auditor")
    issues = run_scanners(config, fast_scan=args.fast_scan, cloud_only=args.cloud_only)
    print(f"[+] Collected {len(issues)} findings")
    print(f"[+] Total risk score: {total_risk_score(issues)}")

    html = render_report(issues)
    html_path = save_report_html(html, args.output_html)
    print(f"[+] HTML report saved to {html_path}")

    json_path = save_report_json(issues, args.output_json)
    print(f"[+] JSON report saved to {json_path}")


if __name__ == "__main__":
    main()
