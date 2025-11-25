
from typing import List

from config import Issue, TargetConfig


class ActiveDirectoryScanner:
    def __init__(self, config: TargetConfig) -> None:
        self.config = config

    def run(self) -> List[Issue]:
        issues: List[Issue] = []

        if not self.config.ldap_server:
            issues.append(
                Issue(
                    area="ad",
                    severity="Info",
                    title="AD scan skipped",
                    description="No LDAP server configured.",
                    remediation="Set LDAP details to enable AD checks.",
                    references=[],
                )
            )
            return issues

        try:
            from ldap3 import Server, Connection, ALL
        except ImportError:
            issues.append(
                Issue(
                    area="ad",
                    severity="Info",
                    title="ldap3 not installed",
                    description="AD scan requires ldap3 library.",
                    remediation="Install ldap3 with: pip install ldap3",
                    references=["https://ldap3.readthedocs.io/"],
                )
            )
            return issues

        server = Server(self.config.ldap_server, get_info=ALL)
        conn = Connection(
            server,
            user=self.config.ldap_user,
            password=self.config.ldap_password,
            auto_bind=True,
        )

        search_base = "DC=example,DC=local"
        search_filter = "(&(objectCategory=person)(objectClass=user))"
        conn.search(search_base, search_filter, attributes=["userAccountControl", "sAMAccountName"])

        risky_accounts = []
        for entry in conn.entries:
            uac = int(entry.userAccountControl.value)
            if uac & 0x10000:
                risky_accounts.append(entry.sAMAccountName.value)

        if risky_accounts:
            issues.append(
                Issue(
                    area="ad",
                    severity="Medium",
                    title="Accounts with password never expire",
                    description=(
                        "Some accounts have password never expire flag. "
                        "This increases the risk of long term credential exposure."
                    ),
                    remediation=(
                        "Review these accounts and enforce password expiration "
                        "or move them to managed service accounts."
                    ),
                    references=[
                        "https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties"
                    ],
                )
            )

        issues.extend(self.kerberoast_demo(conn, search_base))

        conn.unbind()
        return issues

    def kerberoast_demo(self, conn, search_base: str) -> List[Issue]:
        issues: List[Issue] = []

        try:
            conn.search(
                search_base,
                "(&(objectClass=user)(servicePrincipalName=*))",
                attributes=["sAMAccountName", "servicePrincipalName"],
            )
        except Exception:
            return issues

        if conn.entries:
            issues.append(
                Issue(
                    area="ad",
                    severity="Medium",
                    title="Kerberoastable service accounts detected",
                    description=(
                        "There are user accounts with servicePrincipalName set. "
                        "These accounts can be targets for Kerberoasting attacks if weak passwords are used."
                    ),
                    remediation=(
                        "Use long random passwords for service accounts and monitor "
                        "for unusual Kerberos ticket requests."
                    ),
                    references=[
                        "https://adsecurity.org/?p=2293"
                    ],
                )
            )
        return issues
