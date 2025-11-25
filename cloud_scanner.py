
from typing import List

from config import Issue, TargetConfig


class CloudScanner:
    def __init__(self, config: TargetConfig) -> None:
        self.config = config

    def run(self) -> List[Issue]:
        issues: List[Issue] = []

        if not self.config.aws_profile:
            issues.append(
                Issue(
                    area="cloud",
                    severity="Info",
                    title="Cloud scan skipped",
                    description="No AWS profile configured.",
                    remediation="Set AWS profile to enable basic cloud checks.",
                    references=[],
                )
            )
            return issues

        try:
            import boto3
        except ImportError:
            issues.append(
                Issue(
                    area="cloud",
                    severity="Info",
                    title="boto3 not installed",
                    description="Cloud scan requires boto3 library.",
                    remediation="Install boto3 with: pip install boto3",
                    references=["https://boto3.amazonaws.com/v1/documentation/api/latest/index.html"],
                )
            )
            return issues

        session = boto3.Session(profile_name=self.config.aws_profile)

        iam_issues = self.check_iam(session)
        issues.extend(iam_issues)

        s3_issues = self.check_s3_public_buckets(session)
        issues.extend(s3_issues)

        return issues

    def check_iam(self, session) -> List[Issue]:
        issues: List[Issue] = []
        iam = session.client("iam")

        users = iam.list_users().get("Users", [])
        for user in users:
            username = user["UserName"]
            policies = iam.list_attached_user_policies(UserName=username).get("AttachedPolicies", [])
            if policies:
                issues.append(
                    Issue(
                        area="cloud",
                        severity="Low",
                        title=f"IAM user with attached policies: {username}",
                        description=(
                            "IAM users with attached policies often hold permanent "
                            "credentials and permissions."
                        ),
                        remediation=(
                            "Prefer role based access with temporary credentials. "
                            "Review the need for user attached policies."
                        ),
                        references=[
                            "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"
                        ],
                    )
                )

        return issues

    def check_s3_public_buckets(self, session) -> List[Issue]:
        issues: List[Issue] = []
        s3 = session.client("s3")

        buckets = s3.list_buckets().get("Buckets", [])
        for bucket in buckets:
            name = bucket["Name"]
            try:
                acl = s3.get_bucket_acl(Bucket=name)
            except Exception:
                continue

            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                permission = grant.get("Permission")
                uri = grantee.get("URI", "")
                if permission in ("READ", "FULL_CONTROL") and ("AllUsers" in uri or "AuthenticatedUsers" in uri):
                    issues.append(
                        Issue(
                            area="cloud",
                            severity="High",
                            title=f"Public S3 bucket ACL: {name}",
                            description=(
                                f"S3 bucket {name} has ACL grant to a global group. "
                                "This might expose data to public access."
                            ),
                            remediation=(
                                "Remove public ACL grants and use bucket policies "
                                "with least privilege. Review S3 Block Public Access."
                            ),
                            references=[
                                "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html"
                            ],
                        )
                    )

        return issues
