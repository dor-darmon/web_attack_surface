
Web Attack Surface Auditor

A Python based security auditing and offensive testing toolkit that runs automated checks on web, network, Active Directory and AWS environments.

Main features
Web security checks
  Security headers
  Reflected XSS demo
  CSRF token presence
  CORS configuration
  JWT cookie flags
  IDOR pattern demo
  Exposed files

Network checks
  Nmap service scan
  Nmap default and safe scripts

Active Directory checks
  Password never expire flag
  Kerberoastable accounts demo

Cloud checks
  IAM user attached policies
  Public S3 bucket ACLs

Attack runner
  Simple credential brute force demo for login endpoints

Reports
  HTML report with summary and risk score
  JSON report for integrations

CLI examples
  python main.py --url https://target.local --host 1.2.3.4 --login-path /login --idor-path /item?id=

API server
  uvicorn api_server:app --reload

  POST /scan with JSON body to trigger scans programmatically.
