🛡 API Guard Lite
    _    ____  ___    ____                     _
   / \  |  _ \|_ _|  / ___|_   _  __ _ _ __ __| |
  / _ \ | |_) || |  | |  _| | | |/ _` | '__/ _` |
 / ___ \|  __/ | |  | |_| | |_| | (_| | | | (_| |
/_/   \_\_|   |___|  \____|\__,_|\__,_|_|  \__,_|
                                         L I T E


Lightweight Defensive API Security Scanner
Built for startups who ship fast — but want to ship secure.

🚀 Why API Guard Lite?

Most teams build APIs.
Very few actively validate their security hygiene before production.

API Guard Lite performs fast, non-intrusive checks to detect common misconfigurations that often lead to real-world breaches.

It’s not about hacking.
It’s about preventing stupid mistakes.

🧠 What It Actually Does

✔ Detects exposed sensitive files

.env

.git

common backup/config files

✔ Identifies publicly accessible admin panels

✔ Checks security headers

Strict-Transport-Security

Content-Security-Policy

X-Frame-Options

X-Content-Type-Options

✔ Validates SSL/TLS certificate health

✔ Verifies HTTP → HTTPS enforcement

✔ Performs lightweight rate limit behavior checks

✔ Generates structured JSON output (CI/CD friendly)

❌ What It Is NOT

NOT a penetration testing framework

NOT an exploitation tool

NOT designed for SQLi, XSS, RCE or payload attacks

NOT a replacement for professional security audits

API Guard Lite focuses on defensive misconfiguration detection only.

⚡ Quick Start
git clone https://github.com/yourusername/apiguard-lite.git
cd apiguard-lite
pip install -r requirements.txt
python cli.py https://example.com


JSON output:

python cli.py https://example.com --json

🏗 Example Output
Sensitive Files   ✖  CRITICAL   Exposed file detected: /.env
SSL/TLS           ✔  SAFE       Certificate valid
Security Headers  !  LOW        Missing CSP header


Security Score:

82 / 100

🔐 Designed For

Startup founders

Backend engineers

DevOps teams

CI/CD pipelines

Pre-production validation

🔄 CI Integration Example

Fail deployment if score < 80:

apiguard https://staging.example.com --json


Parse score in pipeline and block release if necessary.

📌 Philosophy

Security is not about hiding admin URLs.
Security is about eliminating misconfigurations.

API Guard Lite helps you enforce baseline API hygiene before attackers find it for you.

⚠ Disclaimer

Use only on assets you own or are explicitly authorized to test.
This tool is built for defensive security assessment purposes only.

🛠 Roadmap

Safe Mode for production checks

Plugin-based architecture

GitHub Action template

HTML report export