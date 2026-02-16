```text
   _    ____  ___    ____                     _ 
  / \  |  _ \|_ _|  / ___|_   _  __ _ _ __ __| |
 / _ \ | |_) || |  | |  _| | | |/ _` | '__/ _` |
/ ___ \|  __/ | |  | |_| | |_| | (_| | | | (_| |
/_/   \_\_|   |___|  \____|\__,_|\__,_|_|  \__,_|
                                             L I T E
Lightweight Defensive API Security Scanner Built for startups who ship fast — but want to ship secure.

🚀 Why API Guard Lite?
Most teams build APIs. Very few actively validate their security hygiene before production.

API Guard Lite performs fast, non-intrusive checks to detect common misconfigurations that often lead to real-world breaches. It’s not about hacking. It’s about preventing stupid mistakes before they go live.

🧠 What It Actually Does
API Guard Lite is designed to be a "sanity check" for your infrastructure.

✅ Capabilities
📂 Detects Exposed Sensitive Files:
.env, .git/config, backup.sql, config.php, etc.

🔓 Identifies Public Admin Panels:
Checks for common paths like /admin, /dashboard, /django-admin.

🛡 Checks Security Headers:
Strict-Transport-Security (HSTS)
Content-Security-Policy (CSP)
X-Frame-Options
X-Content-Type-Options

🔒 Validates SSL/TLS Health:
Checks certificate validity and issuer.
Enforce HTTPS: Verifies HTTP → HTTPS redirection.

🚦 Rate Limit Detection:
Performs lightweight behavior checks to see if the server throttles requests.

🤖 CI/CD Ready:
Generates structured JSON output for automated pipelines.

❌ What It Is NOT
This is a defensive tool, not an offensive weapon.

❌ NOT a penetration testing framework (like Metasploit).

❌ NOT an exploitation tool.

❌ NOT designed for SQLi, XSS, RCE, or payload injection attacks.

❌ NOT a replacement for professional security audits.

⚡ Quick Start
Installation

# Clone the repository
git clone [https://github.com/yourusername/apiguard-lite.git](https://github.com/yourusername/apiguard-lite.git)
cd apiguard-lite

# Install dependencies
pip install -r requirements.txt
Usage
Standard Scan:

python cli.py [https://example.com](https://example.com)
Safe Mode (Production Safe):
Skips intrusive checks like rate limit testing and directory brute-forcing.

python cli.py [https://example.com](https://example.com) --safe
JSON Output (CI/CD):

python cli.py [https://example.com](https://example.com) --json
🏗 Example Output
When running in standard mode, you get a rich, hacker-chic terminal output:


Target locked: [https://example.com](https://example.com)

CHECK             STATUS   RISK     DETAILS
────────────────────────────────────────────────────────────
Sensitive Files   ✖ FAIL   CRITICAL Exposed file: /.env
SSL/TLS           ✔ PASS   SAFE     Certificate valid
Security Headers  ! WARN   LOW      Missing CSP header
Admin Panel       ✔ PASS   SAFE     No panels detected
Rate Limiting     ✔ PASS   SAFE     Protected (429 returned)
Security Score
82 / 100

🔄 CI/CD Integration
You can easily integrate API Guard Lite into your GitHub Actions or GitLab CI pipelines.

Example Logic:
Fail the deployment if the security score is below 80.


# Run scan and capture JSON
SCAN_RESULT=$(python cli.py [https://staging.example.com](https://staging.example.com) --json)

# Parse score (requires jq)
SCORE=$(echo $SCAN_RESULT | jq '.score')

if [ "$SCORE" -lt 80 ]; then
  echo "Security Score too low: $SCORE. Deployment aborted."
  exit 1
fi
🔐 Designed For
Startup Founders: Quick check before showing investors.

Backend Engineers: Sanity check your own deployments.

DevOps Teams: Automate hygiene checks in pipelines.

QA Engineers: Validate pre-production environments.

📌 Philosophy
"Security is not about hiding admin URLs. Security is about eliminating misconfigurations."

API Guard Lite helps you enforce baseline API hygiene before attackers find the gaps for you.

🛠 Roadmap
[x] CLI Interface (Rich)

[x] JSON Export

[x] Safe Mode

[ ] Plugin-based architecture

[ ] HTML Report Export

[ ] Slack/Discord Notification Webhooks

⚠ Disclaimer
Use only on assets you own or are explicitly authorized to test.
This tool is built for defensive security assessment purposes only. The authors are not responsible for any misuse or damage caused by this tool.