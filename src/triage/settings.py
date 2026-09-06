import os
from pathlib import Path

from dotenv import load_dotenv

# Detect if running on Vercel
IS_VERCEL = os.environ.get("VERCEL") == "1"

BASE_DIR = Path(__file__).resolve().parent.parent.parent
load_dotenv(BASE_DIR / ".env")

# On Vercel, only /tmp is writable
if IS_VERCEL:
    import tempfile
    DATA_DIR = Path(tempfile.gettempdir()) / "triage_data"
else:
    DATA_DIR = BASE_DIR / "data"

REPORT_DIR = DATA_DIR / "reports"
DB_PATH = DATA_DIR / "triage.db"

for _d in (DATA_DIR, REPORT_DIR):
    _d.mkdir(parents=True, exist_ok=True)

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "").strip()
TRIAGE_MODEL = os.getenv("TRIAGE_MODEL", "claude-sonnet-4-5")
MAX_TOKENS = int(os.getenv("MAX_TOKENS", "4096"))
MAX_TOOL_ITERATIONS = int(os.getenv("MAX_TOOL_ITERATIONS", "12"))
DEMO_SEED = int(os.getenv("DEMO_SEED", "1337"))
CORRELATION_WINDOW_MINUTES = int(os.getenv("CORRELATION_WINDOW_MINUTES", "45"))

# Optional real threat-intel API (AbuseIPDB). When empty, only the bundled
# local reputation table is used.
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()

# Organization context the agent uses for user/asset lookups.
ORGANIZATION = "Acme Corp"
ORG_LOCATIONS = ["Manila, PH", "Singapore, SG", "San Jose, US", "Frankfurt, DE"]

# Known hosts / accounts used by suppression rules and user context tool.
TEST_HOSTS = ["corp-ws-test-01", "corp-ws-test-02"]
SERVICE_ACCOUNTS = ["backup.svc", "scanner.svc", "patch.svc"]
SCANNER_CIDRS = ["10.0.0.0/24"]
VPN_NETWORK = "10.200.0.0/24"

# ATT&CK technique IDs that must ALWAYS reach the agent tier, even if they
# match a suppression rule. Suppress by evidence, escalate by category.
ALWAYS_ESCALATE_TECHNIQUES = [
    "T1098.001",  # account creation / manipulation
    "T1562.001",  # log tampering / clearing
    "T1621",      # MFA fatigue
    "T1053.005",  # scheduled task persistence
    "T1110",      # brute force
    "T1505.003",  # web shell
    "T1003.001",  # lsass credential dumping
]

# Techniques worth a strong "true positive" prior when corroborated by intel.
HIGH_SIGNAL_NOISE = [
    "T1566.002",  # phishing link
    "T1048.003",  # exfiltration over HTTPS
    "T1021.001",  # psexec lateral movement
    "T1041",      # exfil over C2
]
