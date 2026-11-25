import re
from dataclasses import dataclass
from typing import List, Pattern, Set


@dataclass
class Rule:
    name: str
    description: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM"
    pattern: Pattern
    entropy_check: bool = False


# Obvious non-secret placeholders to avoid false positives in generic assignments
PLACEHOLDER_EXCLUSIONS: Set[str] = {
    "your_api_key_here",
    "your_secret_here",
    "your_token_here",
    "your_password_here",
    "insert_api_key_here",
    "insert_token_here",
    "my_secret_token_123",
    "placeholder_key",
    "replace_with_key",
    "changethispassword",
    "dummy_secret_value",
    "00000000000000000000000000000000",
    "12345678901234567890123456789012",
}


DEFAULT_RULES: List[Rule] = [
    Rule(
        name="OpenAI API Key",
        description="Matched OpenAI API key pattern",
        severity="CRITICAL",
        pattern=re.compile(r"\b(sk-(?:proj|admin|svcacct|None)-[a-zA-Z0-9_-]{20,128}|sk-[a-zA-Z0-9_-]{20,64})\b"),
    ),
    Rule(
        name="GitHub Personal Access Token",
        description="Matched GitHub token (classic, fine-grained, app or OAuth)",
        severity="CRITICAL",
        pattern=re.compile(r"\b(gh[pousr]_[a-zA-Z0-9]{30,40}|github_pat_[a-zA-Z0-9_]{40,82})\b"),
    ),
    Rule(
        name="AWS Access Key ID",
        description="Matched AWS standard or STS temporary access key",
        severity="HIGH",
        pattern=re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"),
    ),
    Rule(
        name="AWS Secret Access Key",
        description="Matched AWS secret access key assignment",
        severity="CRITICAL",
        pattern=re.compile(r"(?i)\b(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9\/+=]{40})['\"]?\b"),
    ),
    Rule(
        name="Google Cloud API Key",
        description="Matched Google Cloud API Key pattern",
        severity="HIGH",
        pattern=re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
    ),
    Rule(
        name="Stripe API Key",
        description="Matched Stripe live or test secret/restricted key",
        severity="CRITICAL",
        pattern=re.compile(r"\b([rs]k_(?:live|test)_[0-9a-zA-Z]{24,34})\b"),
    ),
    Rule(
        name="Slack Token",
        description="Matched Slack bot, user or workspace token",
        severity="HIGH",
        pattern=re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b"),
    ),
    Rule(
        name="Private Encryption Key",
        description="Detected private certificate or encryption key block",
        severity="CRITICAL",
        pattern=re.compile(r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY(?: BLOCK)?-----"),
    ),
    Rule(
        name="JSON Web Token (JWT)",
        description="Matched structured compact JSON Web Token",
        severity="MEDIUM",
        pattern=re.compile(r"\b(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b"),
    ),
    Rule(
        name="Database Connection String",
        description="Database connection URL containing embedded credentials",
        severity="CRITICAL",
        pattern=re.compile(
            r"\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis):\/\/[a-zA-Z0-9_\-\.]+:[^@\s]+@[a-zA-Z0-9\.\-_]+(?::\d+)?\/?[^\s]*)\b"
        ),
    ),
    Rule(
        name="Generic Secret Assignment",
        description="Variable assignment matching sensitive credential name",
        severity="HIGH",
        pattern=re.compile(
            r"(?i)\b(?:api_key|apikey|secret_key|app_secret|client_secret|auth_token|db_password)\s*[:=]\s*['\"]([a-zA-Z0-9_\-\.]{14,})['\"]"
        ),
        entropy_check=True,
    ),
]

SENSITIVE_FILE_PATTERNS = [
    re.compile(r"^.*\.env(?:\..+)?$"),
    re.compile(r"^.*id_(?:rsa|ecdsa|ed25519)$"),
    re.compile(r"^.*\.pem$"),
    re.compile(r"^.*\.pfx$"),
    re.compile(r"^.*\.key$"),
    re.compile(r"^.*credentials\.json$"),
    re.compile(r"^.*service-account.*\.json$"),
]

DEFAULT_IGNORE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".venv",
    "venv",
    "env",
    ".tox",
    "build",
    "dist",
    ".eggs",
    ".idea",
    ".vscode",
}

DEFAULT_IGNORE_EXTENSIONS = {
    ".pyc",
    ".pyo",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".svg",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".7z",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp4",
    ".mp3",
    ".mov",
}
