import re
import math
from typing import List, Dict, Any

# Common secret signatures and patterns
REGEX_PATTERNS = [
    {
        "id": "AWS_KEY",
        "pattern": r"(AKIA[0-9A-Z]{16})",
        "title": "AWS Access Key ID Detected",
        "cwe": "CWE-798",
        "severity": "CRITICAL",
        "description": "Hard-coded AWS Access Key ID found in source code."
    },
    {
        "id": "AWS_SECRET",
        "pattern": r"(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key|aws_secret)\s*=\s*['\"]([A-Za-z0-9/+=]{30,})['\"]",
        "title": "AWS Secret Access Key Detected",
        "cwe": "CWE-798",
        "severity": "CRITICAL",
        "description": "Hard-coded AWS Secret Access Key found in source code."
    },
    {
        "id": "DB_CONNECTION_STRING",
        "pattern": r"((?:postgres(?:ql)?|mysql|mongodb|redis|mssql):\/\/[A-Za-z0-9_\-\.]+:[^@\s\"']+@[A-Za-z0-9_\-\.:]+(?:\/[A-Za-z0-9_\-\.]*)?)",
        "title": "Database URI With Hardcoded Credentials",
        "cwe": "CWE-798",
        "severity": "CRITICAL",
        "description": "Connection string contains plaintext username and password."
    },
    {
        "id": "JWT_SECRET",
        "pattern": r"(?:JWT_SECRET_KEY|JWT_SECRET|SECRET_KEY|jwt_secret)\s*=\s*['\"]([^'\"]{10,})['\"]",
        "title": "Hard-coded JWT Signing Secret",
        "cwe": "CWE-798",
        "severity": "HIGH",
        "description": "Symmetric JWT signing key exposed in source code enables token forgery."
    },
    {
        "id": "STRIPE_KEY",
        "pattern": r"(?:sk_live_[0-9a-zA-Z]{24,})|(?:STRIPE_LIVE_KEY\s*=\s*['\"]([^'\"]+)['\"])",
        "title": "Stripe Live API Key Detected",
        "cwe": "CWE-798",
        "severity": "CRITICAL",
        "description": "Production payment gateway API secret found in code."
    },
    {
        "id": "GIT_HISTORY_LEAK",
        "pattern": r"(#.*secret remains in commit|#.*committed credential|#.*leaked in git)",
        "title": "Git History Credential Leak Warning",
        "cwe": "CWE-798",
        "severity": "HIGH",
        "description": "Code indicates sensitive credentials remain in prior git commits or version control history."
    }
]

def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    for char in set(data):
        p_x = float(data.count(char)) / len(data)
        entropy += - p_x * math.log2(p_x)
    return entropy

def scan_secrets(code: str) -> List[Dict[str, Any]]:
    vulnerabilities = []
    lines = code.split("\n")
    
    # 1. Regex pattern scans
    for rule in REGEX_PATTERNS:
        for line_no, line in enumerate(lines, 1):
            matches = re.finditer(rule["pattern"], line, re.IGNORECASE)
            for m in matches:
                matched_str = m.group(0)
                # Mask secret value in report
                masked = re.sub(r'(:[^@\s/]+@|="[^"]{4})', '=[REDACTED]', matched_str)
                vulnerabilities.append({
                    "id": rule["id"],
                    "category": "Secret Exposure",
                    "title": rule["title"],
                    "line": line_no,
                    "cwe": rule["cwe"],
                    "severity": rule["severity"],
                    "description": rule["description"],
                    "snippet": line.strip(),
                    "recommendation": "Extract credentials into environment variables (`os.getenv(...)`) and inject them via a secure secrets manager."
                })

    # 2. Entropy-based high-entropy string assignment detection
    assign_pattern = re.compile(r'([A-Za-z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASS|AUTH|CREDENTIAL)[A-Za-z0-9_]*)\s*=\s*["\']([^"\']{16,})["\']', re.IGNORECASE)
    for line_no, line in enumerate(lines, 1):
        for m in assign_pattern.finditer(line):
            var_name, val = m.group(1), m.group(2)
            # Avoid duplicate if already caught by regex
            if any(v["line"] == line_no for v in vulnerabilities):
                continue
            if shannon_entropy(val) > 3.2:
                vulnerabilities.append({
                    "id": "HIGH_ENTROPY_SECRET",
                    "category": "Secret Exposure",
                    "title": f"High-Entropy Secret Assigned to '{var_name}'",
                    "line": line_no,
                    "cwe": "CWE-798",
                    "severity": "HIGH",
                    "description": f"Variable '{var_name}' is assigned a high-entropy string (Shannon Entropy: {shannon_entropy(val):.2f}) resembling an API key or token.",
                    "snippet": line.strip(),
                    "recommendation": f"Replace literal with `os.getenv('{var_name}')`."
                })
                
    return vulnerabilities
