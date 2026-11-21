import re
from typing import List, Dict, Any, Tuple

# Known popular packages for typosquatting defense
POPULAR_PACKAGES = [
    "requests", "urllib3", "fastapi", "flask", "django", "numpy", "pandas",
    "pydantic", "sqlalchemy", "pytest", "scipy", "cryptography", "jinja2",
    "pyyaml", "boto3", "botocore", "aiohttp", "httpx", "celery", "redis",
    "langchain", "openai", "transformers", "torch", "tensorflow"
]

# Known vulnerability database with fixed versions
KNOWN_CVES = {
    "requests": [
        {"max_vulnerable": "2.20.0", "cve": "CVE-2018-18074", "severity": "HIGH", "fixed": "2.31.0", "desc": "Redirect credential leakage via Authorization header"},
        {"max_vulnerable": "2.31.0", "cve": "CVE-2023-32681", "severity": "MEDIUM", "fixed": "2.32.3", "desc": "Proxy-Authorization header leak on HTTPS redirect"}
    ],
    "urllib3": [
        {"max_vulnerable": "1.24.2", "cve": "CVE-2019-11324", "severity": "HIGH", "fixed": "1.26.18", "desc": "Certification handling failure when using certain SSL contexts"},
        {"max_vulnerable": "1.26.17", "cve": "CVE-2023-43804", "severity": "HIGH", "fixed": "2.2.2", "desc": "Cookie stripping failure on cross-origin redirects"}
    ],
    "pyyaml": [
        {"max_vulnerable": "5.3.1", "cve": "CVE-2020-14343", "severity": "CRITICAL", "fixed": "6.0.1", "desc": "Arbitrary code execution through FullLoader/UnsafeLoader"},
        {"max_vulnerable": "4.1", "cve": "CVE-2017-18342", "severity": "CRITICAL", "fixed": "5.4.1", "desc": "Arbitrary code execution during load()"}
    ],
    "flask": [
        {"max_vulnerable": "0.12.3", "cve": "CVE-2018-1000656", "severity": "HIGH", "fixed": "2.3.3", "desc": "Denial of service and unexpected behavior in older WSGI parsing"},
        {"max_vulnerable": "1.0.2", "cve": "CVE-2019-1010083", "severity": "HIGH", "fixed": "2.2.5", "desc": "High memory consumption via encoding mismatch"}
    ],
    "jinja2": [
        {"max_vulnerable": "2.11.2", "cve": "CVE-2019-10906", "severity": "HIGH", "fixed": "3.1.4", "desc": "Sandbox escape vulnerability via str.format_map"},
        {"max_vulnerable": "3.1.2", "cve": "CVE-2024-22195", "severity": "MEDIUM", "fixed": "3.1.4", "desc": "HTML attribute injection vulnerability"}
    ]
}

# Known AI-hallucinated package registry / heuristics
KNOWN_HALLUCINATED_PACKAGES = {
    "langchain-auto-sql-sanitizer": {
        "reason": "AI Hallucination Attack Vector: Non-existent phantom package frequently hallucinated by LLMs during prompt-to-code generation. Vulnerable to PyPI registry squatting and remote payload injection.",
        "safe_alternative": "Native parameterized queries with SQLAlchemy or SQLite cursor params."
    },
    "fastapi-auto-auth": {
        "reason": "AI Hallucinated phantom package. Not found on official PyPI repository.",
        "safe_alternative": "fastapi.security with OAuth2PasswordBearer or Depends."
    },
    "huggingface-prompt-shield": {
        "reason": "AI Hallucinated phantom package.",
        "safe_alternative": "transformers pipeline with official moderation model."
    }
}

def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def parse_version_tuple(v: str) -> Tuple[int, ...]:
    clean = re.sub(r'[^0-9\.]', '', v)
    parts = clean.split(".")
    res = []
    for p in parts:
        try:
            res.append(int(p))
        except ValueError:
            res.append(0)
    return tuple(res)

def version_lte(v1: str, v2: str) -> bool:
    t1 = parse_version_tuple(v1)
    t2 = parse_version_tuple(v2)
    max_len = max(len(t1), len(t2))
    t1 += (0,) * (max_len - len(t1))
    t2 += (0,) * (max_len - len(t2))
    return t1 <= t2

def scan_packages(text: str) -> List[Dict[str, Any]]:
    vulnerabilities = []
    lines = text.strip().split("\n")
    
    for line_no, line in enumerate(lines, 1):
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("#"):
            continue
        
        # Parse package and version constraint (e.g. requests==2.19.0 or reqeusts==2.31.0)
        match = re.match(r'^([A-Za-z0-9_\-\.]+)(?:([=><!~]+)([A-Za-z0-9_\-\.]+))?', line_clean)
        if not match:
            continue
        
        pkg_name = match.group(1).lower()
        operator = match.group(2) or "=="
        version = match.group(3) or "latest"

        # 1. Check AI-Hallucinated Package Risk (CWE-829)
        if pkg_name in KNOWN_HALLUCINATED_PACKAGES or ("sanitizer" in pkg_name and "langchain" in pkg_name):
            info = KNOWN_HALLUCINATED_PACKAGES.get(pkg_name, {
                "reason": "AI Hallucination Supply-Chain Risk: Package does not exist in legitimate package ecosystem. Attackers exploit this by registering hallucinated names on PyPI.",
                "safe_alternative": "Use native, audited libraries."
            })
            vulnerabilities.append({
                "id": "AI_PACKAGE_HALLUCINATION",
                "category": "Dependency Risk",
                "title": f"AI Hallucinated Package '{pkg_name}' Detected",
                "line": line_no,
                "cwe": "CWE-829",
                "severity": "CRITICAL",
                "description": f"AI coding assistant suggested package '{pkg_name}', which is a hallucinated entity not in trusted registries. If an attacker claims this name on PyPI, it results in arbitrary code execution.",
                "snippet": line_clean,
                "recommendation": f"Remove '{pkg_name}'. {info['safe_alternative']}"
            })
            continue

        # 2. Check Typosquatting / Supply Chain Masquerading (CWE-829)
        for legit_pkg in POPULAR_PACKAGES:
            if pkg_name != legit_pkg:
                dist = levenshtein_distance(pkg_name, legit_pkg)
                # Distance of 1 or transposed letters in common packages
                if (dist == 1 and len(pkg_name) >= 5) or (sorted(pkg_name) == sorted(legit_pkg) and pkg_name != legit_pkg):
                    vulnerabilities.append({
                        "id": "PACKAGE_TYPOSQUATTING",
                        "category": "Dependency Risk",
                        "title": f"Supply Chain Typosquatting: '{pkg_name}' Mimicking '{legit_pkg}'",
                        "line": line_no,
                        "cwe": "CWE-829",
                        "severity": "CRITICAL",
                        "description": f"Package name '{pkg_name}' has an edit distance of {dist} from popular package '{legit_pkg}'. AI code generation frequently mispredicts token character sequences.",
                        "snippet": line_clean,
                        "recommendation": f"Replace with the genuine package: `{legit_pkg}{operator}{version}`."
                    })
                    break

        # 3. Check Known Outdated Vulnerable Dependencies (CWE-1395)
        if pkg_name in KNOWN_CVES:
            cve_list = KNOWN_CVES[pkg_name]
            for cve_info in cve_list:
                if version != "latest" and version_lte(version, cve_info["max_vulnerable"]):
                    vulnerabilities.append({
                        "id": f"VULNERABLE_DEP_{cve_info['cve'].replace('-', '_')}",
                        "category": "Dependency Risk",
                        "title": f"{cve_info['cve']} Vulnerability in '{pkg_name}=={version}'",
                        "line": line_no,
                        "cwe": "CWE-1395",
                        "severity": cve_info["severity"],
                        "description": f"{cve_info['desc']}. Maximum vulnerable version is {cve_info['max_vulnerable']}.",
                        "snippet": line_clean,
                        "recommendation": f"Upgrade to secure release: `{pkg_name}>={cve_info['fixed']}`."
                    })
                    break

    return vulnerabilities
