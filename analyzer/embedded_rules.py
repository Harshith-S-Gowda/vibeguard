"""
ShipSafe - Hardware-Aware Embedded Dependency Security
Module: embedded_rules.py
Implements the 4 Analysis Dimensions:
  1. Package-Name Similarity Against Trusted Libraries
  2. Publisher & Package Metadata
  3. Static Source Indicators
  4. ESP32-Specific Hardware-Context Checks
"""

import re
from typing import Dict, Any, List, Tuple

# Canonical trusted embedded libraries (PlatformIO & Arduino registries)
TRUSTED_LIBRARIES = {
    "arduinojson": {
        "canonical_name": "ArduinoJson",
        "aliases": ["arduinojson"],
        "verified_publishers": ["bblanchon", "benoit blanchon"],
        "purpose": "json_parser",
        "legitimate_network": False,
        "expected_peripherals": ["none"]
    },
    "pubsubclient": {
        "canonical_name": "PubSubClient",
        "aliases": ["pubsubclient"],
        "verified_publishers": ["knolleary", "nick o'leary"],
        "purpose": "mqtt_client",
        "legitimate_network": True,
        "expected_peripherals": ["wifi", "ethernet"]
    },
    "adafruit_sensor": {
        "canonical_name": "Adafruit_Sensor",
        "aliases": ["adafruitsensor", "adafruitunifiedsensor"],
        "verified_publishers": ["adafruit"],
        "purpose": "sensor_abstraction",
        "legitimate_network": False,
        "expected_peripherals": ["i2c", "spi", "analog"]
    },
    "dht_sensor_library": {
        "canonical_name": "DHT sensor library",
        "aliases": ["dhtsensorlibrary", "dht"],
        "verified_publishers": ["adafruit"],
        "purpose": "dht_sensor",
        "legitimate_network": False,
        "expected_peripherals": ["gpio"]
    },
    "espasyncwebserver": {
        "canonical_name": "ESPAsyncWebServer",
        "aliases": ["espasyncwebserver"],
        "verified_publishers": ["me-no-dev", "lacamera"],
        "purpose": "web_server",
        "legitimate_network": True,
        "expected_peripherals": ["wifi"]
    },
    "asynctcp": {
        "canonical_name": "AsyncTCP",
        "aliases": ["asynctcp"],
        "verified_publishers": ["me-no-dev"],
        "purpose": "async_tcp",
        "legitimate_network": True,
        "expected_peripherals": ["wifi"]
    },
    "wire": {
        "canonical_name": "Wire",
        "aliases": ["wire"],
        "verified_publishers": ["arduino", "espressif"],
        "purpose": "i2c_bus",
        "legitimate_network": False,
        "expected_peripherals": ["i2c"]
    },
    "spi": {
        "canonical_name": "SPI",
        "aliases": ["spi"],
        "verified_publishers": ["arduino", "espressif"],
        "purpose": "spi_bus",
        "legitimate_network": False,
        "expected_peripherals": ["spi"]
    }
}

# ESP32 Strapping / Boot pins that must not be disrupted
ESP32_STRAPPING_PINS = {"0", "2", "12", "15"}

def levenshtein(s1: str, s2: str) -> int:
    s1 = s1.lower()
    s2 = s2.lower()
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            ins = prev[j + 1] + 1
            dels = curr[j] + 1
            subs = prev[j] + (c1 != c2)
            curr.append(min(ins, dels, subs))
        prev = curr
    return prev[-1]

def normalize_name(name: str) -> str:
    return re.sub(r'[^a-z0-9]', '', name.lower())

def analyze_package_name_similarity(pkg_name: str) -> Dict[str, Any]:
    """
    Dimension 1: Package-name similarity against trusted libraries
    """
    norm = normalize_name(pkg_name)
    best_canonical = None
    min_dist = 999
    is_exact = False

    for key, data in TRUSTED_LIBRARIES.items():
        candidates = [normalize_name(data["canonical_name"])] + data.get("aliases", [])
        for cand in candidates:
            dist = levenshtein(norm, cand)

            # Lookalike substitutions (0 -> o, 1 -> l, etc.)
            sub = (
                norm.replace("0", "o")
                    .replace("1", "l")
                    .replace("1", "i")
                    .replace("v", "u")
            )
            dist = min(dist, levenshtein(sub, cand))

            if dist < min_dist:
                min_dist = dist
                best_canonical = data["canonical_name"]
                if norm == cand:
                    is_exact = True

    is_lookalike = (min_dist in (1, 2) and not is_exact)

    similarity_score = max(0.0, 1.0 - (min_dist / max(len(norm), 1)))

    evidence = []
    if is_lookalike:
        evidence.append({
            "dimension": "1. Name Similarity",
            "rule": "TYPOSQUATTING_LOOKALIKE_DETECTED",
            "severity": "HIGH",
            "message": f"Package '{pkg_name}' has an edit distance of {min_dist} from trusted library '{best_canonical}'. Potential typosquatting lookalike."
        })

    return {
        "best_match": best_canonical,
        "edit_distance": min_dist,
        "is_exact_match": is_exact,
        "is_lookalike": is_lookalike,
        "similarity_score": round(similarity_score, 3),
        "evidence": evidence
    }

def analyze_metadata(pkg_name: str, publisher: str, repo_url: str = "") -> Dict[str, Any]:
    """
    Dimension 2: Publisher & package metadata checks
    """
    evidence = []
    pub_lower = publisher.lower().strip()
    norm = normalize_name(pkg_name)
    
    is_known_publisher = False
    publisher_mismatch = False

    for key, data in TRUSTED_LIBRARIES.items():
        if normalize_name(data["canonical_name"]) == norm or levenshtein(norm, normalize_name(data["canonical_name"])) <= 2:
            verified = [p.lower() for p in data["verified_publishers"]]
            if any(v in pub_lower for v in verified):
                is_known_publisher = True
            else:
                publisher_mismatch = True
                evidence.append({
                    "dimension": "2. Publisher Metadata",
                    "rule": "UNVERIFIED_PUBLISHER_LOOKALIKE",
                    "severity": "HIGH",
                    "message": f"Publisher '{publisher}' does not match official maintainer(s) {data['verified_publishers']} for '{data['canonical_name']}'."
                })
            break

    if "github.com" in repo_url.lower() and publisher_mismatch:
        evidence.append({
            "dimension": "2. Publisher Metadata",
            "rule": "REPOSITORY_ORIGIN_SUSPICIOUS",
            "severity": "MEDIUM",
            "message": f"Repository URL '{repo_url}' points to an unverified third-party fork or newly registered namespace."
        })

    return {
        "is_known_publisher": is_known_publisher,
        "publisher_mismatch": publisher_mismatch,
        "evidence": evidence
    }

def analyze_static_source(code: str) -> Dict[str, Any]:
    """
    Dimension 3: Static source indicators (Network, Credential, Dynamic Execution, Obfuscation)
    """
    evidence = []
    indicators = {
        "network_calls": 0,
        "credential_access": 0,
        "dynamic_execution": 0,
        "build_scripts": 0,
        "obfuscation": 0
    }

    # 1. Network indicators (WiFi, sockets, HTTP)
    net_patterns = [
        (r'\b(WiFiClient|HTTPClient|WiFiClientSecure)\b', "Direct WiFi/HTTP client instantiation"),
        (r'\b(WiFi\.begin|client\.connect|socket\(|connect\()\b', "Socket or connection establishment"),
        (r'\bhttps?://[0-9a-zA-Z\.\-]+(?::\d+)?(?:/[^\s"\']*)?', "Hard-coded outbound HTTP/HTTPS URL endpoint")
    ]
    for pat, desc in net_patterns:
        matches = re.findall(pat, code)
        if matches:
            indicators["network_calls"] += len(matches)
            evidence.append({
                "dimension": "3. Static Source Indicators",
                "rule": "SUSPICIOUS_NETWORK_INDICATOR",
                "severity": "MEDIUM",
                "message": f"{desc} detected ({len(matches)} instance(s))."
            })

    # 2. Credential-related identifiers (WiFi PSK, SSID, NVS flash tokens)
    cred_patterns = [
        (r'\bWiFi\.(psk|SSID|BSSID)\(\)', "Direct extraction of stored WiFi credentials"),
        (r'\b(esp_wifi_get_config|nvs_get_str|nvs_open)\b', "Reading sensitive device NVS partition or WiFi configuration"),
        (r'(?:password|secret|apikey|token)\s*=\s*["\'][^"\']+["\']', "Potential hard-coded token or credential extraction buffer")
    ]
    for pat, desc in cred_patterns:
        matches = re.findall(pat, code, re.IGNORECASE)
        if matches:
            indicators["credential_access"] += len(matches)
            evidence.append({
                "dimension": "3. Static Source Indicators",
                "rule": "CREDENTIAL_IDENTIFIER_ACCESSED",
                "severity": "CRITICAL",
                "message": f"{desc} found in library source."
            })

    # 3. Dynamic execution indicators
    dyn_patterns = [
        (r'\(\s*\*\s*\((?:void|char|int)\s*\*\s*\)\s*\)\s*\(', "Function pointer casting from raw memory address"),
        (r'\b(esp_restart|system_restart|abort)\b', "Forced device reboot / crash trigger"),
        (r'\b(memcpy|memset)\s*\(\s*(?:0x|&)?(?:400|3ff)', "Direct write into ESP32 SRAM / IRAM instruction space")
    ]
    for pat, desc in dyn_patterns:
        matches = re.findall(pat, code)
        if matches:
            indicators["dynamic_execution"] += len(matches)
            evidence.append({
                "dimension": "3. Static Source Indicators",
                "rule": "DYNAMIC_EXECUTION_MEMORY_HOOK",
                "severity": "HIGH",
                "message": f"{desc} detected."
            })

    # 4. Build-script presence (PlatformIO extra_scripts)
    if "extra_scripts" in code or "pre:" in code or "post:" in code:
        indicators["build_scripts"] += 1
        evidence.append({
            "dimension": "3. Static Source Indicators",
            "rule": "PLATFORMIO_BUILD_SCRIPT_EXECUTION",
            "severity": "HIGH",
            "message": "PlatformIO `extra_scripts` build hook detected. Executes arbitrary Python on developer's host machine during compilation."
        })

    # 5. Obfuscation indicators (XOR decoding loops, hex sequences)
    hex_runs = re.findall(r'\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){4,}', code)
    xor_loops = re.findall(r'\^\s*0x[0-9a-fA-F]{2}', code)
    if hex_runs or xor_loops:
        indicators["obfuscation"] += len(hex_runs) + len(xor_loops)
        evidence.append({
            "dimension": "3. Static Source Indicators",
            "rule": "SOURCE_OBFUSCATION_INDICATOR",
            "severity": "HIGH",
            "message": "Hex-encoded payload or XOR string decrypter loop detected in source code."
        })

    return {
        "indicators": indicators,
        "evidence": evidence
    }

def analyze_hardware_context(code: str, declared_device_profile: Dict[str, Any]) -> Dict[str, Any]:
    """
    Dimension 4: ESP32-Specific Hardware-Context Checks
    Detects hardware mismatches: e.g., ambient sensor using WiFi, or tampering with strapping pins
    """
    evidence = []
    hardware_mismatch = False
    pin_conflict = False

    device_type = declared_device_profile.get("device_type", "ESP32-WROOM-32")
    library_purpose = declared_device_profile.get("library_purpose", "sensor")
    is_network_permitted = declared_device_profile.get("allow_network", False)

    # Check 1: Hardware peripheral mismatch
    # If the declared purpose is a local sensor (e.g. DHT, BMP280, OLED) but it invokes WiFi / Sockets
    has_wifi_calls = bool(re.search(r'\b(WiFi|HTTPClient|WiFiClient|socket)\b', code))
    if not is_network_permitted and has_wifi_calls:
        hardware_mismatch = True
        evidence.append({
            "dimension": "4. ESP32 Hardware Context",
            "rule": "HARDWARE_PERIPHERAL_MISMATCH",
            "severity": "CRITICAL",
            "message": f"Library claimed purpose '{library_purpose}' does not declare network capability, but initializes WiFi / socket hardware on {device_type}."
        })

    # Check 2: Strapping pin conflict
    # Check if code configures GPIO0, GPIO2, GPIO12, GPIO15 as outputs or pulls them low
    pin_matches = re.findall(r'pinMode\s*\(\s*([0-9]+)\s*,', code)
    for p in pin_matches:
        if p in ESP32_STRAPPING_PINS:
            pin_conflict = True
            evidence.append({
                "dimension": "4. ESP32 Hardware Context",
                "rule": "STRAPPING_PIN_TAMPERING",
                "severity": "HIGH",
                "message": f"Library manipulates critical ESP32 strapping pin GPIO{p}. May prevent device flashing or force bootloader loop."
            })

    # Check 3: Flash partition / NVS tampering
    if re.search(r'\b(nvs_flash_erase|esp_partition_read|spi_flash_erase_range)\b', code):
        evidence.append({
            "dimension": "4. ESP32 Hardware Context",
            "rule": "FLASH_PARTITION_MANIPULATION",
            "severity": "CRITICAL",
            "message": "Raw flash sector erasure or direct partition read detected outside standard EEPROM API."
        })
        hardware_mismatch = True

    return {
        "hardware_mismatch": hardware_mismatch,
        "pin_conflict": pin_conflict,
        "evidence": evidence
    }

def run_deterministic_rules(
    pkg_name: str,
    publisher: str,
    code: str,
    repo_url: str = "",
    device_profile: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    Combines all four dimensions into an explainable audit and composite Risk Score (0-100).
    """
    if device_profile is None:
        device_profile = {
            "device_type": "ESP32-WROOM-32",
            "library_purpose": "sensor",
            "allow_network": False
        }

    dim1 = analyze_package_name_similarity(pkg_name)
    dim2 = analyze_metadata(pkg_name, publisher, repo_url)
    dim3 = analyze_static_source(code)
    dim4 = analyze_hardware_context(code, device_profile)

    all_evidence = []
    all_evidence.extend(dim1["evidence"])
    all_evidence.extend(dim2["evidence"])
    all_evidence.extend(dim3["evidence"])
    all_evidence.extend(dim4["evidence"])

    # Calculate deterministic Risk Score
    score = 0
    for ev in all_evidence:
        if ev["severity"] == "CRITICAL":
            score += 35
        elif ev["severity"] == "HIGH":
            score += 20
        elif ev["severity"] == "MEDIUM":
            score += 10
        elif ev["severity"] == "LOW":
            score += 5

    # Safe allowance: If library is a legitimate library with verified publisher and declared network,
    # suppress raw socket alerts
    if dim2["is_known_publisher"] and not dim1["is_lookalike"] and not dim4["hardware_mismatch"]:
        score = 0
        all_evidence = [e for e in all_evidence if e["rule"] != "SUSPICIOUS_NETWORK_INDICATOR"]

    score = min(100, score)

    has_high_or_crit = any(ev["severity"] in ("CRITICAL", "HIGH") for ev in all_evidence)

    if score >= 60:
        risk_level = "CRITICAL"
        verdict = "SUSPICIOUS"
    elif score >= 20 or has_high_or_crit:
        risk_level = "HIGH"
        verdict = "SUSPICIOUS"
    elif score >= 10:
        risk_level = "MEDIUM"
        verdict = "INVESTIGATE"
    else:
        risk_level = "LOW"
        verdict = "LEGITIMATE"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "verdict": verdict,
        "evidence": all_evidence,
        "dimensions": {
            "name_similarity": dim1,
            "publisher_metadata": dim2,
            "static_source": dim3,
            "hardware_context": dim4
        }
    }
