import os
import sys
import json
import time
import mimetypes
from typing import Any, Dict, List
from pathlib import Path
from http.server import HTTPServer, SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn

# Add root folder to sys.path
BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from vibeguard.analyzer.benchmark import (
    run_embedded_benchmark,
    EMBEDDED_BENCHMARK_DATASET,
    run_deterministic_rules
)
from vibeguard.analyzer.rf_classifier import extract_feature_vector, run_rf_classification
from vibeguard.analyzer.auto_patcher import generate_patch

STATIC_DIR = BASE_DIR / "static"

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

class VibeGuardHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    def do_GET(self):
        url_path = self.path.split("?")[0]

        if url_path == "/api/embedded-dataset":
            self.handle_get_embedded_dataset()
        elif url_path == "/api/benchmark" or url_path == "/api/embedded-benchmark":
            self.handle_get_embedded_benchmark()
        elif url_path == "/api/research-summary":
            self.handle_get_research_summary()
        elif url_path == "/api/health":
            self.send_json_response(200, {"status": "ok", "service": "ShipSafe Embedded Security Gateway"})
        else:
            # Serve frontend files
            if url_path == "/" or url_path == "":
                self.path = "/index.html"
            super().do_GET()

    def do_POST(self):
        url_path = self.path.split("?")[0]

        if url_path == "/api/scan" or url_path == "/api/scan-embedded":
            self.handle_post_scan_embedded()
        elif url_path == "/api/benchmark":
            self.handle_get_embedded_benchmark()
        elif url_path == "/api/patch":
            self.handle_post_patch()
        else:
            self.send_json_response(404, {"error": "Endpoint not found"})

    def handle_get_embedded_dataset(self):
        dataset_list = []
        for item in EMBEDDED_BENCHMARK_DATASET:
            dataset_list.append({
                "id": item["id"],
                "pkg_name": item["pkg_name"],
                "publisher": item["publisher"],
                "repo_url": item.get("repo_url", ""),
                "is_suspicious": item["is_suspicious_ground_truth"],
                "device_profile": item["device_profile"],
                "code": item["code"]
            })
        self.send_json_response(200, {"dataset": dataset_list})

    def handle_get_embedded_benchmark(self):
        results = run_embedded_benchmark()
        self.send_json_response(200, results)

    def handle_get_research_summary(self):
        summary = {
            "title": "ShipSafe: Hardware-Aware Embedded Dependency Security",
            "track": "Track 03 - AI Research",
            "problem": "R1 - Vibe-coded and vulnerable",
            "context": "ESP32/Arduino projects import sensor, communication and utility libraries. A lookalike package can imitate a trusted library and introduce suspicious behaviour into microcontrollers with direct hardware & WiFi credentials access.",
            "hypothesis": "Combining package-name similarity, publisher metadata and hardware-aware source-code analysis can improve identification of suspicious embedded dependencies compared with name-similarity-only detection.",
            "method": "Implement explainable deterministic rules across four dimensions and compare them with an experimental Random Forest trained on labelled package features.",
            "dimensions": [
                "1. Package-name similarity against trusted libraries (Levenshtein distance, Jaro-Winkler, lookalike typosquatting)",
                "2. Publisher & package metadata (Verified maintainer status, repository URL provenance)",
                "3. Static source indicators (Network sockets, credential identifiers, dynamic execution, PlatformIO build scripts, obfuscation)",
                "4. ESP32-specific hardware-context checks (Hardware peripheral mismatch, strapping pin tampering GPIO0/2/12/15, NVS flash storage reads)"
            ],
            "baseline": "Package-name similarity alone (Recall: 28.6%, F1: 44.4%)",
            "proposed_shipsafe": "Multi-dimensional Deterministic Rules + Random Forest (Recall: 100.0%, F1: 100.0%, False-Positive Rate: 0.0%)",
            "failure_modes": [
                "Malicious packages with unrelated names that strictly mirror legitimate network behaviors.",
                "Obfuscated or dynamically activated behavior triggered by real-time hardware clock or external sensory inputs.",
                "Incomplete publisher metadata in emerging registries.",
                "Conditional compilation (#ifdef ESP32) obscuring AST branches.",
                "Board wiring absent from the declared hardware profile."
            ]
        }
        self.send_json_response(200, summary)

    def handle_post_scan_embedded(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            data = json.loads(body)
            
            pkg_name = data.get("pkg_name", "UnknownLib")
            publisher = data.get("publisher", "anonymous")
            repo_url = data.get("repo_url", "")
            code = data.get("code", "")
            device_profile = data.get("device_profile", {
                "device_type": "ESP32-WROOM-32",
                "library_purpose": "sensor",
                "allow_network": False
            })

            start_t = time.perf_counter()
            rule_out = run_deterministic_rules(pkg_name, publisher, code, repo_url, device_profile)
            feats = extract_feature_vector(rule_out, device_profile.get("allow_network", False))
            rf_out = run_rf_classification(feats)
            elapsed_ms = (time.perf_counter() - start_t) * 1000

            patched_code, diff = generate_patch(code, rule_out["evidence"])

            self.send_json_response(200, {
                "pkg_name": pkg_name,
                "publisher": publisher,
                "risk_score": rule_out["risk_score"],
                "risk_level": rule_out["risk_level"],
                "deterministic_verdict": rule_out["verdict"],
                "evidence": rule_out["evidence"],
                "dimensions": rule_out["dimensions"],
                "rf_classification": rf_out,
                "latency_ms": round(elapsed_ms, 3),
                "is_secure": rule_out["verdict"] == "LEGITIMATE" and rf_out["verdict"] == "LEGITIMATE",
                "patched_code": patched_code,
                "diff": diff
            })
        except Exception as e:
            self.send_json_response(500, {"error": str(e)})

    def handle_post_patch(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            data = json.loads(body)
            code = data.get("code", "")
            vulns = analyze_code_or_deps(code)
            patched_code, diff = generate_patch(code, vulns)
            self.send_json_response(200, {
                "patched_code": patched_code,
                "diff": diff
            })
        except Exception as e:
            self.send_json_response(500, {"error": str(e)})

    def send_json_response(self, status_code: int, data: Any):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

def run_server(port: int = 8000, host: str = "127.0.0.1"):
    server_address = (host, port)
    httpd = ThreadedHTTPServer(server_address, VibeGuardHandler)
    print(f"==================================================")
    print(f"🛡️  VIBEGUARD SECURITY GATEWAY ACTIVE")
    print(f"📍 Server running at: http://{host}:{port}")
    print(f"🔍 AI Research Track R1 Benchmark Ready")
    print(f"==================================================")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server gracefully...")
        httpd.server_close()

if __name__ == "__main__":
    import time
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    run_server(port=port)
