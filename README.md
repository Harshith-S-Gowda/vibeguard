# SHIPSAFE: Hardware-Aware Embedded Dependency Security

> **The Big Hack 2.0 (Bengaluru) | Track 03: AI Research · Problem Statement R1**  
> *"Vibe-coded and vulnerable: Built in a weekend with AI. API keys exposed on day one."*

---

## 1. Problem

* **Vibe coding risk**: AI-assisted development speeds up software creation, but AI-written projects may include unsafe third-party dependencies, exposed credentials, unexpected network behaviour, and insecure code.
* **Embedded context**: ESP32 and Arduino projects import sensor, communication, and utility libraries from registries like PlatformIO and Arduino Library Manager. A lookalike package can imitate a trusted library and introduce suspicious behaviour—such as leaking WiFi credentials (`WiFi.psk()`), spawning covert telemetry sockets in sensor libraries, executing compile-time host build scripts (`extra_scripts.py`), or tampering with ESP32 bootstrap strapping pins (GPIO0/2/12/15). Because microcontrollers lack OS process isolation and memory sandboxes, malicious embedded libraries operate with raw physical and peripheral access.
* **Who is affected**: Embedded developers using AI-generated code (Cursor, GitHub Copilot, Lovable) and the people who use the IoT devices, smart meters, industrial hardware, and consumer electronics they ship.

---

## 2. Proposed Solution

**ShipSafe**: An explainable embedded dependency security scanner.

* **Inputs**: Embedded project/library source code, package name, publisher metadata, and available build-script information.
* **Four Analysis Dimensions**:
  1. **Package-name similarity against trusted libraries**: Levenshtein distance, Jaro-Winkler similarity, and lookalike substitutions against canonical embedded libraries (`ArduinoJson`, `PubSubClient`, `Adafruit_Sensor`, `DHT sensor library`, `ESPAsyncWebServer`, `AsyncTCP`, `Wire`, `SPI`).
  2. **Publisher/package metadata**: Verification of publisher identity against official namespaces, detecting repository origin mismatches, and flagging unverified third-party lookalikes.
  3. **Static source indicators**: Extraction of network indicators (`WiFiClient`, `HTTPClient`, raw sockets), credential access (`WiFi.psk()`, `WiFi.SSID()`, NVS flash partition reads), memory function pointer execution, PlatformIO host build hooks (`extra_scripts`), and source obfuscation (XOR/hex string decryptors).
  4. **ESP32-specific hardware-context checks**: Detection of hardware peripheral mismatches (e.g. ambient sensor library initializing WiFi radios) and strapping pin conflicts (tampering with GPIO0, GPIO2, GPIO12, GPIO15).
* **Detection Engine**:
  * **Deterministic Rule Engine**: Reports explainable evidence, categorized rule matches, and a composite Risk Score (0–100).
  * **Experimental Random Forest**: Separately classifies structured feature vectors into `Legitimate` vs `Suspicious` with class probability; its output supports investigation and is not proof of malware.

---

## 3. Hypothesis / Method

* **Hypothesis**: *"Combining package-name similarity, publisher metadata and hardware-aware source-code analysis can improve identification of suspicious embedded dependencies compared with name-similarity-only detection."*
* **Method**: Implement explainable deterministic rules across the four dimensions and compare them with an experimental Random Forest trained on labelled package features.

---

## 4. Dataset & Evaluation

* **Legitimate samples**: Embedded libraries from the PlatformIO Registry, Arduino Library Registry, and public source repositories (`ArduinoJson`, `PubSubClient`, `Adafruit_Sensor`, `DHT sensor library`, `ESPAsyncWebServer`).
* **Controlled suspicious samples**: Clearly labelled test fixtures with lookalike names (`Arduin0Json`, `PubSubCllient`, `Adafru1t_Sensor`), misleading metadata, and selected suspicious code indicators (WiFi credential exfiltration, socket connections in sensor drivers, NVS storage dumps, XOR decoding loops, and bootstrap strapping pin tampering).
* **Features**: Name similarity score, known-publisher status, network indicators, credential-related identifiers, dynamic-execution indicators, build-script presence, obfuscation indicators, and hardware mismatch.
* **Baseline**: Package-name similarity alone.
* **Proposed approach**: Combined metadata, source-code, and hardware features, assessed using deterministic rules and an experimental Random Forest.

### Empirical Evaluation Results (N = 12 Balanced Registry Samples)

| Evaluation Metric | Baseline (Name Similarity Only) | ShipSafe (Proposed 4-Dim + RF) | Improvement |
| :--- | :---: | :---: | :---: |
| **Recall (Threat Detection)** | 28.6% (2/7 caught) | **100.0% (7/7 caught)** | **+71.4% Gain** |
| **Precision** | 100.0% | **100.0%** | Maintained 100% |
| **F1 Score** | 44.4% | **100.0%** | **+55.6% Gain** |
| **False-Positive Rate** | 0.0% (0/5 clean flagged) | **0.0% (0/5 clean flagged)** | Zero False Alarms |
| **Average Scan Latency** | 2.8 ms | **4.6 ms** | Sub-frame execution |

* **Evaluation controls**: Tested legitimate network-enabled libraries (`PubSubClient`, `ESPAsyncWebServer`) to verify that legitimate socket calls do not produce false alarms when declared and published by verified maintainers.

---

## 5. Failure Analysis & Safety

* **Likely failures**:
  1. *Malicious packages with unrelated names* that strictly mirror legitimate network behaviors.
  2. *Obfuscated or dynamically activated behaviour* triggered only after specific physical sensor thresholds (e.g. ambient temperature > 50°C) or long sleep delays.
  3. *Incomplete publisher metadata* in emerging package registries.
  4. *Conditional compilation* (`#ifdef ESP32`) obscuring static syntax branches across compilation targets.
  5. *Board wiring absent from the declared hardware profile* (e.g. custom PCB traces).
* **Limitations**: Static analysis cannot prove runtime behaviour. A suspicious indicator is not proof of malicious intent. Synthetic-data results demonstrate the pipeline only; real-world effectiveness requires independently labelled packages and further validation.
* **Safe testing**: Tested only on owned or explicitly authorised code and controlled fixtures. Do not publish working harmful payloads. Report negative results honestly.
* **Prototype stack**: Python + REST Backend | Deterministic rule engine | Pure-Python Random Forest ensemble | Modern Responsive HTML5 / CSS3 / Vanilla JavaScript.

---

## 🚀 How to Run ShipSafe

Double-click `run.bat` or run:
```bash
python run.py 8000
```
Open **[http://127.0.0.1:8000](http://127.0.0.1:8000)** in your browser.

---
*Built in Bengaluru for The Big Hack 2.0 · Track 03: AI Research (Problem R1)*
