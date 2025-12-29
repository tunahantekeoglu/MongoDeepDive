# 🌊 MongoDeepDive

> **Context-Aware MongoDB Wire Protocol Exploit (CVE-2025-14847)** > *Advanced Heuristics Analyzer for Red Team Operations*

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)
![Security](https://img.shields.io/badge/Focus-Offensive%20Security-red)

## 💀 Overview

**MongoDeepDive** is a high-performance, asynchronous vulnerability scanner and forensic analyzer designed to detect **uninitialized memory leaks** in MongoDB servers affected by **CVE-2025-14847**.

Unlike standard PoC scripts that merely check for response size, MongoDeepDive employs **Shannon Entropy** analysis and heuristic filtering to distinguish between empty memory padding (garbage) and high-value secrets (e.g., Private Keys, AWS Tokens, Passwords).

This tool is engineered for **Security Architects** and **Red Teamers** who need actionable intelligence, not just noise.

### 📺 Demo Output

```text
────────────────────────── MongoDeepDive - Tunahan Tekeoğlu ──────────────────────────
Scanning... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:02

[+] VULNERABLE: 192.168.1.15:27017 | Response Size: 65552 bytes
    └── SECRETS FOUND: 3 critical blocks extracted
       ➜ SECRET_EXPOSED (AWS_KEY)
       ➜ HIGH_ENTROPY (Key/Encrypted)
       ➜ SECRET_EXPOSED (DB_URI)

[+] VULNERABLE: 192.168.1.18:27017 | Response Size: 65552 bytes
    └── Leak confirmed, but memory content is currently empty/low-entropy.

Scan Complete. Report saved to mongo_audit.json

```

## 🚀 Key Features

* **🧠 Heuristic Intelligence:** Real-time entropy calculation to identify encrypted data or keys within leaked memory chunks.
* **⚡ High-Performance AsyncIO:** Scans hundreds of targets simultaneously with minimal resource footprint.
* **🛡️ Smart Filtering:** Automatically removes null bytes and filters out low-entropy "junk" data.
* **⚗️ Hybrid Analysis:** Reports both the raw leak size (Scanner Mode) and the analyzed content (Forensic Mode).
* **👻 Stealth Mode:** Includes a `--safe` flag for throttled, production-safe scanning.
* **JSON Export:** Structured output for easy integration with vulnerability management platforms.

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/tunahantekeoglu/MongoDeepDive.git

# Enter the directory
cd MongoDeepDive

# Install dependencies
pip install -r requirements.txt

```

*(Note: Requires `rich` library for CLI visualization)*

## 🛠️ Usage

### 1. Mass Scanning (List Mode)

Scan a list of targets with high concurrency and generate a JSON report:

```bash
python3 mongo_deep_dive.py -l targets.txt -o report.json -c 50

```

### 2. Deep Extraction (Single Target)

Aggressively siphon memory from a confirmed target to hunt for secrets (e.g., sending 1000 packets):

```bash
python3 mongo_deep_dive.py -t 192.168.1.10 -n 1000

```

### 3. Production / Stealth Mode

Enable throttling to avoid network saturation or service instability on legacy systems:

```bash
python3 mongo_deep_dive.py -l targets.txt --safe

```

## 🧠 How It Works

1. **Payload Injection:** Sends a malformed `OP_COMPRESSED` packet with a spoofed uncompressed size.
2. **Memory Leak:** The vulnerable server allocates memory based on the spoofed size but fails to initialize it, returning raw heap data.
3. **Entropy Analysis:** The tool calculates the Shannon Entropy of the returned bytes.
* **Entropy > 4.5:** Likely Encrypted Data, Keys, or Compressed Strings.
* **Entropy < 3.0:** Likely Padding, Logs, or Null Bytes.


4. **Pattern Matching:** Regex filters are applied to identify specific patterns like `AKIA...` (AWS Keys) or `eyJ...` (JWTs).

## ⚠️ Disclaimer

**For Educational and Authorized Testing Purposes Only.**

This tool is intended for security research, authorized Red Team engagements, and vulnerability assessment. The author takes no responsibility for the misuse of this code. Accessing computer systems without permission is illegal.

---

**Author:** Tunahan Tekeoğlu


## Get in touch with me! 🚀

[![Instagram](https://img.shields.io/badge/-tunahantekeoglu-E4405F?style=for-the-badge&logo=Instagram&logoColor=white)](https://www.instagram.com/tunahantekeoglu)<br>
[![Twitter](https://img.shields.io/badge/-tunahantekeoglu-1DA1F2?style=for-the-badge&logo=Twitter&logoColor=white)](https://twitter.com/tunahantekeoglu)<br>
[![LinkedIn](https://img.shields.io/badge/-tunahantekeoglu-0A66C2?style=for-the-badge&logo=LinkedIn&logoColor=white)](https://www.linkedin.com/in/tunahantekeoglu/?originalSubdomain=tr)<br>

### Or You Can Send Me an Email 📩

[![Email](https://img.shields.io/badge/tunahantekeoglu%40gmail.com-D14836?style=for-the-badge&logo=Gmail&logoColor=white)](mailto:tunahantekeoglu@gmail.com)

## To Read My Articles About Cyber Security

[![Medium](https://img.shields.io/badge/-tun4hunt-000000?style=for-the-badge&logo=Medium&logoColor=white)](https://medium.com/@tun4hunt)

</div>

---

