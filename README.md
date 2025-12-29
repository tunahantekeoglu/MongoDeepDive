# 🌊 MongoDeepDive

> **Context-Aware MongoDB Wire Protocol Exploit (CVE-2025-14847)** > *Advanced Heuristics Analyzer for Red Team Operations*

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)
![Security](https://img.shields.io/badge/Focus-Offensive%20Security-red)

## 💀 Overview

**MongoDeepDive** is a high-performance, asynchronous vulnerability scanner and forensic analyzer designed to detect **uninitialized memory leaks** in MongoDB servers affected by **CVE-2025-14847**.

Unlike standard PoC scripts that merely check for response size, MongoDeepDive employs **Shannon Entropy** analysis and heuristic filtering to distinguish between empty memory padding (garbage) and high-value secrets (e.g., Private Keys, AWS Tokens, Passwords).

This tool is engineered for **Security Architects** and **Red Teamers** who need actionable intelligence, not just noise.

## 🚀 Key Features

- **🧠 Heuristic Intelligence:** Real-time entropy calculation to identify encrypted data or keys within leaked memory chunks.
- **⚡ High-Performance AsyncIO:** Scans hundreds of targets simultaneously with minimal resource footprint.
- **🛡️ Smart Filtering:** Automatically removes null bytes and filters out low-entropy "junk" data.
- **⚗️ Hybrid Analysis:** Reports both the raw leak size (Scanner Mode) and the analyzed content (Forensic Mode).
- **👻 Stealth Mode:** Includes a `--safe` flag for throttled, production-safe scanning.
- **JSON Export:** Structured output for easy integration with vulnerability management platforms.

## 📦 Installation

```bash
# Clone the repository
git clone [https://github.com/YOUR_USERNAME/MongoDeepDive.git](https://github.com/YOUR_USERNAME/MongoDeepDive.git)

# Enter the directory
cd MongoDeepDive

# Install dependencies
pip install -r requirements.txt
