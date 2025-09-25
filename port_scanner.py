# port_scanner_safe.py
"""
Ethical-by-default port scanner:
- Only scans loopback (localhost) and private IP ranges by default.
- Requires explicit consent.txt file to operate.
- Supports a one-click "dry-run" mode for safe demonstrations.
"""

import socket
import time
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import sys
import logging

ALLOWED_FILE = "allowed_targets.txt"
CONSENT_FILE = "consent.txt"
LOG_FILE = "scan_log.log"

# Set up logging to a file
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# ---------- Utility checks ----------
def is_private_or_loopback(ip_str):
    """Return True if ip is loopback or private (RFC1918) - safe to scan locally."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback
    except Exception:
        return False

def check_consent():
    """Check for explicit consent from the user."""
    if not os.path.exists(CONSENT_FILE):
        return False
    with open(CONSENT_FILE, "r", encoding="utf-8") as f:
        content = f.read().strip().lower()
        if "i consent to use this tool on my own network" in content:
            return True
    return False

def read_allowed_targets():
    """Read allowed targets from ALLOWED_FILE. Each line may be domain or IP."""
    allowed = set()
    if not os.path.exists(ALLOWED_FILE):
        return allowed
    with open(ALLOWED_FILE, "r", encoding="utf-8") as f:
        for line in f:
            t = line.strip()
            if t and not t.startswith("#"):
                allowed.add(t.lower())
    return allowed

def resolve_target(target):
    """Return resolved IP or raise exception."""
    return socket.gethostbyname(target)

# ---------- Port scan (keeps it simple & safe) ----------
def scan_port(target_ip, port, timeout=0.6):
    """Return port if open, else None. Short timeout to avoid long waits."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((target_ip, port))
            if result == 0:
                return port
    except Exception:
        return None
    return None

# ---------- Main program ----------
def main():
    print("⚠️  Ethical scanner — only scan devices you own or have permission to test.")
    
    # Check for consent file
    if not check_consent():
        print("\n🔒 Scan blocked: No consent found.")
        print("To proceed, you must create a file named 'consent.txt' in this directory")
        print("with the exact phrase 'I consent to use this tool on my own network'.")
        return

    is_dry_run = "--dry-run" in sys.argv
    if is_dry_run:
        print("✅ Dry-run mode enabled. No ports will be scanned.")
    else:
        print("By default this tool will only scan localhost or private network IPs.")
        print("To scan any other public domain/IP, add it to 'allowed_targets.txt'.\n")
        
    target = input("Enter host to scan (domain or IP, e.g. example.com or 127.0.0.1): ").strip()
    if not target:
        print("No target provided. Exiting.")
        return

    # Try resolve early
    try:
        target_ip = resolve_target(target)
    except Exception:
        print("Could not resolve the target. Check the name/IP and try again.")
        return

    # Load allowed list
    allowed_set = read_allowed_targets()
    target_lower = target.lower()

    # If IP itself is private or loopback -> allowed
    if is_private_or_loopback(target_ip):
        allowed = True
    # If user added this exact domain/IP to allowed_targets.txt -> allowed
    elif target_lower in allowed_set or target_ip in allowed_set:
        allowed = True
    else:
        allowed = False

    if not allowed:
        print("\n🔒 Scan blocked: target is NOT in the safe list.")
        print("If you own this target and want to scan it, add the domain or IP to the")
        print("file 'allowed_targets.txt' in this repository.")
        print("After adding the target to allowed_targets.txt, re-run this script.")
        logging.info(f"BLOCKED: Attempt to scan unapproved target '{target}' ({target_ip})")
        return

    print(f"Resolved {target} -> {target_ip}")
    logging.info(f"SCAN START: Target '{target}' ({target_ip})")

    # Defaults & safe limits
    try:
        start_port = int(input("Start port (default 1): ") or "1")
        end_port   = int(input("End port (default 1024): ") or "1024")
    except ValueError:
        print("Invalid ports entered. Using defaults 1-1024.")
        start_port, end_port = 1, 1024

    # sanitize port range
    if start_port < 1: start_port = 1
    if end_port > 65535: end_port = 65535
    if end_port < start_port:
        print("End port < start port. Using defaults 1-1024.")
        start_port, end_port = 1, 1024

    # Safety caps
    max_range_span = 5000
    if (end_port - start_port) > max_range_span:
        print(f"Port range too large. Limiting to {max_range_span} ports from the start.")
        end_port = start_port + max_range_span

    # Concurrency
    max_workers = 30
    print(f"Scanning ports {start_port} to {end_port} on {target_ip} using up to {max_workers} threads...\n")

    # --- Dry-run check ---
    if is_dry_run:
        print("\n--- Dry-Run Complete ---")
        print(f"The following scan would be performed:")
        print(f"Target: {target_ip}")
        print(f"Port Range: {start_port} to {end_port}")
        print(f"Concurrency: {max_workers} threads")
        print("No network connections were made.")
        logging.info(f"DRY-RUN: Target '{target_ip}', Ports {start_port}-{end_port}")
        return

    # --- Actual Scan ---
    start_time = time.time()
    open_ports = []
    ports = range(start_port, end_port + 1)
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, target_ip, p): p for p in ports}
        for future in as_completed(futures):
            port_found = future.result()
            if port_found:
                print(f"[OPEN]  Port {port_found}")
                open_ports.append(port_found)

    duration = time.time() - start_time
    print("\nScan finished.")
    if open_ports:
        print("Open ports:", sorted(open_ports))
        logging.info(f"SCAN COMPLETE: Found open ports: {sorted(open_ports)}")
    else:
        print("No open ports found in the scanned range.")
        logging.info("SCAN COMPLETE: No open ports found.")
        
    print(f"Time taken: {duration:.2f} seconds")

if __name__ == "__main__":
    main()
