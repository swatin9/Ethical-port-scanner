"""
port_scanner_safe.py
Ethical-by-default port scanner:
- Only scans loopback (localhost) and private IP ranges by default.
- To scan any public IP or domain, you must add that target explicitly
  to allowed_targets.txt in the repo (this prevents accidental/malicious use).
- Keeps defaults conservative: limited concurrency and short range by default.
- Prints a clear ethical warning and refuses otherwise.
"""

import socket
import time
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import os

ALLOWED_FILE = "allowed_targets.txt"  # list of extra targets the repo owner added

# ---------- Utility checks ----------
def is_private_or_loopback(ip_str):
    """Return True if ip is loopback or private (RFC1918) - safe to scan locally."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback
    except Exception:
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

# ---------- Demo scan ----------
def demo_scan():
    print("\n🎬 Running demo scan on localhost (127.0.0.1)...")
    target_ip = "127.0.0.1"
    start_port, end_port = 20, 1024  # safe demo range
    open_ports = []

    print(f"Scanning ports {start_port}-{end_port} on {target_ip}...\n")
    start_time = time.time()

    ports = range(start_port, end_port + 1)
    for port in ports:
        if scan_port(target_ip, port):
            print(f"\033[92m[OPEN]   Port {port}\033[0m")  # green for open
            open_ports.append(port)
        else:
            print(f"\033[90m[CLOSED] Port {port}\033[0m", end="\r")  # gray for closed (overwrite line)

    duration = time.time() - start_time
    print("\n\nDemo scan finished.")
    if open_ports:
        print("Open ports found:", open_ports)
    else:
        print("No open ports found.")
    print(f"Time taken: {duration:.2f} seconds\n")

# ---------- Main program ----------
def main():
    print("⚠️  Ethical scanner — only scan devices you own or have permission to test.")
    print("By default this tool will only scan localhost or private network IPs.")
    print("To scan any other public domain/IP, add it to 'allowed_targets.txt' in this repo.\n")

    # Mode choice
    print("Choose mode:")
    print("[1] Manual scan (your own IP or allowed targets)")
    print("[2] Demo scan (safe localhost scan to see output)")

    mode = input("Enter 1 or 2: ").strip()
    if mode == "2":
        demo_scan()
        return

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
        print("file 'allowed_targets.txt' in this repository (one entry per line).")
        print("Example content for allowed_targets.txt:")
        print("  # explicit allow list for this scanner")
        print("  myserver.example.com")
        print("  203.0.113.42\n")
        print("After adding the target to allowed_targets.txt, re-run this script.")
        return

    # Defaults & safe limits
    print(f"Resolved {target} -> {target_ip}")
    print("NOTE: Because this tool is ethical-by-default, defaults are conservative.")
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

    # Safety caps:
    max_range_span = 5000   # don't let user try to scan tens of thousands by accident
    if (end_port - start_port) > max_range_span:
        print(f"Port range too large. Limiting to {max_range_span} ports from the start.")
        end_port = start_port + max_range_span

    # Concurrency: lower by default for phones
    max_workers = 30
    print(f"Scanning ports {start_port} to {end_port} on {target_ip} using up to {max_workers} threads...\n")

    start_time = time.time()
    open_ports = []

    ports = range(start_port, end_port + 1)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, target_ip, p): p for p in ports}
        for future in as_completed(futures):
            port_found = future.result()
            if port_found:
                print(f"\033[92m[OPEN]  Port {port_found}\033[0m")  # green for open
                open_ports.append(port_found)

    duration = time.time() - start_time
    print("\nScan finished.")
    if open_ports:
        print("Open ports:", sorted(open_ports))
    else:
        print("No open ports found in the scanned range.")
    print(f"Time taken: {duration:.2f} seconds")

if __name__ == "__main__":
    main()
