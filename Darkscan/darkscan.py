#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DarkScan v2.0 - Secure Nmap Wrapper for Penetration Testing
By: 1ucif3r - dark4rmy.in
Security fixes: Input validation, subprocess usage (no shell injection)
"""

import sys
import os
import time
import signal
import subprocess
import re
from dataclasses import dataclass
from typing import Optional, List
from enum import Enum

# ==================== CONFIGURATION ====================
DEFAULT_TOP_PORTS = "50"
VERSION = "2.0"

# ==================== COLORS ====================
class Colors:
    RED = '\033[1;91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

# ==================== SECURITY FUNCTIONS ====================
def validate_target(target: str) -> bool:
    """Validate target is a valid IP, domain, or CIDR (anti-injection)"""
    patterns = [
        r'^(\d{1,3}\.){3}\d{1,3}$',  # IPv4
        r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$',  # IPv6
        r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$',  # Domain
        r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$',  # CIDR
    ]
    return any(re.match(p, target) for p in patterns)

def validate_port(port_str: str) -> bool:
    """Validate port number"""
    if not port_str:
        return True
    try:
        port = int(port_str)
        return 1 <= port <= 65535
    except ValueError:
        return False

def validate_number(num_str: str, min_val: int = 1, max_val: int = 100000) -> bool:
    """Validate a numeric input"""
    if not num_str:
        return True
    try:
        num = int(num_str)
        return min_val <= num <= max_val
    except ValueError:
        return False

def safe_filename(name: str) -> str:
    """Create a safe filename from target"""
    return re.sub(r'[^a-zA-Z0-9._-]', '_', name)

# ==================== NMAP EXECUTION ====================
def run_nmap(args: List[str], output_file: Optional[str] = None) -> bool:
    """Execute nmap securely with subprocess (no shell)"""
    cmd = ['nmap'] + args
    if output_file:
        cmd.extend(['-oN', output_file])

    print(f"\n{Colors.GREEN}[*] Executing: {' '.join(cmd)}{Colors.RESET}\n")

    try:
        result = subprocess.run(cmd, check=False)
        return result.returncode == 0
    except FileNotFoundError:
        print(f"{Colors.RED}[!] Error: nmap not found. Please install nmap.{Colors.RESET}")
        return False
    except Exception as e:
        print(f"{Colors.RED}[!] Error executing nmap: {e}{Colors.RESET}")
        return False

# ==================== SCAN CONFIGURATIONS ====================
@dataclass
class ScanConfig:
    name: str
    description: str
    nmap_args: List[str]
    requires_ports: bool = True

SCAN_TYPES = {
    # Normal Scans
    'default': ScanConfig("Default Scan", "Basic port scan", ['-vv']),
    'host_discovery': ScanConfig("Host Discovery", "Skip ping, discover hosts", ['-vv', '-Pn']),
    'syn': ScanConfig("SYN Scan", "Stealth SYN scan", ['-vv', '-sS']),
    'tcp': ScanConfig("TCP Connect Scan", "Full TCP connection", ['-vv', '-sT']),
    'udp': ScanConfig("UDP Scan", "UDP port scan", ['-vv', '-sU']),
    'null': ScanConfig("NULL Scan", "TCP NULL scan", ['-vv', '-sN']),
    'fin': ScanConfig("FIN Scan", "TCP FIN scan", ['-vv', '-sF']),
    'os_version': ScanConfig("OS & Version Detection", "Detect OS and services", ['-sS', '-sV', '-O']),
    'nse_default': ScanConfig("NSE Default Scripts", "Run default NSE scripts", ['-vv', '--script=default']),

    # Firewall Bypass
    'fw_script': ScanConfig("Firewall Bypass Script", "NSE firewall bypass", ['-vv', '--script=firewall-bypass']),
    'fw_fragment': ScanConfig("Fragment Packets", "Fragment packets to bypass FW", ['-vv', '-ff']),

    # Vulnerability Scans
    'vuln_default': ScanConfig("Default Vuln Scan", "General vulnerability scan", ['-vv', '-sV', '-ff', '-Pn', '--script', 'vuln']),
    'vuln_ftp': ScanConfig("FTP Vuln Scan", "FTP vulnerabilities", ['-vv', '-sV', '-ff', '-Pn', '--script', 'ftp*']),
    'vuln_smb': ScanConfig("SMB Vuln Scan", "SMB vulnerabilities", ['-vv', '-sV', '-ff', '-Pn', '--script', 'smb*']),
    'vuln_http': ScanConfig("HTTP Vuln Scan", "HTTP vulnerabilities", ['-vv', '-sV', '-ff', '-Pn', '--script', 'http-vuln*']),
    'vuln_sqli': ScanConfig("SQL Injection Scan", "SQL injection detection", ['-vv', '-sV', '-ff', '-Pn', '--script=http-sql-injection']),
    'vuln_xss_stored': ScanConfig("Stored XSS Scan", "Stored XSS detection", ['-vv', '-sV', '-ff', '-Pn', '--script=http-stored-xss']),
    'vuln_xss_dom': ScanConfig("DOM XSS Scan", "DOM-based XSS detection", ['-vv', '-sV', '-ff', '-Pn', '--script=http-dombased-xss']),
}

# ==================== UI HELPERS ====================
def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def print_logo():
    print(f"""{Colors.RED}
██████╗  █████╗ ██████╗ ██╗  ██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
██║  ██║███████║██████╔╝█████╔╝     ███████╗██║     ███████║██╔██╗ ██║
██║  ██║██╔══██║██╔══██╗██╔═██╗     ╚════██║██║     ██╔══██║██║╚██╗██║
██████╔╝██║  ██║██║  ██║██║  ██╗    ███████║╚██████╗██║  ██║██║ ╚████║
╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝  v{VERSION}

             |_|  By: 1ucif3r - dark4rmy.in |_|
{Colors.RESET}""")

def get_input(prompt: str, color: str = Colors.RED) -> str:
    """Get user input with colored prompt"""
    return input(f"{color}{prompt}{Colors.RESET}").strip()

def print_error(message: str):
    print(f"{Colors.RED}[!] {message}{Colors.RESET}")

def print_success(message: str):
    print(f"{Colors.GREEN}[+] {message}{Colors.RESET}")

def print_info(message: str):
    print(f"{Colors.BLUE}[*] {message}{Colors.RESET}")

# ==================== SCAN EXECUTOR ====================
def execute_scan(scan_type: str):
    """Execute a specific scan type with input validation"""
    config = SCAN_TYPES.get(scan_type)
    if not config:
        print_error("Unknown scan type")
        return

    clear_screen()
    print_logo()
    print(f"\n{Colors.GREEN}=== {config.name} ==={Colors.RESET}")
    print(f"    {config.description}\n")

    # Get and validate target
    target = get_input("Enter Target (IP/Domain): ")
    if not target:
        print_error("No target specified")
        time.sleep(2)
        return

    if not validate_target(target):
        print_error("Invalid target format. Use IP address or domain name only.")
        print_error("Examples: 192.168.1.1, 10.0.0.0/24, example.com")
        time.sleep(3)
        return

    # Get top ports
    args = config.nmap_args.copy()
    if config.requires_ports:
        top_ports = get_input(f"Top Ports (default {DEFAULT_TOP_PORTS}): ")
        if top_ports and not validate_number(top_ports, 1, 65535):
            print_error("Invalid port number")
            time.sleep(2)
            return
        ports = top_ports if top_ports else DEFAULT_TOP_PORTS
        args.append(f'--top-ports={ports}')

    # Add target
    args.append(target)

    # Generate safe output filename
    output_file = f"{scan_type}-{safe_filename(target)}-output"

    # Execute scan
    run_nmap(args, output_file)

    # Post-scan menu
    print(f"\n{Colors.GREEN}[+] Output saved to: {output_file}{Colors.RESET}")
    post_scan_menu()

def execute_data_length_scan():
    """Special handler for data length firewall bypass"""
    clear_screen()
    print_logo()
    print(f"\n{Colors.GREEN}=== Data Length Firewall Bypass ==={Colors.RESET}\n")

    target = get_input("Enter Target (IP/Domain): ")
    if not target or not validate_target(target):
        print_error("Invalid target format")
        time.sleep(2)
        return

    top_ports = get_input(f"Top Ports (default {DEFAULT_TOP_PORTS}): ")
    if top_ports and not validate_number(top_ports, 1, 65535):
        print_error("Invalid port number")
        time.sleep(2)
        return
    ports = top_ports if top_ports else DEFAULT_TOP_PORTS

    data_length = get_input("Data Length (bytes to append): ")
    if not data_length or not validate_number(data_length, 1, 1500):
        print_error("Invalid data length (1-1500)")
        time.sleep(2)
        return

    args = ['-vv', f'--data-length={data_length}', f'--top-ports={ports}', target]
    output_file = f"datalength-{safe_filename(target)}-output"

    run_nmap(args, output_file)
    print(f"\n{Colors.GREEN}[+] Output saved to: {output_file}{Colors.RESET}")
    post_scan_menu()

# ==================== MENUS ====================
def post_scan_menu():
    """Menu after scan completion"""
    print(f"\n{Colors.RED}Your output file is in the current directory{Colors.RESET}")
    print(f"Current directory: {os.getcwd()}\n")
    print("1) Back to Main Menu")
    print("2) Exit")

    choice = get_input("DarkScan:~$ ")
    if choice == "2":
        print(f"{Colors.RED}Good Bye! Happy Hacking!{Colors.RESET}")
        sys.exit(0)

def normal_scan_menu():
    """Normal scanning submenu"""
    while True:
        clear_screen()
        print_logo()
        print(f"""
{Colors.GREEN}=== Normal Scanning ==={Colors.RESET}

    1) Default Scan
    2) Host Discovery (-Pn)
    3) SYN Scan (-sS)
    4) TCP Connect Scan (-sT)
    5) UDP Scan (-sU)
    6) NULL Scan (-sN)
    7) FIN Scan (-sF)
    8) OS & Version Detection (-sV -O)
    9) NSE Default Scripts

    0) Back to Main Menu
        """)

        choice = get_input("DScan:~$ ")

        scan_map = {
            '1': 'default', '2': 'host_discovery', '3': 'syn',
            '4': 'tcp', '5': 'udp', '6': 'null', '7': 'fin',
            '8': 'os_version', '9': 'nse_default'
        }

        if choice == '0':
            return
        elif choice in scan_map:
            execute_scan(scan_map[choice])
        else:
            print_error("Invalid option")
            time.sleep(1)

def firewall_bypass_menu():
    """Firewall bypass submenu"""
    while True:
        clear_screen()
        print_logo()
        print(f"""
{Colors.GREEN}=== Firewall Bypass ==={Colors.RESET}

    1) Script Bypass (--script=firewall-bypass)
    2) Data Length (--data-length)
    3) Fragment Packets (-ff)

    0) Back to Main Menu
        """)

        choice = get_input("FirewallBypass:~$ ")

        if choice == '0':
            return
        elif choice == '1':
            execute_scan('fw_script')
        elif choice == '2':
            execute_data_length_scan()
        elif choice == '3':
            execute_scan('fw_fragment')
        else:
            print_error("Invalid option")
            time.sleep(1)

def vulnerability_scan_menu():
    """Vulnerability scanning submenu"""
    while True:
        clear_screen()
        print_logo()
        print(f"""
{Colors.GREEN}=== Vulnerability Scanning ==={Colors.RESET}

    1) Default Vuln Scan (--script vuln)
    2) FTP Vulnerabilities
    3) SMB Vulnerabilities
    4) HTTP Vulnerabilities
    5) SQL Injection Detection
    6) Stored XSS Detection
    7) DOM-based XSS Detection

    0) Back to Main Menu
        """)

        choice = get_input("VulnScan:~$ ")

        scan_map = {
            '1': 'vuln_default', '2': 'vuln_ftp', '3': 'vuln_smb',
            '4': 'vuln_http', '5': 'vuln_sqli', '6': 'vuln_xss_stored',
            '7': 'vuln_xss_dom'
        }

        if choice == '0':
            return
        elif choice in scan_map:
            execute_scan(scan_map[choice])
        else:
            print_error("Invalid option")
            time.sleep(1)

def show_credits():
    """Display credits"""
    clear_screen()
    print(f"""{Colors.RED}
         ▄▄·        ▐ ▄ ▄▄▄▄▄ ▄▄▄·  ▄▄· ▄▄▄▄▄
        ▐█ ▌▪▪     •█▌▐█•██  ▐█ ▀█ ▐█ ▌▪•██
        ██ ▄▄ ▄█▀▄ ▐█▐▐▌ ▐█.▪▄█▀▀█ ██ ▄▄ ▐█.▪
        ▐███▌▐█▌.▐▌██▐█▌ ▐█▌·▐█ ▪▐▌▐███▌ ▐█▌·
        ·▀▀▀  ▀█▄▀▪▀▀ █▪ ▀▀▀  ▀  ▀ ·▀▀▀  ▀▀▀
        =====================================
{Colors.RESET}
    [*] Author: 1ucif3r
    [*] Email: 0x1ucif3r@gmail.com
    [*] GitHub: https://github.com/1ucif3r
    [*] Website: https://dark4rmy.in
    [*] Instagram: https://instagram.com/0x1ucif3r

    Press Enter to continue...
    """)
    input()

def main_menu():
    """Main menu loop"""
    while True:
        clear_screen()
        print_logo()
        print(f"""
    1) Normal Scanning
    2) Firewall Bypass
    3) Vulnerability Scanning

    c) Credits
    q) Exit
        """)

        choice = get_input("root@DarkScan:~$ ").lower()

        if choice == '1':
            normal_scan_menu()
        elif choice == '2':
            firewall_bypass_menu()
        elif choice == '3':
            vulnerability_scan_menu()
        elif choice == 'c':
            show_credits()
        elif choice in ('q', '0', 'exit', 'quit'):
            print(f"{Colors.RED}Good Bye! Happy Hacking!{Colors.RESET}")
            sys.exit(0)
        else:
            print_error("Invalid option")
            time.sleep(1)

# ==================== SIGNAL HANDLER ====================
def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully"""
    print(f"\n{Colors.RED}[!] Interrupted. Goodbye!{Colors.RESET}")
    sys.exit(0)

# ==================== MAIN ====================
def main():
    """Entry point with root check"""
    signal.signal(signal.SIGINT, signal_handler)

    # Check for root (nmap needs root for some scans)
    if os.geteuid() != 0:
        print(f"{Colors.YELLOW}[!] Warning: Running without root. Some scans may not work.{Colors.RESET}")
        print("[*] Consider running with: sudo python3 darkscan.py")
        time.sleep(2)

    main_menu()

if __name__ == "__main__":
    main()
