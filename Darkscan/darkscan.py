#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DarkScan v3.0 - Secure Nmap Wrapper for Penetration Testing
By: 1ucif3r - dark4rmy.in
Security fixes: Input validation, subprocess usage (no shell injection)
Features: Demo mode, HTML reports, Visual risk scoring
"""

import sys
import os
import time
import signal
import subprocess
import re
import argparse
from dataclasses import dataclass
from typing import Optional, List, Tuple
from enum import Enum
from datetime import datetime

# Add parent directory for utils import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from utils.pentest_utils import (
        RiskLevel, Finding, ScanResult, DemoMode,
        HTMLReportGenerator, TerminalOutput
    )
    UTILS_AVAILABLE = True
except ImportError:
    UTILS_AVAILABLE = False

# ==================== CONFIGURATION ====================
DEFAULT_TOP_PORTS = "50"
VERSION = "3.0"

# Global demo mode and scan result
DEMO_MODE: Optional[DemoMode] = None
CURRENT_SCAN: Optional['ScanResult'] = None

# ==================== COLORS ====================
class Colors:
    RED = '\033[1;91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
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

# ==================== RISK ANALYSIS ====================
PORT_RISK_DATABASE = {
    # Critical - Remote code execution / Direct compromise
    21: ("FTP", RiskLevel.HIGH if UTILS_AVAILABLE else "HIGH", "FTP souvent vulnérable, accès anonyme possible"),
    22: ("SSH", RiskLevel.MEDIUM if UTILS_AVAILABLE else "MEDIUM", "Point d'entrée commun, vérifier bruteforce"),
    23: ("Telnet", RiskLevel.CRITICAL if UTILS_AVAILABLE else "CRITICAL", "Protocole non chiffré, très dangereux"),
    25: ("SMTP", RiskLevel.MEDIUM if UTILS_AVAILABLE else "MEDIUM", "Relay ouvert possible, spam"),
    53: ("DNS", RiskLevel.MEDIUM if UTILS_AVAILABLE else "MEDIUM", "Zone transfer, DNS amplification"),
    80: ("HTTP", RiskLevel.MEDIUM if UTILS_AVAILABLE else "MEDIUM", "Applications web vulnérables"),
    110: ("POP3", RiskLevel.MEDIUM if UTILS_AVAILABLE else "MEDIUM", "Protocole non chiffré par défaut"),
    111: ("RPC", RiskLevel.HIGH if UTILS_AVAILABLE else "HIGH", "Services RPC exploitables"),
    135: ("MSRPC", RiskLevel.HIGH if UTILS_AVAILABLE else "HIGH", "Windows RPC, cible courante"),
    139: ("NetBIOS", RiskLevel.HIGH if UTILS_AVAILABLE else "HIGH", "Enumération réseau Windows"),
    143: ("IMAP", RiskLevel.MEDIUM if UTILS_AVAILABLE else "MEDIUM", "Email non chiffré par défaut"),
    443: ("HTTPS", RiskLevel.LOW if UTILS_AVAILABLE else "LOW", "Vérifier certificats et config TLS"),
    445: ("SMB", RiskLevel.CRITICAL if UTILS_AVAILABLE else "CRITICAL", "EternalBlue, ransomware, très critique"),
    512: ("rexec", RiskLevel.CRITICAL if UTILS_AVAILABLE else "CRITICAL", "Exécution distante sans auth"),
    513: ("rlogin", RiskLevel.CRITICAL if UTILS_AVAILABLE else "CRITICAL", "Login distant non sécurisé"),
    514: ("RSH", RiskLevel.CRITICAL if UTILS_AVAILABLE else "CRITICAL", "Shell distant non sécurisé"),
    1433: ("MSSQL", RiskLevel.HIGH if UTILS_AVAILABLE else "HIGH", "Base de données exposée"),
    1521: ("Oracle", RiskLevel.HIGH if UTILS_AVAILABLE else "HIGH", "Base Oracle exposée"),
    2049: ("NFS", RiskLevel.HIGH if UTILS_AVAILABLE else "HIGH", "Partages réseau exploitables"),
    3306: ("MySQL", RiskLevel.HIGH if UTILS_AVAILABLE else "HIGH", "Base MySQL exposée"),
    3389: ("RDP", RiskLevel.HIGH if UTILS_AVAILABLE else "HIGH", "BlueKeep, bruteforce RDP"),
    5432: ("PostgreSQL", RiskLevel.HIGH if UTILS_AVAILABLE else "HIGH", "Base PostgreSQL exposée"),
    5900: ("VNC", RiskLevel.HIGH if UTILS_AVAILABLE else "HIGH", "Accès graphique distant"),
    6379: ("Redis", RiskLevel.CRITICAL if UTILS_AVAILABLE else "CRITICAL", "Souvent sans authentification"),
    8080: ("HTTP-Proxy", RiskLevel.MEDIUM if UTILS_AVAILABLE else "MEDIUM", "Proxy/admin panel exposé"),
    27017: ("MongoDB", RiskLevel.CRITICAL if UTILS_AVAILABLE else "CRITICAL", "NoSQL souvent sans auth"),
}

def analyze_nmap_output(output: str, target: str, scan_type: str) -> Optional['ScanResult']:
    """Analyze nmap output and create findings with risk scoring"""
    if not UTILS_AVAILABLE:
        return None

    scan_result = ScanResult(
        target=target,
        scan_type=scan_type,
        demo_mode=DEMO_MODE.enabled if DEMO_MODE else False
    )
    scan_result.raw_output = output

    # Parse open ports from nmap output
    port_pattern = r'(\d+)/tcp\s+open\s+(\S+)'
    for match in re.finditer(port_pattern, output):
        port = int(match.group(1))
        service = match.group(2)

        if port in PORT_RISK_DATABASE:
            db_service, risk, description = PORT_RISK_DATABASE[port]
            finding = Finding(
                title=f"Port {port} ouvert ({db_service})",
                description=description,
                risk=risk,
                port=port,
                service=service,
                evidence=match.group(0),
                recommendation=get_port_recommendation(port)
            )
        else:
            finding = Finding(
                title=f"Port {port} ouvert ({service})",
                description=f"Service {service} détecté sur port {port}",
                risk=RiskLevel.INFO,
                port=port,
                service=service,
                evidence=match.group(0)
            )

        scan_result.add_finding(finding)

    # Check for vulnerability scripts output
    vuln_pattern = r'VULNERABLE[:\s]*(.*?)(?=\n\n|\Z)'
    for match in re.finditer(vuln_pattern, output, re.DOTALL | re.IGNORECASE):
        scan_result.add_finding(Finding(
            title="Vulnérabilité détectée par NSE",
            description=match.group(1).strip()[:200],
            risk=RiskLevel.CRITICAL,
            evidence=match.group(0)[:500]
        ))

    scan_result.end_time = datetime.now()
    return scan_result

def get_port_recommendation(port: int) -> str:
    """Get security recommendation for a specific port"""
    recommendations = {
        21: "Utiliser SFTP à la place, désactiver FTP anonyme",
        22: "Utiliser des clés SSH, désactiver auth par mot de passe",
        23: "Désactiver Telnet immédiatement, utiliser SSH",
        445: "Mettre à jour Windows, désactiver SMBv1, isoler le réseau",
        3389: "Utiliser un VPN, activer NLA, patcher BlueKeep",
        6379: "Activer l'authentification Redis, restreindre l'accès",
        27017: "Activer l'authentification MongoDB, ne pas exposer publiquement",
    }
    return recommendations.get(port, "Évaluer la nécessité du service et restreindre l'accès")

# ==================== NMAP EXECUTION ====================
def run_nmap(args: List[str], output_file: Optional[str] = None,
             target: str = "", scan_type: str = "scan") -> Tuple[bool, str]:
    """Execute nmap securely with subprocess (no shell)"""
    global CURRENT_SCAN

    cmd = ['nmap'] + args
    if output_file:
        cmd.extend(['-oN', output_file])

    cmd_str = ' '.join(cmd)

    # Demo mode check
    if DEMO_MODE and DEMO_MODE.enabled:
        DEMO_MODE.log_action("NMAP_SCAN", cmd_str,
                             f"Scan {scan_type} sur {target}", "MEDIUM")

        # Create simulated result for demo
        if UTILS_AVAILABLE:
            CURRENT_SCAN = ScanResult(
                target=target,
                scan_type=scan_type,
                demo_mode=True
            )
            CURRENT_SCAN.raw_output = f"[DEMO MODE] Command would be: {cmd_str}"
            CURRENT_SCAN.end_time = datetime.now()

        return True, ""

    print(f"\n{Colors.GREEN}[*] Executing: {cmd_str}{Colors.RESET}\n")

    try:
        result = subprocess.run(cmd, check=False, capture_output=True, text=True)
        output = result.stdout + result.stderr
        print(output)

        # Analyze output for findings
        if UTILS_AVAILABLE and target:
            CURRENT_SCAN = analyze_nmap_output(output, target, scan_type)

        return result.returncode == 0, output
    except FileNotFoundError:
        print(f"{Colors.RED}[!] Error: nmap not found. Please install nmap.{Colors.RESET}")
        return False, ""
    except Exception as e:
        print(f"{Colors.RED}[!] Error executing nmap: {e}{Colors.RESET}")
        return False, ""

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

    # Show demo mode banner
    if DEMO_MODE and DEMO_MODE.enabled:
        print(f"\n{Colors.YELLOW}{'='*60}")
        print(f"  🎭 MODE DÉMO ACTIF - Aucune commande ne sera exécutée")
        print(f"{'='*60}{Colors.RESET}")

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

    # Execute scan with target info for analysis
    success, output = run_nmap(args, output_file, target=target, scan_type=config.name)

    # Show risk summary if available
    if UTILS_AVAILABLE and CURRENT_SCAN and CURRENT_SCAN.findings:
        print_risk_summary()

    # Post-scan menu
    if not (DEMO_MODE and DEMO_MODE.enabled):
        print(f"\n{Colors.GREEN}[+] Output saved to: {output_file}{Colors.RESET}")
    post_scan_menu(target, scan_type)

def print_risk_summary():
    """Print visual risk summary after scan"""
    if not UTILS_AVAILABLE or not CURRENT_SCAN:
        return

    TerminalOutput.print_summary(CURRENT_SCAN)

def execute_data_length_scan():
    """Special handler for data length firewall bypass"""
    clear_screen()
    print_logo()

    # Show demo mode banner
    if DEMO_MODE and DEMO_MODE.enabled:
        print(f"\n{Colors.YELLOW}{'='*60}")
        print(f"  🎭 MODE DÉMO ACTIF - Aucune commande ne sera exécutée")
        print(f"{'='*60}{Colors.RESET}")

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

    success, output = run_nmap(args, output_file, target=target, scan_type="Data Length Bypass")

    # Show risk summary if available
    if UTILS_AVAILABLE and CURRENT_SCAN and CURRENT_SCAN.findings:
        print_risk_summary()

    if not (DEMO_MODE and DEMO_MODE.enabled):
        print(f"\n{Colors.GREEN}[+] Output saved to: {output_file}{Colors.RESET}")
    post_scan_menu(target, "Data Length Bypass")

# ==================== MENUS ====================
def post_scan_menu(target: str = "", scan_type: str = ""):
    """Menu after scan completion with report options"""
    print(f"\n{Colors.RED}Your output file is in the current directory{Colors.RESET}")
    print(f"Current directory: {os.getcwd()}\n")

    # Show demo mode summary if applicable
    if DEMO_MODE and DEMO_MODE.enabled:
        print(DEMO_MODE.get_summary())

    print("1) Back to Main Menu")
    print("2) Exit")

    # Add report options if utils available and we have findings
    if UTILS_AVAILABLE and CURRENT_SCAN:
        print(f"\n{Colors.CYAN}=== Options de Rapport ==={Colors.RESET}")
        print("3) Générer rapport HTML")
        print("4) Afficher résumé des risques")

    choice = get_input("DarkScan:~$ ")

    if choice == "2":
        print(f"{Colors.RED}Good Bye! Happy Hacking!{Colors.RESET}")
        sys.exit(0)
    elif choice == "3" and UTILS_AVAILABLE and CURRENT_SCAN:
        generate_html_report(target, scan_type)
        post_scan_menu(target, scan_type)  # Return to menu
    elif choice == "4" and UTILS_AVAILABLE and CURRENT_SCAN:
        print_risk_summary()
        input(f"\n{Colors.GREEN}Appuyez sur Entrée pour continuer...{Colors.RESET}")
        post_scan_menu(target, scan_type)

def generate_html_report(target: str, scan_type: str):
    """Generate and save HTML report"""
    if not UTILS_AVAILABLE or not CURRENT_SCAN:
        print_error("No scan results available for report")
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"report_{safe_filename(target)}_{timestamp}.html"

    try:
        HTMLReportGenerator.generate(CURRENT_SCAN, filename)
        print_success(f"Rapport HTML généré: {filename}")
        print_info(f"Ouvrez le fichier dans un navigateur pour visualiser")
    except Exception as e:
        print_error(f"Erreur lors de la génération du rapport: {e}")

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

        # Show mode indicators
        if DEMO_MODE and DEMO_MODE.enabled:
            print(f"{Colors.YELLOW}  🎭 MODE DÉMO ACTIF{Colors.RESET}")

        print(f"""
    1) Normal Scanning
    2) Firewall Bypass
    3) Vulnerability Scanning
    {"" if not UTILS_AVAILABLE else f'''
    {Colors.CYAN}=== Nouvelles Fonctionnalités ==={Colors.RESET}
    d) Basculer Mode Démo (actuellement: {"ON" if DEMO_MODE and DEMO_MODE.enabled else "OFF"})
    r) Générer Rapport Démo
    '''}
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
        elif choice == 'd' and UTILS_AVAILABLE:
            toggle_demo_mode()
        elif choice == 'r' and UTILS_AVAILABLE:
            generate_demo_report()
        elif choice == 'c':
            show_credits()
        elif choice in ('q', '0', 'exit', 'quit'):
            print(f"{Colors.RED}Good Bye! Happy Hacking!{Colors.RESET}")
            sys.exit(0)
        else:
            print_error("Invalid option")
            time.sleep(1)

def toggle_demo_mode():
    """Toggle demo mode on/off"""
    global DEMO_MODE
    if DEMO_MODE is None:
        DEMO_MODE = DemoMode(enabled=True)
    else:
        DEMO_MODE.enabled = not DEMO_MODE.enabled

    status = "ACTIVÉ" if DEMO_MODE.enabled else "DÉSACTIVÉ"
    print_success(f"Mode démo {status}")
    time.sleep(1)

def generate_demo_report():
    """Generate a demo report to showcase the reporting feature"""
    from utils.pentest_utils import demo_report_example

    print_info("Génération d'un rapport de démonstration...")

    demo_result = demo_report_example()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"demo_report_{timestamp}.html"

    try:
        HTMLReportGenerator.generate(demo_result, filename)
        print_success(f"Rapport démo généré: {filename}")
        print_info("Ce rapport montre les capacités de scoring visuel")

        # Show summary in terminal
        TerminalOutput.print_summary(demo_result)

        input(f"\n{Colors.GREEN}Appuyez sur Entrée pour continuer...{Colors.RESET}")
    except Exception as e:
        print_error(f"Erreur: {e}")
        time.sleep(2)

# ==================== SIGNAL HANDLER ====================
def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully"""
    print(f"\n{Colors.RED}[!] Interrupted. Goodbye!{Colors.RESET}")
    sys.exit(0)

# ==================== ARGUMENT PARSER ====================
def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description=f"DarkScan v{VERSION} - Secure Nmap Wrapper for Penetration Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 darkscan.py --demo         Start in demo mode (no actual scans)
  python3 darkscan.py --generate-demo Generate a demo report and exit
  python3 darkscan.py                 Normal mode

Features:
  - Demo Mode: Show what would happen without executing scans
  - HTML Reports: Professional security reports with risk scoring
  - Visual Risk Scoring: CRITICAL/HIGH/MEDIUM/LOW indicators
        """
    )
    parser.add_argument('--demo', '-d', action='store_true',
                        help='Start in demo mode (no actual scans executed)')
    parser.add_argument('--generate-demo', '-g', action='store_true',
                        help='Generate a demo report and exit')
    parser.add_argument('--version', '-v', action='version',
                        version=f'DarkScan v{VERSION}')
    return parser.parse_args()

# ==================== MAIN ====================
def main():
    """Entry point with root check and argument parsing"""
    global DEMO_MODE

    signal.signal(signal.SIGINT, signal_handler)

    # Parse command line arguments
    args = parse_arguments()

    # Initialize demo mode if requested
    if UTILS_AVAILABLE:
        DEMO_MODE = DemoMode(enabled=args.demo)

        # Generate demo report and exit if requested
        if args.generate_demo:
            print_logo()
            generate_demo_report()
            return
    elif args.demo or args.generate_demo:
        print_error("Utils module not available. Demo features require utils/pentest_utils.py")
        sys.exit(1)

    # Check for root (nmap needs root for some scans)
    if os.geteuid() != 0:
        print(f"{Colors.YELLOW}[!] Warning: Running without root. Some scans may not work.{Colors.RESET}")
        print("[*] Consider running with: sudo python3 darkscan.py")
        time.sleep(2)

    main_menu()

if __name__ == "__main__":
    main()
