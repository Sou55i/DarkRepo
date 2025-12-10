#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Crips v2.0 - IP/Domain Reconnaissance Tool
Original by Manisso - Refactored with security fixes
Security: Input validation, secure HTTP requests (no shell injection)
"""

import sys
import os
import re
import urllib.request
import urllib.parse
import urllib.error
import socket
import subprocess
from typing import Optional

# ==================== CONFIGURATION ====================
VERSION = "2.0"
API_BASE = "https://api.hackertarget.com"

# ==================== COLORS ====================
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

# ==================== SECURITY FUNCTIONS ====================
def validate_target(target: str) -> bool:
    """Validate that input is a valid IP or domain (anti-injection)"""
    # IPv4 pattern
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    # IPv6 pattern (simplified)
    ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
    # Domain pattern
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
    # IP range for reverse DNS (e.g., 192.168.1.0/24)
    cidr_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'

    if re.match(ipv4_pattern, target):
        return True
    if re.match(ipv6_pattern, target):
        return True
    if re.match(domain_pattern, target):
        return True
    if re.match(cidr_pattern, target):
        return True
    return False

def safe_url_encode(value: str) -> str:
    """Safely encode a value for URL inclusion"""
    return urllib.parse.quote(value, safe='')

# ==================== API FUNCTIONS ====================
def api_request(endpoint: str, query: str) -> Optional[str]:
    """Make a secure API request to hackertarget.com"""
    if not validate_target(query):
        print(f"{Colors.RED}[!] Invalid target format. Use IP or domain only.{Colors.RESET}")
        return None

    url = f"{API_BASE}/{endpoint}/?q={safe_url_encode(query)}"

    try:
        req = urllib.request.Request(url, headers={
            'User-Agent': 'Crips/2.0 Security Tool'
        })
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.read().decode('utf-8')
    except urllib.error.HTTPError as e:
        print(f"{Colors.RED}[!] HTTP Error: {e.code} - {e.reason}{Colors.RESET}")
        return None
    except urllib.error.URLError as e:
        print(f"{Colors.RED}[!] Connection Error: {e.reason}{Colors.RESET}")
        return None
    except Exception as e:
        print(f"{Colors.RED}[!] Error: {e}{Colors.RESET}")
        return None

def get_my_ip() -> Optional[str]:
    """Get current public IP address"""
    try:
        req = urllib.request.Request("https://api.ipify.org", headers={
            'User-Agent': 'Crips/2.0'
        })
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.read().decode('utf-8')
    except:
        return None

# ==================== UI HELPERS ====================
def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def print_logo():
    print(f"""{Colors.CYAN}
   _|_|_|            _|
 _|        _|  _|_|      _|_|_|      _|_|_|
 _|        _|_|      _|  _|    _|  _|_|
 _|        _|        _|  _|    _|      _|_|
   _|_|_|  _|        _|  _|_|_|    _|_|_|
                         _|
                         _|  {Colors.RED}v{VERSION}{Colors.RESET}
{Colors.BOLD}
       }}--{{+}} Coded By Manisso {{+}}--{{
     }}----{{+}}  Secured Edition   {{+}}----{{
       }}--{{+}} Greetz To IcoDz  {{+}}--{{
{Colors.RESET}""")

def print_menu():
    print(f"""{Colors.CYAN}
    {{1}}--Whois Lookup
    {{2}}--Traceroute (MTR)
    {{3}}--DNS Lookup
    {{4}}--Reverse DNS Lookup
    {{5}}--GeoIP Lookup
    {{6}}--Port Scan
    {{7}}--Reverse IP Lookup (Find domains on same IP)
    {{8}}--HTTP Headers
    {{9}}--Find Subdomains

    {{0}}--Exit
{Colors.RESET}""")

def get_input(prompt: str) -> str:
    """Get user input with validation"""
    return input(f"{Colors.GREEN}{prompt}{Colors.RESET}").strip()

def print_banner(title: str):
    """Print a formatted banner for results"""
    print(f"\n{Colors.YELLOW}{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}{Colors.RESET}\n")

def wait_for_continue():
    """Ask user to continue or exit"""
    print()
    choice = get_input("Continue? [Y/n] -> ")
    if choice.lower() == 'n':
        print(f"{Colors.CYAN}Goodbye!{Colors.RESET}")
        sys.exit(0)

# ==================== RECONNAISSANCE FUNCTIONS ====================
def whois_lookup():
    """Perform WHOIS lookup"""
    print_banner("WHOIS LOOKUP")
    target = get_input("Enter IP or Domain: ")

    result = api_request("whois", target)
    if result:
        print(result)

    wait_for_continue()

def traceroute():
    """Perform MTR traceroute"""
    print_banner("TRACEROUTE (MTR)")
    target = get_input("Enter IP or Domain: ")

    result = api_request("mtr", target)
    if result:
        print(result)

    wait_for_continue()

def dns_lookup():
    """Perform DNS lookup"""
    print_banner("DNS LOOKUP")
    target = get_input("Enter Domain: ")

    result = api_request("dnslookup", target)
    if result:
        print(result)

    wait_for_continue()

def reverse_dns():
    """Perform reverse DNS lookup"""
    print_banner("REVERSE DNS LOOKUP")
    print("Enter IP address, IP range (e.g., 192.168.1.0/24), or domain")
    target = get_input("Target: ")

    result = api_request("reversedns", target)
    if result:
        print(result)

    wait_for_continue()

def geoip_lookup():
    """Perform GeoIP lookup"""
    print_banner("GEOIP LOOKUP")
    target = get_input("Enter IP or Domain: ")

    result = api_request("geoip", target)
    if result:
        print(result)

    wait_for_continue()

def port_scan():
    """Perform basic port scan via API"""
    print_banner("PORT SCAN")
    print(f"{Colors.YELLOW}Note: This uses an external API for basic scanning.")
    print(f"For comprehensive scans, use DarkScan with nmap.{Colors.RESET}\n")
    target = get_input("Enter IP or Domain: ")

    result = api_request("nmap", target)
    if result:
        print(result)

    wait_for_continue()

def reverse_ip_lookup():
    """Find domains hosted on the same IP"""
    print_banner("REVERSE IP LOOKUP")
    print("Find all domains hosted on the same IP address\n")
    target = get_input("Enter IP or Domain: ")

    result = api_request("reverseiplookup", target)
    if result:
        lines = result.strip().split('\n')
        print(f"\n{Colors.GREEN}[+] Found {len(lines)} domain(s):{Colors.RESET}\n")
        for line in lines:
            print(f"    {line}")

        # Offer to save results
        save = get_input("\nSave results to file? [y/N]: ")
        if save.lower() == 'y':
            filename = f"reverse_ip_{target.replace('.', '_')}.txt"
            try:
                with open(filename, 'w') as f:
                    f.write(result)
                print(f"{Colors.GREEN}[+] Saved to {filename}{Colors.RESET}")
            except Exception as e:
                print(f"{Colors.RED}[!] Error saving: {e}{Colors.RESET}")

    wait_for_continue()

def http_headers():
    """Get HTTP headers from a target"""
    print_banner("HTTP HEADERS")
    target = get_input("Enter Domain (e.g., example.com): ")

    result = api_request("httpheaders", target)
    if result:
        print(result)

    wait_for_continue()

def find_subdomains():
    """Find subdomains of a target domain"""
    print_banner("SUBDOMAIN FINDER")
    target = get_input("Enter Domain (e.g., example.com): ")

    result = api_request("hostsearch", target)
    if result:
        lines = result.strip().split('\n')
        print(f"\n{Colors.GREEN}[+] Found {len(lines)} subdomain(s):{Colors.RESET}\n")
        for line in lines:
            print(f"    {line}")

        # Offer to save results
        save = get_input("\nSave results to file? [y/N]: ")
        if save.lower() == 'y':
            filename = f"subdomains_{target.replace('.', '_')}.txt"
            try:
                with open(filename, 'w') as f:
                    f.write(result)
                print(f"{Colors.GREEN}[+] Saved to {filename}{Colors.RESET}")
            except Exception as e:
                print(f"{Colors.RED}[!] Error saving: {e}{Colors.RESET}")

    wait_for_continue()

# ==================== MAIN MENU ====================
def main_menu():
    """Main menu loop"""
    while True:
        clear_screen()

        # Show current IP
        my_ip = get_my_ip()
        if my_ip:
            print(f"{Colors.YELLOW}[*] Your IP: {my_ip}{Colors.RESET}")

        print_logo()
        print_menu()

        choice = get_input("Crips~# ")

        menu_actions = {
            '1': whois_lookup,
            '2': traceroute,
            '3': dns_lookup,
            '4': reverse_dns,
            '5': geoip_lookup,
            '6': port_scan,
            '7': reverse_ip_lookup,
            '8': http_headers,
            '9': find_subdomains,
        }

        if choice == '0' or choice.lower() in ('exit', 'quit', 'q'):
            print(f"{Colors.CYAN}Goodbye!{Colors.RESET}")
            sys.exit(0)
        elif choice in menu_actions:
            clear_screen()
            print_logo()
            menu_actions[choice]()
        else:
            print(f"{Colors.RED}[!] Invalid option{Colors.RESET}")
            import time
            time.sleep(1)

# ==================== ENTRY POINT ====================
def main():
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n{Colors.CYAN}Interrupted. Goodbye!{Colors.RESET}")
        sys.exit(0)

if __name__ == "__main__":
    main()
