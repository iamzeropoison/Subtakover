#!/usr/bin/env python3
import argparse
import socket
import random
import re
import sys
import time
import whois
import ipaddress
import dns.resolver
import requests
import threading
from ipwhois import IPWhois
import os

# Fingerprints for service detection
FINGERPRINTS = {
    "AWS/S3": r"The specified bucket does not exist",
    "Bitbucket": r"Repository not found",
    "Github": r"There isn't a GitHub Pages site here",
    "Wordpress": r"Do you want to register .*?\\.wordpress\\.com?",
    "Fastly": r"Fastly error: unknown domain",
    "Help Scout": r"No settings were found for this company:",
    "Ghost": r"Site unavailable|Failed to resolve DNS path",
    "Readthedocs": r"The link you have followed or the URL that you entered does not exist",
    "LaunchRock": r"HTTP_STATUS=500",
    "Help Juice": r"We could not find what you're looking for.",
    "Pantheon": r"404 error unknown site!",
    "Zendesk": r"Help Center Closed",
    "Ngrok": r"Tunnel .*\\.ngrok\\.io not found"
}

COLOR_CODES = ['\033[91m', '\033[92m', '\033[93m', '\033[94m', '\033[95m', '\033[96m']
RESET = '\033[0m'

def color_text(text):
    return f"{random.choice(COLOR_CODES)}{text}{RESET}"

def print_banner():
    print(color_text("""
╔══════════════════════════════════════════════════════════╗
║          Subdomain Takeover Scanner v1.0                 ║
║              Powered by ZeroPoison                       ║
╠═══════════════════════════════════════════════════════════════════════════
║  Example Usage:                                                           ║
║  Full Scan        : python3 subtakover.py -d example.com                  ║
║  Subdomain Check  : python3 subtakover.py -s sub.target.com               ║
║  Subdomain w/Thread: python3 subtakover.py -l subdomains.txt --threads 15 ║
╚═══════════════════════════════════════════════════════════════════════════
"""))

def get_cname(domain):
    try:
        answers = dns.resolver.resolve(domain, 'CNAME')
        for rdata in answers:
            return str(rdata.target).rstrip('.')
    except:
        return None

def get_content(domain):
    try:
        url = f"http://{domain}"
        response = requests.get(url, timeout=5)
        return response.text, response.status_code
    except:
        return None, None

def match_fingerprint(content):
    if not content:
        return "Unknown", False
    for service, pattern in FINGERPRINTS.items():
        if re.search(pattern, content):
            return service, True
    return "Unknown", False

def whois_info(domain):
    try:
        w = whois.whois(domain)
        return w.registrar or "Unknown"
    except:
        return "Unknown"

def get_asn_info(domain):
    try:
        ip = socket.gethostbyname(domain)
        obj = IPWhois(ip)
        res = obj.lookup_rdap()
        return res.get("asn_description", "Unknown")
    except:
        return "Unknown"

results = []
http_404s = []
lock = threading.Lock()

def scan_domain(domain):
    content, status_code = get_content(domain)

    if status_code == 404:
        with lock:
            http_404s.append(domain)

        cname = get_cname(domain)
        service, vulnerable = match_fingerprint(content)

        print(color_text(f"[ ] Subdomain : {domain}"))
        print(color_text(f"[ ] CNAME     : {cname if cname else 'None'}"))
        print(color_text(f"[ ] Service   : {service}"))
        status = "Vulnerable" if vulnerable else "Not Vulnerable"
        print(color_text(f"[*] Status    : {status}"))

        if vulnerable:
            asn = get_asn_info(domain)
            reg = whois_info(domain)
            print(color_text(f"[🌐] ASN Info : {asn}"))
            print(color_text(f"[👤] Registrar: {reg}"))

        print("──────────────────────────────────────────────")
        with lock:
            results.append([domain, cname or "None", service, status])

def load_targets(file):
    with open(file) as f:
        return [line.strip() for line in f if line.strip()]

def write_report():
    with open("takeover_report.txt", "w") as f:
        f.write("# ZeroPoison Subdomain Takeover Report\n\n")
        for row in results:
            f.write(f"Subdomain          : {row[0]}\n")
            f.write(f"CNAME              : {row[1]}\n")
            f.write(f"Service            : {row[2]}\n")
            f.write(f"Vulnerability      : {row[3]}\n")
            f.write("------------------------------------------------------------\n")
    print(color_text("[✔] Report saved as takeover_report.txt"))

    with open("404_subdomains.txt", "w") as f:
        for domain in http_404s:
            f.write(domain + "\n")
    print(color_text("[✔] 404 subdomains saved as 404_subdomains.txt"))

def run_full_domain_scan(domain):
    print(color_text(f"[🔍] Running Subdomain Enumeration for: {domain}"))
    os.system(f"subfinder -d {domain} -silent > subs_temp.txt")
    print(color_text("[📁] Subdomains saved to subs_temp.txt"))
    os.system("httpx -status-code -mc 404 -silent -l subs_temp.txt > 404_subdomains.txt")
    print(color_text("[🔍] 404 Subdomains filtered to 404_subdomains.txt"))

    if not os.path.exists("404_subdomains.txt") or os.stat("404_subdomains.txt").st_size == 0:
        print(color_text("[⚠️] No 404 subdomains found. Exiting scan."))
        return

    targets = load_targets("404_subdomains.txt")
    for sub in targets:
        scan_domain(sub)
    write_report()

def show_example():
    print("""
Examples:
  python3 subtakover.py -s blog.target.com
  python3 subtakover.py -l subs.txt --threads 10
  python3 subtakover.py -d example.com
    """)
    sys.exit()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--subdomain", help="Scan single subdomain")
    parser.add_argument("-l", "--list", help="Scan list of subdomains")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("-d", "--domain", help="Run full scan from domain to takeover")
    parser.add_argument("--example", action="store_true", help="Show usage examples")
    args = parser.parse_args()

    print_banner()

    if args.example:
        show_example()

    if args.domain:
        run_full_domain_scan(args.domain)
    elif args.subdomain:
        scan_domain(args.subdomain)
        write_report()
    elif args.list:
        targets = load_targets(args.list)
        thread_list = []

        def thread_worker(subs):
            for sub in subs:
                scan_domain(sub)

        chunks = [targets[i::args.threads] for i in range(args.threads)]
        for chunk in chunks:
            t = threading.Thread(target=thread_worker, args=(chunk,))
            thread_list.append(t)
            t.start()

        for t in thread_list:
            t.join()

        write_report()
    else:
        parser.print_help()
        return

if __name__ == "__main__":
    main()

