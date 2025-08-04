# Subtakover

### ⚔️ Subdomain Takeover Scanner v1.0  
**Developed by [iamzeropoison](https://github.com/iamzeropoison)**

---

## 📌 What is Subtakover?

**Subtakover** is a powerful and automated subdomain takeover scanner. It performs enumeration, filtering for `404` subdomains, detects vulnerable services using content fingerprinting, and generates a clean takeover report.

Subdomain takeover vulnerabilities occur when a DNS entry points to an external service (like AWS, GitHub, etc.) that is no longer claimed. This tool helps identify such weak subdomains quickly and efficiently.

---

## 🚀 Features

- ✅ Automated subdomain enumeration (using `subfinder`)
- ✅ 404 response filtering (using `httpx`)
- ✅ Fingerprint matching for common takeover services
- ✅ WHOIS and ASN info for vulnerable subdomains
- ✅ Colored terminal output
- ✅ Threaded scanning for better performance
- ✅ Generates:
  - `takeover_report.txt` with detailed info
  - `404_subdomains.txt` for potential targets

---

## 🛠️ Installation

Make sure you have the following tools installed:

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
pip install -r requirements.txt


## Required Python modules:


pip install ipwhois dnspython python-whois requests

## Usage
Full Domain Scan
python3 Subtakover.py -d example.com

## Scan Single Subdomain

python3 Subtakover.py -s blog.example.com

## Scan Subdomain List (with Threads)

python3 Subtakover.py -l subdomains.txt --threads 15

## Output Files

subs_temp.txt: Raw subdomains from subfinder
404_subdomains.txt: Subdomains with 404 responses
takeover_report.txt: Final report of possible takeovers


##  Disclaimer
This tool is created for educational and authorized testing purposes only.
Do not use it on targets you do not own or have permission to test.

## Contributing
Pull requests are welcome. For major changes, open an issue first to discuss what you'd like to change.
