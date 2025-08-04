---

````
# 🔎 Subtakover

**Subtakover** is a powerful subdomain takeover detection tool built for bug bounty hunters and security researchers. It automates subdomain enumeration, filters 404 responses, and matches known fingerprints of third-party services that are commonly vulnerable to takeovers.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

---

## ✨ Features

- 🔍 Fast subdomain enumeration using [subfinder](https://github.com/projectdiscovery/subfinder)
- 🚫 Filters out subdomains with HTTP `404` responses
- 🔎 Detects fingerprints of vulnerable third-party services (e.g., GitHub, AWS, Bitbucket, etc.)
- 🧵 Supports multi-threaded scanning for large subdomain lists
- 📝 Generates detailed reports with CNAME, service, status, ASN, and registrar information

---

## 🛠️ Installation

Make sure you have the following tools and dependencies installed:
````

```bash
# Install required Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Install Python dependencies
pip install -r requirements.txt
````


Required Python modules:

```bash
pip install ipwhois dnspython python-whois requests
```

---

## ⚙️ Usage

### Full Domain Scan

```bash
python3 Subtakover.py -d example.com
```

### Scan Single Subdomain

```bash
python3 Subtakover.py -s blog.example.com
```

### Scan Subdomain List (with Threads)

```bash
python3 Subtakover.py -l subdomains.txt --threads 15
```

---

## 📁 Output Files

| File                  | Description                         |
| --------------------- | ----------------------------------- |
| `subs_temp.txt`       | Raw subdomains from Subfinder       |
| `404_subdomains.txt`  | Subdomains returning HTTP 404       |
| `takeover_report.txt` | Final report with takeover analysis |

---

## 📸 Demo

![Subtakover Demo](sub.PNG)

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## ⚠️ Disclaimer

This tool is created for **educational and authorized testing** purposes only.
**Do not use it on targets you do not own or have explicit permission to test.**

---

## 🤝 Contributing

Pull requests are welcome.
For major changes, open an issue first to discuss what you’d like to change or improve.

---

## 👤 Author

**iamzeropoison**
GitHub: [@iamzeropoison](https://github.com/iamzeropoison)

````
