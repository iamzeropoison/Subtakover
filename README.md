## 🛠️ Installation

Ensure you have the following tools and dependencies installed before using **Subtakover**:

### 🔧 Dependencies

Install the required external tools:

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Or install them manually if needed:

```bash
pip install ipwhois dnspython python-whois requests
```

---

## 🚀 Usage

### 🔍 Full Domain Scan

Scan all subdomains of a target domain and check for takeover possibilities:

```bash
python3 Subtakover.py -d example.com
```

### 🎯 Scan a Single Subdomain

```bash
python3 Subtakover.py -s blog.example.com
```

### 📂 Scan a List of Subdomains (with Threading)

```bash
python3 Subtakover.py -l subdomains.txt --threads 15
```

---

## 📄 Output Files

| File Name             | Description                                    |
| --------------------- | ---------------------------------------------- |
| `subs_temp.txt`       | Raw subdomains collected via **subfinder**     |
| `404_subdomains.txt`  | Subdomains returning **HTTP 404** response     |
| `takeover_report.txt` | Final report showing potential takeover status |

---

## ⚠️ Disclaimer

> This tool is intended **for educational purposes and authorized security testing only**.
> **Do not scan or attempt takeovers on domains you do not own or have explicit permission to test.**

---

## 🤝 Contributing

Pull requests are welcome!
For major changes, please open an issue first to discuss your ideas and proposed improvements.

---

Let me know if you'd like to add GitHub badges, screenshots, or contact info at the bottom.

