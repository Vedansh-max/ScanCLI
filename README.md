# 🔥 ScanCLI - Ethical Hacking CLI Tool

ScanCLI is a multi-threaded command-line based ethical hacking tool built in Python.  
It performs automated security testing including:

https://github.com/Vedansh-max/ScanCLI

- Web crawling
- Port scanning (Nmap + socket fallback)
- SQL Injection detection
- XSS vulnerability detection

---

## 🚀 Features

- ⚡ Fast multi-threaded scanning
- 🔍 Intelligent crawler (internal links only)
- 🛡 SQL Injection detection (error-based)
- 💉 XSS detection (reflected)
- 🌐 Port scanning using Nmap + fallback
- 📊 CLI-based output (Kali Linux ready)

---

## 📁 Project Structure
project/
│
├── cli.py # CLI entry point
├── scanner_engine.py # Core controller
│
├── scanner/
│ ├── init.py
│ ├── crawler.py
│ ├── portscan.py
│ ├── sqli.py
│ ├── xss.py
│
├── payloads/
│ ├── sqli.txt
│ ├── xss.txt
│
├── requirements.txt
└── README.md


---

## ⚙️ Installation

### 1. Clone the project
git clone https://github.com/Vedansh-max/ScanCLI
cd ScanCLI

### 2. Install dependencies

pip install -r requirements.txt


### 3. Install Nmap (Required)

sudo apt install nmap


---

## 🧠 Usage

### Basic command:


python cli.py <target> --scan <modules>


---

### Examples:

#### Crawl + SQLi scan

python cli.py http://testphp.vulnweb.com --scan crawler sqli


#### Full scan

python cli.py http://example.com --scan crawler port sqli xss


#### Port scan (deep)

python cli.py http://example.com --scan port --port-mode deep


---

## ⚡ Available Scan Modules

| Module   | Description                  |
|---------|------------------------------|
| crawler | Finds internal URLs          |
| port    | Scans open ports             |
| sqli    | Detects SQL Injection        |
| xss     | Detects XSS vulnerabilities  |

---

## 🔧 Options


--scan Select scan modules
--port-mode fast / normal / deep


---

## 📊 Sample Output


[+] Scanning example.com
[✓] Found 3 open ports

[VULN] SQLi → id parameter vulnerable
[VULN] XSS → search parameter vulnerable


---

## ⚠️ Disclaimer

This tool is developed for educational and ethical testing purposes only.  
Do NOT use this tool on systems without proper authorization.

---

## 🧑‍💻 Author

- Vedansh Sharma

---

## ⭐ Future Improvements

- JSON output export
- GUI version
- Advanced payloads
- Authentication bypass testing
- Subdomain scanning

---

## 🏁 Final Note

This project is designed to simulate real-world penetration testing workflo
