# ScanCLI

ScanCLI is a Python command-line scanner for authorized web security testing. It combines crawling, port scanning, and basic web vulnerability checks in one workflow so you can run quick educational assessments from a terminal.

## Features

- Internal link crawling for target discovery
- Port scanning with Nmap and socket fallback
- Basic SQL injection error detection
- Basic reflected XSS detection using baseline comparison
- JSON export for scan results
- Configurable timeout, page limits, and custom User-Agent
- Verbose and quiet modes for cleaner terminal usage

## Requirements

- Python 3.10+
- pip
- Nmap optional but recommended for richer port scan results

## Installation

```bash
git clone https://github.com/Vedansh-max/ScanCLI.git
cd ScanCLI
pip install -r requirements.txt
```

## Usage

```bash
python app.py <target> --scan <modules> [options]
```

## Examples

Run a crawl and SQLi scan:

```bash
python app.py http://testphp.vulnweb.com --scan crawler sqli
```

Run all modules with JSON output:

```bash
python app.py https://example.com --scan crawler port sqli xss --output reports/scan.json
```

Run a deeper port scan with a custom timeout:

```bash
python app.py https://example.com --scan port --port-mode deep --timeout 20
```

## Options

- `--scan`: one or more modules from `crawler`, `port`, `sqli`, `xss`
- `--port-mode`: `fast`, `normal`, or `deep`
- `--timeout`: request and scan timeout in seconds
- `--max-pages`: maximum number of internal pages to crawl
- `--user-agent`: custom HTTP User-Agent string
- `--output`: write scan results to a JSON file
- `--verbose`: print detailed progress logs
- `--quiet`: minimize progress logs and show the final summary

## Output

ScanCLI prints a summary to the terminal and can optionally write structured JSON output for later review or automation.

## Ethical Use

Use this tool only against systems you own or are explicitly authorized to test. Do not scan third-party systems without permission.

## Roadmap

- richer HTML reporting
- better service fingerprinting
- improved crawler depth and filtering rules
- tests and CI
- plugin-style module expansion
