# 🐞 Bug Bounty Recon Automation Framework | Python

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://python.org)
[![Security](https://img.shields.io/badge/security-Bug%20Bounty-red)](#)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey)](#)

A powerful Python-based reconnaissance automation framework designed for bug bounty hunters, penetration testers, and security researchers. The framework streamlines the reconnaissance phase by automating asset discovery, subdomain enumeration, technology fingerprinting, port scanning, screenshot collection, and vulnerability reconnaissance.

## 🚀 Features

| Category                  | Features                                                                   |
| ------------------------- | -------------------------------------------------------------------------- |
| **Subdomain Enumeration** | Passive & active discovery, Certificate Transparency logs, DNS brute-force |
| **DNS Reconnaissance**    | DNS records extraction, Zone transfer checks, Resolver validation          |
| **Port Scanning**         | Fast TCP port scanning, Service detection, Banner grabbing                 |
| **Web Recon**             | HTTP probing, Technology fingerprinting, Security header analysis          |
| **Content Discovery**     | Directory & file enumeration, JavaScript collection                        |
| **Screenshot Collection** | Automated screenshots of live assets                                       |
| **JavaScript Analysis**   | Endpoint extraction, Secret discovery, Sensitive data detection            |
| **URL Collection**        | Historical URLs, Parameter discovery, Archive enumeration                  |
| **Cloud Enumeration**     | S3 bucket discovery, Azure blob detection, GCP storage identification      |
| **Reporting**             | JSON, CSV, and HTML reports with categorized findings                      |
| **Automation**            | One-command reconnaissance workflow and scheduled scans                    |

## 📊 Quick Start

```bash
# Clone the repository
git clone https://github.com/Prakash586/Bug-Bounty-Recon-Automation-Framework.git

# Navigate to project directory
cd bug-bounty-recon

# Install dependencies
pip install -r requirements.txt

# Run recon against a target
python main.py -d example.com

# Run full reconnaissance workflow
python main.py -d example.com --full

# View results
ls output/
```

## 🎯 Recon Workflow

```text
Target Domain
      │
      ▼
Subdomain Enumeration
      │
      ▼
Live Host Detection
      │
      ▼
Port Scanning
      │
      ▼
Technology Detection
      │
      ▼
Screenshot Collection
      │
      ▼
JavaScript Analysis
      │
      ▼
URL & Parameter Discovery
      │
      ▼
Report Generation
```

## 📁 Output Structure

```text
output/
├── subdomains.txt
├── live_hosts.txt
├── ports.txt
├── technologies.json
├── screenshots/
├── js_files.txt
├── urls.txt
├── parameters.txt
└── report.html
```

## 🛠️ Use Cases

* Bug Bounty Hunting
* Attack Surface Mapping
* External Asset Discovery
* Red Team Reconnaissance
* Web Application Assessments
* Continuous Security Monitoring

