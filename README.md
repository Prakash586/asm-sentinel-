# 🛡️ ASM Sentinel - Attack Surface Management Platform

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://python.org)
[![Security](https://img.shields.io/badge/security-ASM-red)](https://github.com/Prakash586/asm-sentinel)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey)](https://github.com/Prakash586/asm-sentinel)
[![GitHub stars](https://img.shields.io/github/stars/Prakash586/asm-sentinel)](https://github.com/Prakash586/asm-sentinel/stargazers)
[![GitHub issues](https://img.shields.io/github/issues/Prakash586/asm-sentinel)](https://github.com/Prakash586/asm-sentinel/issues)

**ASM Sentinel** is a professional, enterprise-grade Attack Surface Management platform that continuously discovers, monitors, and assesses your organization's external attack surface. Built for security teams, bug bounty hunters, and MSSPs.

## 📋 Table of Contents
- [Features](#-features)
- [Quick Start](#-quick-start)
- [Installation Guide](#-installation-guide)
  - [Linux (Ubuntu/Debian)](#linux-ubuntudebian)
  - [Linux (RHEL/CentOS/Fedora)](#linux-rhelcentosfedora)
  - [macOS](#macos)
  - [Windows (WSL2)](#windows-wsl2)
  - [Docker](#docker)
  - [Termux (Android)](#termux-android)
- [Configuration](#-configuration)
- [Usage Examples](#-usage-examples)
- [Architecture](#-architecture)
- [Output & Reports](#-output--reports)
- [Troubleshooting](#-troubleshooting)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)

## 🚀 Features

| Category | Features |
|----------|----------|
| **Asset Discovery** | Subdomain enumeration, DNS brute-force, crt.sh integration, Certificate Transparency logs |
| **Network Scanning** | Multi-threaded port scanning, Service detection, Banner grabbing |
| **Technology Detection** | Web server identification, Framework detection, CMS fingerprinting, Admin panel discovery |
| **Security Monitoring** | SSL/TLS certificate analysis, Weak cipher detection, Certificate expiry tracking |
| **Cloud Security** | Exposed S3 buckets, Azure blobs, GCP storage, Public repositories |
| **Vulnerability Intelligence** | NVD CVE lookup, CISA KEV catalog integration, Technology-CVE mapping |
| **Risk Assessment** | Customizable risk scoring, Priority-based remediation, Asset criticality ranking |
| **Visualization** | Real-time web dashboard, HTML/JSON reports, Historical trend analysis |
| **Alerting** | Slack integration, Email notifications, Critical finding alerts |
| **Automation** | Scheduled scans, Continuous monitoring, Change detection |

## 📊 Quick Start

```bash
# Clone the repository
git clone https://github.com/Prakash586/asm-sentinel.git
cd asm-sentinel

# Run automated installation (recommended)
chmod +x setup.sh
./setup.sh

# Configure your domains
nano config.yaml

# Run your first scan
python main.py --scan

# Start the web dashboard
python main.py --dashboard

# Open your browser to http://localhost:5000
