# 🛡️ ASM Sentinel - Attack Surface Management Platform

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://python.org)
[![Security](https://img.shields.io/badge/security-ASM-red)](https://github.com)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey)](https://github.com)

ASM Sentinel is a professional Attack Surface Management platform that continuously discovers, monitors, and assesses your organization's external attack surface.

## 📋 Table of Contents
- [Features](#-features)
- [Quick Start](#-quick-start)
- [Installation Guide](#-installation-guide)
  - [Linux Installation](#linux-installation)
  - [macOS Installation](#macos-installation)
  - [Windows Installation (WSL2)](#windows-installation-wsl2)
  - [Docker Installation](#docker-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Architecture](#-architecture)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

## 🚀 Features

- **Asset Discovery** - Find domains, subdomains, and IPs using multiple sources (crt.sh, DNS, Subfinder)
- **Port Scanning** - Discover exposed services and ports with customizable port ranges
- **Technology Detection** - Identify software stacks, frameworks, and CMS platforms
- **SSL/TLS Monitoring** - Track certificate expiry, weak ciphers, and certificate changes
- **Cloud Exposure Detection** - Find exposed S3 buckets, Azure blobs, and GCP storage
- **Vulnerability Intelligence** - Map technologies to known CVEs from NVD and CISA KEV
- **Risk Scoring** - Automated risk assessment with customizable weight system
- **Real-time Dashboard** - Web-based monitoring interface with live updates
- **Automated Reports** - Daily HTML and text reports with actionable insights
- **Change Detection** - Track new assets, open ports, and configuration changes
- **Alerting System** - Slack, Email, and webhook notifications for critical findings

## 📊 Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/asm-sentinel.git
cd asm-sentinel

# Run automated setup (recommended)
chmod +x setup.sh
./setup.sh

# Or manual setup
pip install -r requirements.txt
python main.py --scan
