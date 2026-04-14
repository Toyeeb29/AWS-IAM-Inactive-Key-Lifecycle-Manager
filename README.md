# AWS IAM Inactive Key Lifecycle Manager

> Automated access key risk assessment with SOC 2 & NIST IA-4 compliance reporting — built for GRC Engineering workflows.

![Python](https://img.shields.io/badge/Python-3.13-blue?style=flat-square&logo=python)
![boto3](https://img.shields.io/badge/boto3-1.40.38-orange?style=flat-square&logo=amazonaws)
![SOC2](https://img.shields.io/badge/SOC_2-CC6.1-purple?style=flat-square)
![NIST](https://img.shields.io/badge/NIST-IA--4-purple?style=flat-square)
![moto](https://img.shields.io/badge/tested_with-moto_%26_pytest-green?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square)

---

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Architecture](#architecture)
4. [Getting Started](#getting-started)
5. [Usage & Flags](#usage--flags)
6. [Sample Output](#sample-output)
8. [Disclaimer](#disclaimer)

---

## Overview

IAM access keys are one of the most commonly misconfigured attack surfaces in AWS environments. This tool provides automated discovery, risk scoring, and compliance reporting for all IAM user access keys across an AWS account — enabling GRC, Security, and Cloud teams to maintain continuous visibility into key hygiene.

Designed to align with **SOC 2 CC6.1** (logical access controls) and **NIST SP 800-53 IA-4** (identifier management), this project demonstrates a repeatable, policy-driven approach to credential lifecycle management.

---

## Features

| Feature | Description |
|---------|-------------|
| **Full IAM key enumeration** | Scans all IAM users and retrieves key metadata, last-used timestamps, and creation dates via the AWS SDK |
| **Configurable risk thresholds** | Classifies keys as Critical / High / Compliant based on age and inactivity — both thresholds are CLI-configurable |
| **JSON + CSV reporting** | Generates machine-readable JSON and human-readable CSV reports for audit trail and ticketing workflows |
| **Framework compliance mapping** | Maps each finding to SOC 2 CC6.1 and NIST IA-4 controls with a per-account compliance rate |
| **AWS SSO support** | Authenticates via AWS SSO named profiles — no hardcoded credentials required |

---

## Architecture

```
inactive-key-rotation/
├── inactive_key_checker.py           # Core scanner & risk engine
├── inactive_key_analysis_report.json # Generated JSON compliance report
├── inactive_key_summary.csv          # Generated CSV summary
├── tests/
│   └── test_inactive_key_checker.py
├── requirements.txt
└── README.md
```

---

## Getting Started

### Prerequisites

- Python 3.13
- AWS CLI configured with SSO or static credentials
- IAM permissions: `iam:ListUsers`, `iam:ListAccessKeys`, `iam:GetAccessKeyLastUsed`

### Installation

```bash
git clone https://github.com/Toyeeb29/AWS-IAM-Inactive-Key-Lifecycle-Manager.git


# Create and activate virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

### AWS SSO Authentication

```bash
# Configure SSO profile
aws configure sso

# Log in
aws sso login --profile Toyeeb

# Verify identity
aws sts get-caller-identity --profile Toyeeb
```

**Example verified output:**
```json
{
    "UserId": "AROAWWXFC3ZSPMC6KMBJB:Toyeeb",
    "Account": "461115678308",
    "Arn": "arn:aws:sts::461115678308:assumed-role/AWSReservedSSO_sso-t_7b5f64a31f3931a4/Toyeeb"
}
```

---

## Usage & Flags

```bash
python inactive_key_checker.py --profile <profile> [OPTIONS]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--profile` | AWS named profile (SSO or credentials file) | Required |
| `--key-age-threshold` | Days before a key is considered aged | `90` |
| `--last-used-threshold` | Days since last use before flagging inactive | `45` |

**Output files generated:**
- `inactive_key_analysis_report.json` — full JSON findings
- `inactive_key_summary.csv` — human-readable summary for audit tickets

**Basic scan:**
```bash
python inactive_key_checker.py --profile Toyeeb
```

**Scan with custom thresholds:**
```bash
python inactive_key_checker.py --profile Toyeeb --key-age-threshold 60 --last-used-threshold 30
```

---

## Sample Output

```
🚀 Starting AWS Access Key Lifecycle Assessment
============================================================
🔐 Initializing AWS session with profile: Toyeeb
✅ Successfully connected to AWS Account: 461115678308
🔍 Starting comprehensive access key analysis...
👥 Retrieving all IAM users...
✅ Found 3 IAM users

📊 Analysis complete:
  - Total users: 3
  - Users with keys: 2
  - Total keys: 3
  - Critical risk: 0
  - High risk: 2
  - Compliance rate: 0.0%

📋 Generating compliance reports...
📄 JSON report saved: inactive_key_analysis_report.json
📊 CSV report saved: inactive_key_summary.csv

============================================================
📊 ASSESSMENT SUMMARY
============================================================
Account ID:            461115678308
Total Users:           3
Total Access Keys:     3
Critical Risk Keys:    0
High Risk Keys:        2
Never Used Keys:       2
Compliance Rate:       0.0%
Overall Status:        PARTIALLY_COMPLIANT
SOC 2 CC6.1:           PARTIALLY_COMPLIANT
NIST IA-4:             PARTIALLY_COMPLIANT
⚠️  Access key management requires attention
```

---

## Output & Compliance Mapping

### Risk Classification

| Level | Criteria |
|-------|----------|
| 🔴 **Critical** | Key age > 180 days and never used |
| 🟡 **High** | Key age exceeds threshold OR unused beyond inactivity threshold |
| 🟢 **Compliant** | Active key within all policy thresholds |

### Compliance Controls

| Framework | Control | Description |
|-----------|---------|-------------|
| SOC 2 | CC6.1 | Logical and physical access controls |
| NIST SP 800-53 | IA-4 | Identifier management |

Compliance rate is calculated as the percentage of keys meeting all age and activity policy thresholds. A rate of 100% indicates full control adherence.

---

## Disclaimer

This project is built for educational and GRC portfolio purposes. Always validate findings against your organization's access key policies before taking any remediation action.

---

*Built as part of a GRC Engineering lab series.*
