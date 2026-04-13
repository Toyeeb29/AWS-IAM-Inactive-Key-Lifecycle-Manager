# Lab 2: Inactive Key Rotation Check

## Overview

This lab teaches GRC engineers how to automate the detection of IAM access keys that are older than 90 days or unused. You'll build a comprehensive key lifecycle management tool that generates detailed remediation reports for compliance teams, with intelligent risk classification and actionable recommendations.

## Why This Matters

Stale access keys represent a significant security risk and are a common finding in security audits. Auditors require evidence that organizations actively manage key rotation and deactivate unused credentials. This lab automates the identification of non-compliant keys and provides specific remediation guidance.

## Control Mapping

- **SOC 2 CC6.1** – Restriction of logical access
- **NIST 800-53 IA-4** – Identifier management

## Learning Objectives

By completing this lab, you will:

1. Query IAM for all users and their access keys programmatically
2. Detect unused or stale keys based on configurable thresholds
3. Classify keys by risk level with intelligent analysis
4. Build comprehensive remediation reports with specific recommendations
5. Understand key lifecycle management best practices for compliance

## Prerequisites

- AWS CLI configured with appropriate permissions
- Python 3.9+ installed
- Basic familiarity with AWS IAM and access keys
- Understanding of virtual environments
- Windsurf IDE (download at: https://windsurf.com/refer?referral_code=l8ckp786a0dhgm96)

## Lab Setup Guide

### Step 1: Download and Setup Lab Files

1. **Download the lab files** from the provided ZIP archive
2. **Extract the ZIP file** to a new folder on your local machine (e.g., `GRC_Labs`)
3. **Open Windsurf IDE** and create a new workspace
4. **Open the lab folder** in Windsurf IDE:
   ```
   File → Open Folder → Navigate to extracted folder → 
   Select: lab-2-inactive-key-rotation
   ```
5. **Navigate to the lab directory** in your terminal:
   ```bash
   cd /path/to/your/extracted/folder/lab-2-inactive-key-rotation
   ```

### Step 2: Create and Activate Virtual Environment

**Why use a virtual environment?**
Virtual environments isolate Python dependencies, preventing conflicts between different projects and ensuring consistent, reproducible environments.

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate

# On Windows:
# venv\Scripts\activate

# Verify activation (you should see (venv) in your prompt)
which python
```

### Step 3: Install Dependencies

```bash
# Install required packages
pip install boto3

# Verify installation
pip list
```

### Step 4: Configure AWS Authentication

Choose one of the following methods:

#### Option A: AWS SSO/Identity Center (Recommended)
```bash
# Configure SSO
aws configure sso

# Test connection
aws sts get-caller-identity --profile your-profile-name
```

#### Option B: Traditional AWS CLI
```bash
# Configure credentials
aws configure

# Test connection
aws sts get-caller-identity
```

## Required AWS Permissions

Your AWS credentials need the following IAM permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:ListUsers",
                "iam:ListAccessKeys",
                "iam:GetAccessKeyLastUsed",
                "iam:GetLoginProfile"
            ],
            "Resource": "*"
        }
    ]
}
```

## Running the Lab

### Basic Usage

```bash
# Activate virtual environment (if not already active)
source venv/bin/activate

# Run with default credentials and thresholds
python inactive_key_checker.py

# Run with specific AWS profile
python inactive_key_checker.py --profile your-profile-name

# Run with custom thresholds
python inactive_key_checker.py --profile your-profile-name --key-age-threshold 60 --last-used-threshold 30
```

### Command Line Options

```bash
python inactive_key_checker.py --help
```

**Available options:**
- `--profile`: AWS profile name for authentication
- `--region`: AWS region (default: us-east-1)
- `--key-age-threshold`: Maximum key age in days (default: 90)
- `--last-used-threshold`: Maximum days since last use (default: 90)
- `--output-dir`: Directory for output files (default: current directory)

## Understanding the Results

### Risk Classification System

The script uses intelligent risk classification:

**CRITICAL Risk:**
- Keys >180 days old and never used
- Keys unused for >120 days

**HIGH Risk:**
- Keys >90 days old and never used
- Keys unused for >90 days

**MEDIUM Risk:**
- Keys >60 days old
- Keys unused for >60 days

**LOW Risk:**
- Keys >30 days old but recently used

**COMPLIANT:**
- Recent keys with active usage

### Sample Output

```
📊 Analysis complete:
  - Total users: 5
  - Users with keys: 5
  - Total keys: 6
  - Critical risk: 1
  - High risk: 0
  - Compliance rate: 16.67%
```

## Generated Reports

The script produces two comprehensive files:

### 1. JSON Report (`inactive_key_analysis_report.json`)
Detailed technical report including:
- Complete key analysis for each user
- Risk classifications with justifications
- Last used service and region information
- Compliance assessment against SOC 2 and NIST standards

### 2. CSV Summary (`inactive_key_summary.csv`)
Audit-ready summary with:
- Executive summary statistics
- High-risk findings requiring immediate attention
- Prioritized recommendations for security teams
- Actionable remediation steps

## Testing the Lab

### Test with Your AWS Account
```bash
python inactive_key_checker.py --profile your-profile-name
```

### Create Test Scenario (Optional)
```bash
# Create test user with access key
aws iam create-user --user-name test-key-user --profile your-profile-name

# Create access key
aws iam create-access-key --user-name test-key-user --profile your-profile-name

# Re-run assessment to see new key
python inactive_key_checker.py --profile your-profile-name

# Clean up test resources
aws iam delete-access-key --user-name test-key-user --access-key-id AKIA... --profile your-profile-name
aws iam delete-user --user-name test-key-user --profile your-profile-name
```

## Success Criteria

- [ ] Virtual environment created and activated successfully
- [ ] Dependencies installed without conflicts
- [ ] Script connects to AWS account successfully
- [ ] All IAM users and access keys retrieved
- [ ] Risk classification applied correctly
- [ ] Last used dates analyzed accurately
- [ ] Reports generated in required formats
- [ ] Recommendations are actionable and prioritized

## Troubleshooting

### Virtual Environment Issues
```bash
# If activation fails
which python3
python3 -m venv --help

# If pip install fails
pip install --upgrade pip
pip install boto3 --verbose
```

### AWS Authentication Issues
```bash
# Check AWS configuration
aws configure list
aws sts get-caller-identity

# For SSO profiles
aws sso login --profile your-profile-name
```

### Permission Issues
```bash
# Test specific permissions
aws iam list-users --max-items 1 --profile your-profile-name
aws iam list-access-keys --user-name your-username --profile your-profile-name
```

### Common Error Messages

**"No module named 'boto3'"**
- Ensure virtual environment is activated
- Run `pip install boto3`

**"Profile not found"**
- Check profile name: `aws configure list-profiles`
- Verify SSO login: `aws sso login --profile profile-name`

**"Access denied"**
- Verify IAM permissions listed above
- Check if you're using the correct AWS account

**"Rate limiting"**
- Script includes built-in handling for large accounts
- Consider running during off-peak hours for very large environments

## Compliance Interpretation

### For Auditors

**Key Findings to Review:**
- **Critical Risk Keys**: Require immediate rotation or deletion
- **Never Used Keys**: May indicate over-provisioning or forgotten test accounts
- **Compliance Rate**: Overall percentage of compliant keys
- **User Patterns**: Identify users with multiple old keys

**Evidence Documentation:**
- JSON report provides complete technical details
- CSV summary offers executive-level metrics
- Recommendations include specific remediation steps
- Timestamps ensure audit trail accuracy

### Risk Prioritization

1. **Immediate Action** (Critical/High): Keys requiring rotation within 7 days
2. **Planned Remediation** (Medium): Keys requiring attention within 30 days
3. **Monitoring** (Low): Keys to watch for future rotation cycles
4. **Compliant**: Keys meeting current standards

## Advanced Features

The script includes several advanced capabilities:

- **Console Access Detection**: Identifies users with both programmatic and console access
- **Service Usage Tracking**: Shows which AWS services last used each key
- **Regional Analysis**: Identifies where keys were last used geographically
- **Never-Used Key Detection**: Flags keys that have never been utilized
- **Configurable Thresholds**: Allows customization for different compliance requirements

## Next Steps

After completing this lab:

1. **Review Critical Findings**: Address any critical or high-risk keys immediately
2. **Establish Rotation Procedures**: Create processes for regular key rotation
3. **Implement Monitoring**: Schedule regular assessments (monthly recommended)
4. **Document Exceptions**: Create justifications for any keys that cannot be rotated
5. **Proceed to Lab 3**: Continue with Logging and Monitoring Validation
6. **Automate Remediation**: Consider implementing automated key rotation for service accounts

## Real-World Application

This lab addresses common audit questions:
- "How do you ensure access keys are rotated regularly?"
- "What controls prevent the use of stale credentials?"
- "Can you demonstrate proactive key lifecycle management?"

The generated reports provide concrete evidence of key management practices and identify specific remediation actions, making them ideal for compliance documentation and security team workflows.

## Cleanup

When finished with the lab:

```bash
# Deactivate virtual environment
deactivate

# Optional: Remove virtual environment
rm -rf venv

# Keep generated reports for audit evidence
ls *.json *.csv
```
