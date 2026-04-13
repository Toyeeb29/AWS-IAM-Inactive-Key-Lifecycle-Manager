#!/usr/bin/env python3
"""
AWS Inactive Key Rotation Check Tool
===================================

This script automates the detection of IAM access keys that are older than 90 days or unused.
It generates comprehensive remediation reports for compliance teams.

Control Mappings:
- SOC 2 CC6.1: Restriction of logical access
- NIST 800-53 IA-4: Identifier management
"""

import boto3
import json
import csv
import argparse
import sys
from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound


class InactiveKeyChecker:
    """
    A comprehensive AWS access key lifecycle management checker.
    
    This class handles the detection of stale, unused, or non-compliant access keys
    and generates detailed remediation reports for security teams.
    """
    
    def __init__(self, profile_name=None, region='us-east-1', key_age_threshold=90, last_used_threshold=90):
        """
        Initialize the inactive key checker.
        
        Args:
            profile_name (str, optional): AWS profile name to use for authentication
            region (str): AWS region to use (default: us-east-1)
            key_age_threshold (int): Maximum key age in days (default: 90)
            last_used_threshold (int): Maximum days since last use (default: 90)
        """
        self.profile_name = profile_name
        self.region = region
        self.key_age_threshold = key_age_threshold
        self.last_used_threshold = last_used_threshold
        
        # Required AWS permissions: iam:ListUsers, iam:ListAccessKeys, iam:GetAccessKeyLastUsed
        self.session = None
        self.iam_client = None
        self.account_id = None
        
        # Risk classification thresholds
        self.risk_thresholds = {
            'critical': {'age_days': 180, 'unused_days': 120},  # Very old and unused
            'high': {'age_days': 90, 'unused_days': 90},        # Standard threshold
            'medium': {'age_days': 60, 'unused_days': 60},      # Warning threshold
            'low': {'age_days': 30, 'unused_days': 30}          # Recent but worth monitoring
        }
        
    def initialize_aws_session(self):
        """
        Initialize AWS session with optional profile support.
        
        Returns:
            bool: True if session initialized successfully, False otherwise
        """
        try:
            # Create session with optional profile
            if self.profile_name:
                print(f"🔐 Initializing AWS session with profile: {self.profile_name}")
                self.session = boto3.Session(profile_name=self.profile_name, region_name=self.region)
            else:
                print("🔐 Initializing AWS session with default credentials")
                self.session = boto3.Session(region_name=self.region)
            
            # Create IAM client
            self.iam_client = self.session.client('iam')
            
            # Get account ID for reporting
            sts_client = self.session.client('sts')
            caller_identity = sts_client.get_caller_identity()
            self.account_id = caller_identity['Account']
            
            print(f"✅ Successfully connected to AWS Account: {self.account_id}")
            return True
            
        except ProfileNotFound:
            print(f"❌ Error: AWS profile '{self.profile_name}' not found")
            print("💡 Available profiles can be listed with: aws configure list-profiles")
            return False
            
        except NoCredentialsError:
            print("❌ Error: No AWS credentials found")
            print("💡 Please configure AWS credentials using: aws configure")
            return False
            
        except Exception as e:
            print(f"❌ Error initializing AWS session: {str(e)}")
            return False
    
    def get_all_iam_users(self):
        """
        Retrieve all IAM users in the account.
        
        Returns:
            list: List of IAM user information
        """
        try:
            print("👥 Retrieving all IAM users...")
            
            users = []
            paginator = self.iam_client.get_paginator('list_users')
            
            for page in paginator.paginate():
                users.extend(page['Users'])
            
            print(f"✅ Found {len(users)} IAM users")
            return users
            
        except ClientError as e:
            print(f"❌ Error retrieving IAM users: {e.response['Error']['Message']}")
            return []
        except Exception as e:
            print(f"❌ Unexpected error retrieving IAM users: {str(e)}")
            return []
    
    def get_user_access_keys(self, username):
        """
        Get all access keys for a specific user.
        
        Args:
            username (str): IAM username
            
        Returns:
            list: List of access key information
        """
        try:
            response = self.iam_client.list_access_keys(UserName=username)
            return response['AccessKeyMetadata']
        except ClientError as e:
            print(f"⚠️  Error getting access keys for {username}: {e.response['Error']['Message']}")
            return []
    
    def get_access_key_last_used(self, access_key_id):
        """
        Get the last used information for an access key.
        
        Args:
            access_key_id (str): Access key ID
            
        Returns:
            dict: Last used information or None if never used
        """
        try:
            response = self.iam_client.get_access_key_last_used(AccessKeyId=access_key_id)
            return response['AccessKeyLastUsed']
        except ClientError as e:
            print(f"⚠️  Error getting last used info for {access_key_id}: {e.response['Error']['Message']}")
            return None
    
    def check_user_console_access(self, username):
        """
        Check if a user has console access (login profile).
        
        Args:
            username (str): IAM username
            
        Returns:
            bool: True if user has console access, False otherwise
        """
        try:
            self.iam_client.get_login_profile(UserName=username)
            return True
        except ClientError:
            return False  # No console access
    
    def calculate_key_age(self, create_date):
        """
        Calculate the age of an access key in days.
        
        Args:
            create_date (datetime): Key creation date
            
        Returns:
            int: Age in days
        """
        if isinstance(create_date, str):
            create_date = datetime.fromisoformat(create_date.replace('Z', '+00:00'))
        
        now = datetime.now(timezone.utc)
        age = now - create_date
        return age.days
    
    def calculate_days_since_last_used(self, last_used_date):
        """
        Calculate days since access key was last used.
        
        Args:
            last_used_date (datetime or None): Last used date
            
        Returns:
            int or None: Days since last used, or None if never used
        """
        if last_used_date is None:
            return None
        
        if isinstance(last_used_date, str):
            last_used_date = datetime.fromisoformat(last_used_date.replace('Z', '+00:00'))
        
        now = datetime.now(timezone.utc)
        days_since = now - last_used_date
        return days_since.days
    
    def classify_key_risk(self, key_age_days, days_since_last_used, never_used=False):
        """
        Classify the risk level of an access key.
        
        Args:
            key_age_days (int): Age of the key in days
            days_since_last_used (int or None): Days since last used
            never_used (bool): Whether the key has never been used
            
        Returns:
            str: Risk level (CRITICAL, HIGH, MEDIUM, LOW, COMPLIANT)
        """
        # Critical: Very old keys that are unused or never used
        if never_used and key_age_days >= self.risk_thresholds['critical']['age_days']:
            return 'CRITICAL'
        
        if (days_since_last_used is not None and 
            days_since_last_used >= self.risk_thresholds['critical']['unused_days']):
            return 'CRITICAL'
        
        # High: Keys exceeding standard thresholds
        if never_used and key_age_days >= self.risk_thresholds['high']['age_days']:
            return 'HIGH'
        
        if (days_since_last_used is not None and 
            days_since_last_used >= self.risk_thresholds['high']['unused_days']):
            return 'HIGH'
        
        # Medium: Keys approaching thresholds
        if key_age_days >= self.risk_thresholds['medium']['age_days']:
            return 'MEDIUM'
        
        if (days_since_last_used is not None and 
            days_since_last_used >= self.risk_thresholds['medium']['unused_days']):
            return 'MEDIUM'
        
        # Low: Recent keys but worth monitoring
        if key_age_days >= self.risk_thresholds['low']['age_days']:
            return 'LOW'
        
        # Compliant: Recent and actively used
        return 'COMPLIANT'
    
    def generate_recommendation(self, risk_level, key_age_days, days_since_last_used, never_used, username):
        """
        Generate specific remediation recommendation for a key.
        
        Args:
            risk_level (str): Risk classification
            key_age_days (int): Age of key in days
            days_since_last_used (int or None): Days since last used
            never_used (bool): Whether key was never used
            username (str): IAM username
            
        Returns:
            str: Specific recommendation
        """
        if risk_level == 'CRITICAL':
            if never_used:
                return f"Delete unused key immediately (created {key_age_days} days ago, never used)"
            else:
                return f"Rotate key immediately (last used {days_since_last_used} days ago)"
        
        elif risk_level == 'HIGH':
            if never_used:
                return f"Delete or activate key (created {key_age_days} days ago, never used)"
            else:
                return f"Schedule key rotation within 7 days (last used {days_since_last_used} days ago)"
        
        elif risk_level == 'MEDIUM':
            return f"Plan key rotation within 30 days (age: {key_age_days} days)"
        
        elif risk_level == 'LOW':
            return f"Monitor key usage (age: {key_age_days} days)"
        
        else:
            return "Key is compliant - continue monitoring"
    
    def analyze_all_access_keys(self):
        """
        Analyze all access keys in the account for compliance.
        
        Returns:
            dict: Comprehensive analysis results
        """
        print("🔍 Starting comprehensive access key analysis...")
        
        # Get all users
        users = self.get_all_iam_users()
        if not users:
            print("⚠️  No IAM users found or unable to retrieve users")
            return None
        
        analysis_results = {
            'summary': {
                'total_users': len(users),
                'users_with_keys': 0,
                'total_keys': 0,
                'critical_keys': 0,
                'high_risk_keys': 0,
                'medium_risk_keys': 0,
                'low_risk_keys': 0,
                'compliant_keys': 0,
                'never_used_keys': 0
            },
            'user_analysis': [],
            'high_risk_findings': [],
            'recommendations': []
        }
        
        # Analyze each user
        for user in users:
            username = user['UserName']
            user_created = user['CreateDate']
            
            # Check console access
            has_console_access = self.check_user_console_access(username)
            
            # Get access keys
            access_keys = self.get_user_access_keys(username)
            
            if not access_keys:
                # User has no access keys
                user_info = {
                    'username': username,
                    'user_created': user_created.isoformat(),
                    'has_console_access': has_console_access,
                    'access_keys': [],
                    'key_count': 0,
                    'highest_risk_level': 'NO_KEYS'
                }
                analysis_results['user_analysis'].append(user_info)
                continue
            
            # User has access keys
            analysis_results['summary']['users_with_keys'] += 1
            analysis_results['summary']['total_keys'] += len(access_keys)
            
            user_keys = []
            user_highest_risk = 'COMPLIANT'
            
            # Analyze each access key
            for key_metadata in access_keys:
                access_key_id = key_metadata['AccessKeyId']
                key_status = key_metadata['Status']
                key_created = key_metadata['CreateDate']
                
                # Calculate key age
                key_age_days = self.calculate_key_age(key_created)
                
                # Get last used information
                last_used_info = self.get_access_key_last_used(access_key_id)
                
                if last_used_info and 'LastUsedDate' in last_used_info:
                    last_used_date = last_used_info['LastUsedDate']
                    days_since_last_used = self.calculate_days_since_last_used(last_used_date)
                    never_used = False
                    last_used_service = last_used_info.get('ServiceName', 'Unknown')
                    last_used_region = last_used_info.get('Region', 'Unknown')
                else:
                    last_used_date = None
                    days_since_last_used = None
                    never_used = True
                    last_used_service = None
                    last_used_region = None
                    analysis_results['summary']['never_used_keys'] += 1
                
                # Classify risk
                risk_level = self.classify_key_risk(key_age_days, days_since_last_used, never_used)
                
                # Update summary counts
                if risk_level == 'CRITICAL':
                    analysis_results['summary']['critical_keys'] += 1
                elif risk_level == 'HIGH':
                    analysis_results['summary']['high_risk_keys'] += 1
                elif risk_level == 'MEDIUM':
                    analysis_results['summary']['medium_risk_keys'] += 1
                elif risk_level == 'LOW':
                    analysis_results['summary']['low_risk_keys'] += 1
                else:
                    analysis_results['summary']['compliant_keys'] += 1
                
                # Track highest risk for user
                risk_priority = {'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'COMPLIANT': 1}
                if risk_priority.get(risk_level, 0) > risk_priority.get(user_highest_risk, 0):
                    user_highest_risk = risk_level
                
                # Generate recommendation
                recommendation = self.generate_recommendation(
                    risk_level, key_age_days, days_since_last_used, never_used, username
                )
                
                # Create key analysis
                key_analysis = {
                    'access_key_id': access_key_id,
                    'status': key_status,
                    'created_date': key_created.isoformat(),
                    'age_days': key_age_days,
                    'last_used_date': last_used_date.isoformat() if last_used_date else None,
                    'days_since_last_used': days_since_last_used,
                    'never_used': never_used,
                    'last_used_service': last_used_service,
                    'last_used_region': last_used_region,
                    'risk_level': risk_level,
                    'recommendation': recommendation
                }
                
                user_keys.append(key_analysis)
                
                # Add to high-risk findings if applicable
                if risk_level in ['CRITICAL', 'HIGH']:
                    analysis_results['high_risk_findings'].append({
                        'username': username,
                        'access_key_id': access_key_id,
                        'risk_level': risk_level,
                        'age_days': key_age_days,
                        'days_since_last_used': days_since_last_used,
                        'never_used': never_used,
                        'recommendation': recommendation
                    })
                
                # Add to recommendations
                if risk_level != 'COMPLIANT':
                    analysis_results['recommendations'].append({
                        'priority': risk_level,
                        'username': username,
                        'access_key_id': access_key_id,
                        'issue': f"Key is {risk_level.lower()} risk",
                        'recommendation': recommendation
                    })
            
            # Add user analysis
            user_info = {
                'username': username,
                'user_created': user_created.isoformat(),
                'has_console_access': has_console_access,
                'access_keys': user_keys,
                'key_count': len(access_keys),
                'highest_risk_level': user_highest_risk
            }
            analysis_results['user_analysis'].append(user_info)
        
        # Calculate compliance metrics
        total_keys = analysis_results['summary']['total_keys']
        if total_keys > 0:
            compliant_keys = analysis_results['summary']['compliant_keys']
            compliance_rate = round((compliant_keys / total_keys) * 100, 2)
        else:
            compliance_rate = 100
        
        analysis_results['summary']['compliance_rate'] = compliance_rate
        
        print(f"📊 Analysis complete:")
        print(f"  - Total users: {analysis_results['summary']['total_users']}")
        print(f"  - Users with keys: {analysis_results['summary']['users_with_keys']}")
        print(f"  - Total keys: {total_keys}")
        print(f"  - Critical risk: {analysis_results['summary']['critical_keys']}")
        print(f"  - High risk: {analysis_results['summary']['high_risk_keys']}")
        print(f"  - Compliance rate: {compliance_rate}%")
        
        return analysis_results
    
    def generate_json_report(self, analysis_results):
        """
        Generate comprehensive JSON report for technical teams.
        
        Args:
            analysis_results (dict): Analysis results from analyze_all_access_keys
            
        Returns:
            dict: Complete JSON report
        """
        report = {
            'metadata': {
                'report_type': 'AWS Access Key Lifecycle Assessment',
                'account_id': self.account_id,
                'assessment_date': datetime.now(timezone.utc).isoformat(),
                'aws_region': self.region,
                'aws_profile': self.profile_name,
                'tool_version': '1.0',
                'thresholds': {
                    'key_age_threshold_days': self.key_age_threshold,
                    'last_used_threshold_days': self.last_used_threshold
                },
                'standards_evaluated': ['SOC 2 CC6.1', 'NIST 800-53 IA-4']
            },
            'analysis_results': analysis_results,
            'compliance_assessment': {
                'overall_status': self._determine_overall_compliance_status(analysis_results),
                'soc2_cc6_1_status': self._determine_soc2_status(analysis_results),
                'nist_ia_4_status': self._determine_nist_status(analysis_results)
            }
        }
        
        return report
    
    def _determine_overall_compliance_status(self, results):
        """Determine overall compliance status based on risk levels."""
        if results['summary']['critical_keys'] > 0:
            return 'NON_COMPLIANT'
        elif results['summary']['high_risk_keys'] > 0:
            return 'PARTIALLY_COMPLIANT'
        elif results['summary']['compliance_rate'] >= 90:
            return 'COMPLIANT'
        else:
            return 'PARTIALLY_COMPLIANT'
    
    def _determine_soc2_status(self, results):
        """Determine SOC 2 CC6.1 compliance status."""
        return self._determine_overall_compliance_status(results)
    
    def _determine_nist_status(self, results):
        """Determine NIST IA-4 compliance status."""
        return self._determine_overall_compliance_status(results)
    
    def save_json_report(self, report, filename='inactive_key_analysis_report.json'):
        """
        Save JSON report to file.
        
        Args:
            report (dict): JSON report data
            filename (str): Output filename
        """
        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            print(f"📄 JSON report saved: {filename}")
        except Exception as e:
            print(f"❌ Error saving JSON report: {str(e)}")
    
    def save_csv_report(self, analysis_results, filename='inactive_key_summary.csv'):
        """
        Save CSV summary report for security teams.
        
        Args:
            analysis_results (dict): Analysis results
            filename (str): Output filename
        """
        try:
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                
                # Header information
                writer.writerow(['AWS Access Key Lifecycle Assessment Summary'])
                writer.writerow(['Account ID', self.account_id])
                writer.writerow(['Assessment Date', datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')])
                writer.writerow(['Compliance Rate', f"{analysis_results['summary']['compliance_rate']}%"])
                writer.writerow([])
                
                # Summary statistics
                writer.writerow(['Summary Statistics'])
                writer.writerow(['Metric', 'Count'])
                writer.writerow(['Total Users', analysis_results['summary']['total_users']])
                writer.writerow(['Users with Keys', analysis_results['summary']['users_with_keys']])
                writer.writerow(['Total Keys', analysis_results['summary']['total_keys']])
                writer.writerow(['Critical Risk Keys', analysis_results['summary']['critical_keys']])
                writer.writerow(['High Risk Keys', analysis_results['summary']['high_risk_keys']])
                writer.writerow(['Medium Risk Keys', analysis_results['summary']['medium_risk_keys']])
                writer.writerow(['Never Used Keys', analysis_results['summary']['never_used_keys']])
                writer.writerow([])
                
                # High-risk findings
                writer.writerow(['High-Risk Access Keys Requiring Immediate Attention'])
                writer.writerow(['Username', 'Access Key ID', 'Risk Level', 'Age (Days)', 'Days Since Last Used', 'Never Used', 'Recommendation'])
                
                for finding in analysis_results['high_risk_findings']:
                    writer.writerow([
                        finding['username'],
                        finding['access_key_id'],
                        finding['risk_level'],
                        finding['age_days'],
                        finding['days_since_last_used'] if finding['days_since_last_used'] is not None else 'N/A',
                        'Yes' if finding['never_used'] else 'No',
                        finding['recommendation']
                    ])
                
                writer.writerow([])
                writer.writerow(['All Recommendations by Priority'])
                writer.writerow(['Priority', 'Username', 'Access Key ID', 'Issue', 'Recommendation'])
                
                # Sort recommendations by priority
                priority_order = {'CRITICAL': 1, 'HIGH': 2, 'MEDIUM': 3, 'LOW': 4}
                sorted_recommendations = sorted(
                    analysis_results['recommendations'],
                    key=lambda x: priority_order.get(x['priority'], 5)
                )
                
                for rec in sorted_recommendations:
                    writer.writerow([
                        rec['priority'],
                        rec['username'],
                        rec['access_key_id'],
                        rec['issue'],
                        rec['recommendation']
                    ])
            
            print(f"📊 CSV report saved: {filename}")
            
        except Exception as e:
            print(f"❌ Error saving CSV report: {str(e)}")
    
    def run_assessment(self):
        """
        Execute the complete access key lifecycle assessment.
        
        Returns:
            bool: True if assessment completed successfully, False otherwise
        """
        print("🚀 Starting AWS Access Key Lifecycle Assessment")
        print("=" * 60)
        
        # Initialize AWS session
        if not self.initialize_aws_session():
            return False
        
        # Analyze all access keys
        analysis_results = self.analyze_all_access_keys()
        if not analysis_results:
            print("❌ Failed to analyze access keys")
            return False
        
        # Generate reports
        print("\n📋 Generating compliance reports...")
        json_report = self.generate_json_report(analysis_results)
        
        # Save reports
        self.save_json_report(json_report)
        self.save_csv_report(analysis_results)
        
        # Print summary
        print("\n" + "=" * 60)
        print("📊 ASSESSMENT SUMMARY")
        print("=" * 60)
        print(f"Account ID: {self.account_id}")
        print(f"Total Users: {analysis_results['summary']['total_users']}")
        print(f"Total Access Keys: {analysis_results['summary']['total_keys']}")
        print(f"Critical Risk Keys: {analysis_results['summary']['critical_keys']}")
        print(f"High Risk Keys: {analysis_results['summary']['high_risk_keys']}")
        print(f"Never Used Keys: {analysis_results['summary']['never_used_keys']}")
        print(f"Compliance Rate: {analysis_results['summary']['compliance_rate']}%")
        
        overall_status = json_report['compliance_assessment']['overall_status']
        print(f"Overall Status: {overall_status}")
        print(f"SOC 2 CC6.1: {json_report['compliance_assessment']['soc2_cc6_1_status']}")
        print(f"NIST IA-4: {json_report['compliance_assessment']['nist_ia_4_status']}")
        
        if overall_status == 'COMPLIANT':
            print("✅ Access key management meets compliance requirements!")
        else:
            print("⚠️  Access key management requires attention - see recommendations above")
        
        return True


def main():
    """
    Main function to handle command-line arguments and execute the assessment.
    """
    parser = argparse.ArgumentParser(
        description='AWS Access Key Lifecycle Compliance Checker',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python inactive_key_checker.py
  python inactive_key_checker.py --profile production
  python inactive_key_checker.py --profile dev --key-age-threshold 60
  python inactive_key_checker.py --profile prod --last-used-threshold 30

This tool evaluates AWS access keys against SOC 2 and NIST 800-53 standards.
        """
    )
    
    parser.add_argument(
        '--profile',
        type=str,
        help='AWS profile name to use for authentication (optional)'
    )
    
    parser.add_argument(
        '--region',
        type=str,
        default='us-east-1',
        help='AWS region to use (default: us-east-1)'
    )
    
    parser.add_argument(
        '--key-age-threshold',
        type=int,
        default=90,
        help='Maximum key age in days before flagging (default: 90)'
    )
    
    parser.add_argument(
        '--last-used-threshold',
        type=int,
        default=90,
        help='Maximum days since last use before flagging (default: 90)'
    )
    
    parser.add_argument(
        '--output-dir',
        type=str,
        default='.',
        help='Directory to save output files (default: current directory)'
    )
    
    args = parser.parse_args()
    
    # Create checker instance
    checker = InactiveKeyChecker(
        profile_name=args.profile,
        region=args.region,
        key_age_threshold=args.key_age_threshold,
        last_used_threshold=args.last_used_threshold
    )
    
    # Run assessment
    success = checker.run_assessment()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
