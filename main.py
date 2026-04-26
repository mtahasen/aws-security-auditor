from fastapi import FastAPI
import boto3
import os
from botocore.exceptions import ClientError
from datetime import datetime, timezone, timedelta
import json
import glob
from apscheduler.schedulers.background import BackgroundScheduler
from dotenv import load_dotenv

load_dotenv()

SOURCE_EMAIL = os.getenv("SOURCE_EMAIL")
IAM_USER_EMAILS = {
    "taha": os.getenv("TAHA_ALERT_EMAIL"),
    "root": os.getenv("ROOT_ALERT_EMAIL")
}

def should_send_notification(issue_id, cooldown_days=2):
    state_file = "notification_state.json"
    
    if not os.path.exists(state_file):
        with open(state_file, "w") as f: 
            json.dump({}, f)
            
    with open(state_file, "r") as f:
        notifications = json.load(f)
        
    last_sent = notifications.get(issue_id)
    
    if last_sent:
        last_sent_dt = datetime.fromisoformat(last_sent)
        if datetime.now() < last_sent_dt + timedelta(days=cooldown_days):
            return False
            
    notifications[issue_id] = datetime.now().isoformat()
    with open(state_file, "w") as f:
        json.dump(notifications, f, indent=4)
    return True

def send_ses_email(target_email, subject, body):
    ses_client = boto3.client('ses', region_name='eu-central-1') 
    
    try:
        response = ses_client.send_email(
            Source=SOURCE_EMAIL,
            Destination={'ToAddresses': [target_email]},
            Message={
                'Subject': {'Data': subject},
                'Body': {'Text': {'Data': body}}
            }
        )
        return True
    except Exception as e:
        print(f"SES email error: {str(e)}")
        return False

def save_report_to_disk(report_data):
    if not os.path.exists("reports"):
        os.makedirs("reports")
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"reports/scan_report_{timestamp}.json"

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(report_data, f, ensure_ascii=False, indent = 4)

    return filename

def cleanup_old_reports(max_files):
    list_of_files = glob.glob('reports/*.json')

    list_of_files.sort(key=os.path.getctime)

    while len(list_of_files) > max_files:
        oldest_file = list_of_files.pop(0)
        os.remove(oldest_file)
        print(f"Old report has been deleted: {oldest_file}")

def scheduled_scan_job():
    print("Background scan is starting...")
    scan_all_resources()
    cleanup_old_reports(max_files = 84)     # 12 scans per day for 7 days (every two hours), a total of 84 scans.
    print("The scan is complete and system has been cleaned.")

app = FastAPI(
    title="Infrastructure Security Auditor",
    description="Automated AWS Security Scanner API"
)

# Global clients
sts_client = boto3.client('sts')
s3_client = boto3.client('s3')
ec2_client = boto3.client('ec2')
iam_client = boto3.client('iam')

@app.get("/")
def read_root():
    return {"status": "success", "message": "Auditor Engine is running perfectly!"}

# AWS Connection Test Endpoint
@app.get("/aws-test")
def test_aws_connection():
    try:
        
        # Asking AWS to return the caller identity to verify connection and credentials
        identity = sts_client.get_caller_identity()
        
        return {
            "status": "Connection Successful!",
            "aws_account_id": identity["Account"],
            "iam_user": identity["Arn"]
        }
    except Exception as e:
        return {"status": "Connection Failed", "error_message": str(e)}
    
@app.get("/scan/s3")
def scan_s3_security():
    try:

        # Scan and list all s3 buckets in particular AWS account
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])

        scan_results = []

        # Audit each buckets security settings
        for bucket in buckets:
            bucket_name = bucket['Name']
            is_vulnerable = False
            risk_reasons = []


            # Check the "Public Access Block" setting of the bucket
            try:                
                pab = s3_client.get_public_access_block(Bucket = bucket_name)
                config = pab.get('PublicAccessBlockConfiguration', {})

                # Check if even one these four firewall is down, then there is a risk
                if not (config.get('BlockPublicAcls') and 
                        config.get('BlockPublicPolicy') and
                        config.get('IgnorePublicAcls') and
                        config.get('RestrictPublicBuckets')):
                    is_vulnerable = True
                    risk_reasons.append("Public Access Block is partially or fully disabled!") 
            
            except ClientError as e:
                # If the buckets these firewall settings never exist, then there is a risk by default
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    is_vulnerable = True
                    risk_reasons.append("No Public Access Block configuration found. High Risk!")

            # Check Encryption (KMS/AES-256)
            try:
                s3_client.get_bucket_encryption(Bucket = bucket_name)
            except ClientError as e:
                if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                    is_vulnerable = True
                    risk_reasons.append("Encryption is disabled. Data is in plaintext!")

            # Check Versioning (Ransomware Protection)
            try:
                versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                
                if versioning.get('Status') != 'Enabled':
                    is_vulnerable = True
                    risk_reasons.append("Versioning is disabled. High risk of data loss/ransomware!")
            except ClientError as e:
                is_vulnerable = True
                risk_reasons.append(f"Could not verify versioning: {str(e)}")
                    
            # Add results to report
            final_details = "Safe" if not is_vulnerable else " | ".join(risk_reasons)

            scan_results.append({
                "bucket_name": bucket_name,
                "is_vulnerable": is_vulnerable,
                "details": final_details
            })

        return {
            "status": "Scan Complete",
            "total_buckets_scanned": len(buckets),
            "findings": scan_results
        }
    except Exception as e:
        return {
            "status": "Error during scan",
            "error_message": str(e)
        }
    
@app.get("/scan/ec2")
def scan_ec2_security_groups():
    try:
        # Get all security groups (Firewall Rules) from AWS
        response = ec2_client.describe_security_groups()
        security_groups = response.get('SecurityGroups', [])

        findings = []

        # Check the security groups one by one
        for sg in security_groups:
            sg_name = sg.get('GroupName')
            sg_id = sg.get('GroupId')
            is_vulnerable = False
            risky_ports = []

            # Check the inbound rules inside the group
            for rule in sg.get('IpPermissions', []):
                from_port = rule.get('FromPort')
                to_port = rule.get('ToPort')
                ip_protocol = rule.get('IpProtocol')

                is_risky_port = False

                # Full traffic access status
                if ip_protocol == '-1':
                    # When you create a rule and choose "All Traffic", aws deletes from_port and to_port values
                    # and sets protocol number to '-1'. 
                    is_risky_port = True

                # If a specific port or port range has been entered
                elif from_port is not None and to_port is not None:
                    # Check Admin and Database ports in this range
                    target_ports = [22, 3389, 3306, 5432, 27017, 6379, 1433]
                    for port in target_ports:
                        if from_port <= port <= to_port:
                            is_risky_port = True
                            break

                # If these risky ports have been opened, check who they are for (IP address)
                if is_risky_port:
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            is_vulnerable = True
                            # Save the port info
                            port_info = f"{from_port}-{to_port}" if from_port else "ALL PORTS"
                            if port_info not in risky_ports:
                                risky_ports.append(port_info)

            # If a vulnerable port is open to 0.0.0.0/0, then add to report
            if is_vulnerable:
                ports_str = ", ".join(risky_ports) 
                
                findings.append({
                    "resource": f"Security Group: {sg_name} ({sg_id})",
                    "is_vulnerable": True,
                    "risk_reason": f"High Risk: Ports {ports_str} are open to the world (0.0.0.0/0)!"
                })
            else:
                findings.append({
                    "resource": f"Security Group: {sg_name} ({sg_id})",
                    "is_vulnerable": False,
                    "risk_reason": "Safe: No critical ports open to the public."
                })
        
        # Check EC2 Instance IMDSv2
        instances_response = ec2_client.describe_instances()
        
        for reservation in instances_response.get('Reservations', []):
            for instance in reservation.get('Instances', []):
                instance_id = instance['InstanceId']
                state = instance.get('State', {}).get('Name')
                
                if state in ['running', 'stopped']:
                    metadata_options = instance.get('MetadataOptions', {})
                    http_tokens = metadata_options.get('HttpTokens', '')
                    
                    if http_tokens != 'required':
                        findings.append({
                            "resource": f"EC2 Instance: {instance_id}",
                            "is_vulnerable": True,
                            "risk_reason": "Critical: IMDSv2 is NOT enforced! Vulnerable to SSRF attacks."
                        })
                    else:
                        findings.append({
                            "resource": f"EC2 Instance: {instance_id}",
                            "is_vulnerable": False,
                            "risk_reason": "Safe: IMDSv2 is enforced."
                        })

        return{
            "total_security_groups_scanned": len(security_groups),
            "findings": findings
        }
    except ClientError as e:
        return {"error": f"AWS Error: {str(e)}"}
    except Exception as e:
        return {"error": f"System Error: {str(e)}"}
    
@app.get("/scan/iam")
def scan_iam_security():
    try:
        findings = []

        # MFA control for root user
        summary = iam_client.get_account_summary()
        mfa_enabled = summary['SummaryMap'].get('AccountMFAEnabled', 0)

        if mfa_enabled == 0:
            findings.append({
                "resource": "Root Account",
                "is_vulnerable": True,
                "risk_reason": "CRITICAL RISK!: MFA is disabled on the root account. The account is very vulnerable to hijacking!"
            })

            issue_id = "root_mfa_disabled"
            if should_send_notification(issue_id, cooldown_days=2):
                target_email = IAM_USER_EMAILS.get("root")
                if target_email:
                    subject = "CRITICAL SECURITY ALERT: Root Account MFA Disabled!"
                    body = "MFA is disabled on your AWS Root account. Please enable it immediately to prevent account hijacking."                  
                    success = send_ses_email(target_email, subject, body)
                    if success:
                        print("Success: Warning email delivered to AWS SES for Root account.")
                    else:
                        print("Failure: AWS SES rejected the email for Root. Check terminal logs.")
                else:
                    print("Email not found for root, mail could not be sent.")
            else:
                print("Root MFA warning is in cooldown period.")

        else:
            findings.append({
                "resource": "Root Account",
                "is_vulnerable": False,
                "risk_reason": "Safe: MFA is enabled on the root account."
            })

        # Access Key age control for user accounts
        user_response = iam_client.list_users()

        for user in user_response.get('Users', []):
            username = user['UserName']

            keys_response = iam_client.list_access_keys(UserName = username)

            for key in keys_response.get('AccessKeyMetadata', []):
                key_id = key['AccessKeyId']
                create_date = key['CreateDate']

                age_in_days = (datetime.now(timezone.utc) - create_date).days

                # Industry Standard (PCI-DSS, SOC2): Keys must be changed every 90 days
                if age_in_days > 90:
                    findings.append({
                        "resource": f"IAM User: {username}",
                        "is_vulnerable": True,
                        "risk_reason": f"High Risk: Access Key ({key_id}) has not been renewed for {age_in_days} and carries high risk!"
                    })

                    issue_id = f"{username}_access_key_expired"
                    if should_send_notification(issue_id, cooldown_days=2):
                        target_email = IAM_USER_EMAILS.get(username)
                        
                        if target_email:
                            subject = "CRITICAL: AWS Access Key Renewal Reminder"
                            body = f"Hello {username},\n\nYour AWS Access Key '{key_id}' has not been changed for {age_in_days} days. Please renew it immediately according to security policies."
                            success = send_ses_email(target_email, subject, body)                           
                            if success:
                                print(f"Success: SES warning email delivered to {username}.")
                            else:
                                print(f"Failure: AWS SES rejected the email for {username}. Check terminal logs.")
                        else:
                            print(f"Email not found for {username}, mail could not be sent.")
                    else:
                        print(f"Notification cooldown is active for {username}.")

                else:
                    findings.append({
                        "resource": f"IAM User: {username}",
                        "is_vulnerable": False,
                        "risk_reason": f"Safe: Access Key ({key_id}) is currently {age_in_days} days old."
                    })
        return({
            "total_findings": len(findings),
            "findings": findings
        })

    except ClientError as e:
        return({"error": f"AWS Error: {str(e)}"})
    except Exception as e:
        return({"error": f"System Error: {str(e)}"})
    
@app.get("/scan/all")
def scan_all_resources():
    try:
        s3_results = scan_s3_security()
        ec2_results = scan_ec2_security_groups()
        iam_results = scan_iam_security()

        # Error control
        if "error" in s3_results: s3_results = {"findings": [], "error": s3_results["error"]}
        if "error" in ec2_results: ec2_results = {"findings": [], "error": ec2_results["error"]}
        if "error" in iam_results: iam_results = {"findings": [], "error": iam_results["error"]}

        total_s3_risks = sum(1 for item in s3_results.get("findings", []) if item.get("is_vulnerable"))
        total_ec2_risks = sum(1 for item in ec2_results.get("findings", []) if item.get("is_vulnerable"))
        total_iam_risks = sum(1 for item in iam_results.get("findings", []) if item.get("is_vulnerable"))

        master_report = {
            "scan_date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "executive_summary": {
                "status": "Danger" if (total_ec2_risks + total_iam_risks + total_s3_risks) > 0 else "Secure",
                "total_vulnerabilities_found": total_s3_risks + total_ec2_risks + total_iam_risks,
                "breakdown": {
                    "s3_risks": total_s3_risks,
                    "ec2_risks": total_ec2_risks,
                    "iam_risks": total_iam_risks
                }
            },
            "detailed_reports": {
                "S3_Buckets": s3_results,
                "EC2_Security_Groups": ec2_results,
                "IAM_Identities": iam_results
            }
        }

        saved_file = save_report_to_disk(master_report)
        master_report["saved_at"] = saved_file

        return master_report
    
    except Exception as e:
        return{"error": f"Orchestrator Error: {str(e)}"}
    
scheduler = BackgroundScheduler()
scheduler.add_job(scheduled_scan_job, 'interval', hours=2)
scheduler.start()

