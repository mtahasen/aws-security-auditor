from fastapi import FastAPI
import boto3
import os
from botocore.exceptions import ClientError

app = FastAPI(
    title="Infrastructure Security Auditor",
    description="Automated AWS Security Scanner API"
)

# Global clients
sts_client = boto3.client('sts')
s3_client = boto3.client('s3')
ec2_client = boto3.client('ec2')

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
            is_public_risk = False
            risk_reason = "Safe"

            try:
                # Check the "Public Access Block" setting of the bucket
                pab = s3_client.get_public_access_block(Bucket = bucket_name)
                config = pab.get('PublicAccessBlockConfiguration', {})

                # Check if even one these four firewall is down, then there is a risk
                if not (config.get('BlockPublicAcls') and 
                        config.get('BlockPublicPolicy') and
                        config.get('IgnorePublicAcls') and
                        config.get('RestrictPublicBuckets')):
                    is_public_risk = True
                    risk_reason = "Public Access Block is partially or fully disabled!"
            
            except ClientError as e:
                # If the buckets these firewall settings never exist, then there is a risk by default
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    is_public_risk = True
                    risk_reason = "No Public Access Block configuration found. High Risk!"

            # Add results to report
            scan_results.append({
                "bucket_name": bucket_name,
                "is_vulnerable": is_public_risk,
                "details": risk_reason
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
                    # Check that if 22 or 3389 are in this range
                    if (from_port <= 22 <= to_port) or (from_port <= 3389 <= to_port):
                        is_risky_port = True

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
                findings.append({
                    "security_group_name": sg_name,
                    "security_group_id": sg_id,
                    "is_vulnerable": True,
                    "risk_reason": f"High Risk: Ports {risky_ports} are open to the world (0.0.0.0/0)!"
                })
            else:
                findings.append({
                        "security_group_name": sg_name,
                        "security_group_id": sg_id,
                        "is_vulnerable": False,
                        "risk_reason": "Safe: No critical ports open to the public."
                    })
        
        return{
            "total_security_groups_scanned": len(security_groups),
            "findings": findings
        }
    except ClientError as e:
        return {"error": f"AWS Error: {str(e)}"}
    except Exception as e:
        return {"error": f"System Error: {str(e)}"}