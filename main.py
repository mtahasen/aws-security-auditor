from fastapi import FastAPI
import boto3
import os
from botocore.exceptions import ClientError

app = FastAPI(
    title="Infrastructure Security Auditor",
    description="Automated AWS Security Scanner API"
)

@app.get("/")
def read_root():
    return {"status": "success", "message": "Auditor Engine is running perfectly!"}

# AWS Connection Test Endpoint
@app.get("/aws-test")
def test_aws_connection():
    try:
        # Boto3 finds AWS credentials from environment variables automatically
        sts_client = boto3.client('sts')
        
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
        s3_client = boto3.client('s3')

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