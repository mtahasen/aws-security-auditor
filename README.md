# AWS Security Auditor

## Overview
AWS Security Auditor is an automated Cloud Security Posture Management (CSPM) tool designed to proactively scan, evaluate, and report security vulnerabilities across Amazon Web Services (AWS) infrastructure. Built with a DevSecOps approach, the system provides continuous security monitoring without manual overhead.

The application orchestrates parallel security scans across essential AWS services, archives raw findings in JSON format, persists data into a SQLite database, and triggers conditional email alerts via Amazon SES when critical misconfigurations are detected.

## Key Features
* **Automated & Manual Triggers:** Capable of running scheduled background scans using APScheduler or manual ad-hoc scans via a RESTful API.
* **Parallel Execution:** Implements multi-threaded scanning across AWS services to significantly reduce audit latency.
* **Service Coverage:** Currently supports configuration audits for:
  * **Amazon S3:** Checks for public access blocks, versioning, and encryption status.
  * **Amazon EC2:** Evaluates Security Groups for overly permissive inbound rules (e.g., 0.0.0.0/0).
  * **AWS IAM:** Audits user identities and access management policies.
* **Hybrid Data Persistence:** * Generates hierarchical JSON artifacts for forensic archiving.
  * Utilizes a SQLite database for analytics, historical tracking, and querying.
* **Smart Alerting System:** Integrates with Amazon SES to deliver executive summaries and critical vulnerability alerts to security administrators, incorporating a cooldown mechanism to prevent alert fatigue.
* **Interactive Documentation:** Features a self-documenting OpenAPI (Swagger) interface for seamless interaction and endpoint testing.

## System Architecture
The project follows a modular architecture designed for clear separation of concerns:
* **API Controller:** Acts as the central orchestrator using FastAPI to handle incoming requests and coordinate background tasks.
* **Scanner Modules:** Dedicated scanning modules (`S3Scanner`, `EC2Scanner`, and `IAMScanner`) are utilized to isolate the business logic for each specific AWS service, ensuring maintainability.
* **Storage Management:** A robust storage layer handles local disk operations for JSON reports, while a dedicated database manager parses and maps complex AWS data structures into database records.
* **Notification Service:** Evaluates scan results against predefined risk thresholds to determine the necessity of an alert before interacting with the email service.

## Technology Stack
* **Language:** Python 3.14.x
* **Framework:** FastAPI
* **AWS SDK:** Boto3
* **Database:** SQLite3
* **Task Scheduler:** APScheduler
* **Notification:** Amazon Simple Email Service (SES)

## Installation and Setup

### Prerequisites
* Python 3.x installed on the host machine.
* Valid AWS Credentials with read-only access to S3, EC2, and IAM.
* An AWS SES verified email address.

### Installation Steps
1. Clone the repository:
   ```bash
   git clone [https://github.com/mtahasen/aws-security-auditor.git](https://github.com/your-username/aws-security-auditor.git)
   cd aws-security-auditor
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use: venv\Scripts\activate
   ```

3. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Configure environment variables. Create a `.env` file in the root directory and define the following variables:
   ```env
   AWS_ACCESS_KEY_ID=your_access_key
   AWS_SECRET_ACCESS_KEY=your_secret_key
   AWS_DEFAULT_REGION=your_aws_region
   SOURCE_EMAIL=your_verified_ses_email@example.com
   TARGET_EMAIL=admin@example.com
   ```

## Usage

### Starting the Application
Initialize the FastAPI server using Uvicorn:
   ```bash
   uvicorn main:app --reload
   ```

### Accessing the Interface
Once the server is running, access the interactive OpenAPI documentation via your browser:
* **Swagger UI:** `http://127.0.0.1:8000/docs`

From the Swagger UI, you can manually trigger the `/scan/all` endpoint to initiate a full infrastructure audit. The results will be dynamically generated, saved to the `reports/` directory, inserted into the SQLite database, and optionally emailed to the configured target address.

## License
This project is licensed under the MIT License.
