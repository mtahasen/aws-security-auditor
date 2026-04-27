import sqlite3
from datetime import datetime

DB_NAME = "security_auditor.db"

def setup_database():
    """Initializes the database schema based on the ER diagram."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Scans (
            scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_date DATETIME,
            saved_json_path VARCHAR(255)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Executive_Summaries (
            summary_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            status VARCHAR(50),
            total_vulnerabilities INTEGER,
            FOREIGN KEY(scan_id) REFERENCES Scans(scan_id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Vulnerability_Catalog (
            vuln_id INTEGER PRIMARY KEY AUTOINCREMENT,
            severity VARCHAR(20),
            risk_reason TEXT UNIQUE
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Findings (
            finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            resource_type VARCHAR(50),
            resource_name VARCHAR(255),
            is_vulnerable BOOLEAN,
            vuln_id INTEGER,
            FOREIGN KEY(scan_id) REFERENCES Scans(scan_id),
            FOREIGN KEY(vuln_id) REFERENCES Vulnerability_Catalog(vuln_id)
        )
    ''')

    conn.commit()
    conn.close()

def save_scan_to_db(master_report, json_path):
    """Maps the specific JSON report structure to the relational database tables."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    try:
        # Insert main scan record
        cursor.execute(
            "INSERT INTO Scans (scan_date, saved_json_path) VALUES (?, ?)",
            (master_report['scan_date'], json_path)
        )
        scan_id = cursor.lastrowid

        # Insert executive summary
        summary = master_report['executive_summary']
        cursor.execute(
            "INSERT INTO Executive_Summaries (scan_id, status, total_vulnerabilities) VALUES (?, ?, ?)",
            (scan_id, summary['status'], summary['total_vulnerabilities_found'])
        )

        # Process each finding from the detailed_reports sections
        for category, category_data in master_report['detailed_reports'].items():
            for finding in category_data.get('findings', []):
                vuln_id = None
                is_vulnerable = finding.get('is_vulnerable', False)
                
                if is_vulnerable:
                    # GÜNCELLEME BURADA: risk_reason yoksa details'e bak
                    risk_reason = finding.get('risk_reason', finding.get('details', 'Unknown Risk'))
                    
                    # Handle Vulnerability Catalog (Normalized)
                    cursor.execute("SELECT vuln_id FROM Vulnerability_Catalog WHERE risk_reason = ?", (risk_reason,))
                    row = cursor.fetchone()
                    
                    if row:
                        vuln_id = row[0]
                    else:
                        cursor.execute(
                            "INSERT INTO Vulnerability_Catalog (severity, risk_reason) VALUES (?, ?)",
                            ("High", risk_reason)
                        )
                        vuln_id = cursor.lastrowid

                # GÜNCELLEME BURADA: resource yoksa bucket_name'e bak
                resource_name = finding.get('resource', finding.get('bucket_name', 'Unknown'))
                
                cursor.execute(
                    "INSERT INTO Findings (scan_id, resource_type, resource_name, is_vulnerable, vuln_id) VALUES (?, ?, ?, ?, ?)",
                    (scan_id, category, resource_name, is_vulnerable, vuln_id)
                )

        conn.commit()
    except Exception as e:
        print(f"Database error: {e}")
        conn.rollback()
    finally:
        conn.close()