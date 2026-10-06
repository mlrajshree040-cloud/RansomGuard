import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ============ MULTI-FOLDER PROTECTION ============
PROTECTED_FOLDERS = [
    os.path.join(BASE_DIR, "protected_folder"),
    os.path.join(BASE_DIR, "protected_folder_2"),
    os.path.join(BASE_DIR, "protected_folder_3"),
    os.path.join(BASE_DIR, "protected_folder_4"),
    os.path.join(BASE_DIR, "protected_folder_5"),
]

# Backward-compat: keep single PROTECTED_FOLDER = first one
PROTECTED_FOLDER = PROTECTED_FOLDERS[0]

VAULT_FOLDER = os.path.join(BASE_DIR, "vault")
QUARANTINE_FOLDER = os.path.join(BASE_DIR, "quarantine")
HONEYPOT_FOLDER = os.path.join(BASE_DIR, "honeypot_shares")

DECOY_FILES = [
    "~$Project_COPY.docx",
    "Salary_2026.xlsx",
    "Password_Backup.txt",
    "bitcoin_wallet.dat",
    "backup_keys.pem",
    "_AAAA_urgent_budget.docx",
]

THRESHOLDS = {
    "mass_modify_count": 5,
    "time_window_seconds": 5,
    "entropy_threshold": 7.5,
    "max_ops_per_second": 20,
}

RANSOMWARE_EXTENSIONS = [
    ".locked", ".encrypted", ".crypt", ".zepto", ".locky",
    ".wcry", ".onion", ".wncry", ".ryk", ".ryuk", ".conti",
]

HONEYPOT_SHARES = {
    "IT_Backup": [
        ("payroll_backup.zip", 48000),
        ("employee_data.xlsx", 32000),
        ("database_dump.sql", 92000),
        ("encryption_keys.pem", 2400),
    ],
    "CEO_Documents": [
        ("merger_plan_2026.docx", 18000),
        ("salary_negotiation.pdf", 12000),
        ("board_minutes_Q4.docx", 24000),
    ],
    "Confidential_HR": [
        ("employee_ssn_master.xlsx", 56000),
        ("contracts_2026.pdf", 38000),
        ("performance_reviews.docx", 42000),
    ],
    "Customer_Database": [
        ("customers_full_dump.sql", 148000),
        ("payment_records.xlsx", 64000),
        ("GDPR_compliance.pdf", 22000),
    ],
}

LOG_FILE = os.path.join(BASE_DIR, "ransomguard.log")
DASHBOARD_PORT = 5000