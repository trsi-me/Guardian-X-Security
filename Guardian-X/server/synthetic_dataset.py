# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import random
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

SYNTHETIC_DIR = os.path.join(os.path.dirname(__file__), "..", "dataset", "synthetic")


def _ensure_dir():
    os.makedirs(SYNTHETIC_DIR, exist_ok=True)


def generate_banking_transactions(
    n_rows: int = 800,
    seed: int = 42,
) -> pd.DataFrame:
    random.seed(seed)
    rows = []
    channels = ["mobile", "branch", "atm", "wire", "ach"]
    tx_types = ["transfer", "withdrawal", "payment", "deposit"]

    for i in range(n_rows):
        is_fraud = random.random() < 0.18
        if is_fraud:
            amount = random.choice(
                [random.uniform(45000, 250000), random.uniform(12000, 45000)]
            )
            hour = random.choice([2, 3, 4, 22, 23, 0, 1])
            velocity = random.randint(6, 15)
            label = 1
        else:
            amount = random.choice(
                [
                    random.uniform(20, 8000),
                    random.uniform(8000, 9500),
                ]
            )
            hour = random.randint(8, 17)
            velocity = random.randint(0, 3)
            label = 0

        base = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        ts = base - timedelta(days=random.randint(0, 14)) + timedelta(
            hours=hour, minutes=random.randint(0, 59)
        )

        rows.append(
            {
                "tx_id": f"TX{i:06d}",
                "user_id": random.choice(
                    ["emp_finance01", "emp_finance02", "user01", "analyst", "admin"]
                ),
                "transaction_type": random.choice(tx_types),
                "amount": round(amount, 2),
                "channel": random.choice(channels),
                "velocity_10m": velocity,
                "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "label_fraud": label,
            }
        )

    return pd.DataFrame(rows)


def generate_employee_activity_logs(
    n_rows: int = 1200,
    seed: int = 43,
) -> pd.DataFrame:
    random.seed(seed)
    sensitive = [
        "/secure/vault/customer_pii.csv",
        "/finance/ledger_gl.db",
        "/hr/salaries_2026.xlsx",
        "/keys/signing_key.pem",
    ]
    normal_files = [
        "/shared/reports/Q1_summary.pdf",
        "/projects/specs.md",
        "/tmp/draft_notes.txt",
    ]
    rows = []
    acts_weight = [
        ("Read", 0.35),
        ("Create", 0.12),
        ("Modify", 0.15),
        ("Delete", 0.08),
        ("FileDownload", 0.12),
        ("FileCopy", 0.18),
    ]

    for i in range(n_rows):
        is_bad = random.random() < 0.22
        user = random.choice(
            ["user01", "user02", "contractor_x", "admin", "analyst", "dev01"]
        )
        base = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        if is_bad:
            hour = random.choice([1, 2, 3, 23])
            act = random.choice(["FileCopy", "FileDownload", "Modify", "Delete"])
            if act == "FileCopy":
                src = random.choice(sensitive)
                dst = random.choice(
                    [
                        "D:/USB_STICK/exfil_copy.csv",
                        "/mnt/usb/backup_leak.zip",
                        "C:/Users/Public/unauth_copy.pem",
                    ]
                )
                path = f"{src}|{dst}"
            elif act == "FileDownload":
                path = random.choice(
                    ["/exports/customer_data.zip", "/vault/confidential_bundle.zip"]
                )
            else:
                path = random.choice(sensitive)
            label = 1
        else:
            hour = random.randint(8, 17)
            r = random.random()
            cum = 0
            act = "Read"
            for a, w in acts_weight:
                cum += w
                if r <= cum:
                    act = a
                    break
            if act == "FileCopy":
                src = random.choice(normal_files)
                dst = "/backup/internal_mirror/report.pdf"
                path = f"{src}|{dst}"
            elif act == "FileDownload":
                path = "/intranet/forms/holiday.pdf"
            else:
                path = random.choice(normal_files)
            label = 0

        ts = base - timedelta(days=random.randint(0, 10)) + timedelta(
            hours=hour, minutes=random.randint(0, 59)
        )
        rows.append(
            {
                "log_id": f"LOG{i:06d}",
                "user_id": user,
                "activity_type": act,
                "file_path": path,
                "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "label_anomaly": label,
            }
        )

    return pd.DataFrame(rows)


def banking_row_to_event(row: Dict[str, Any]) -> Dict[str, Any]:
    fraud = int(row.get("label_fraud", 0))
    amt = float(row["amount"])
    ch = row.get("channel", "wire")
    vel = int(row.get("velocity_10m", 0))
    tx_type = row.get("transaction_type", "transfer")
    # صيغة موحدة: النوع:المبلغ:القناة:سرعة — يُستخرج المبلغ في rules/feature_extractor
    file_path = f"{tx_type}:{amt:.2f}:{ch}:{vel}"
    risk = "High Risk" if fraud and amt >= 50000 else "Suspicious" if fraud else "Normal"
    return {
        "user_id": row["user_id"],
        "activity_type": "Transaction",
        "file_path": file_path,
        "timestamp": row["timestamp"],
        "risk_level": risk,
        "source_domain": "banking_synthetic",
        "ground_truth_anomaly": int(fraud),
    }


def employee_row_to_event(row: Dict[str, Any]) -> Dict[str, Any]:
    bad = int(row.get("label_anomaly", 0))
    risk = "High Risk" if bad and row.get("activity_type") == "FileCopy" else (
        "Suspicious" if bad else "Normal"
    )
    return {
        "user_id": row["user_id"],
        "activity_type": row["activity_type"],
        "file_path": row["file_path"],
        "timestamp": row["timestamp"],
        "risk_level": risk,
        "source_domain": "employee_log_synthetic",
        "ground_truth_anomaly": int(bad),
    }


def build_guardian_events_from_synthetic(
    n_banking: int = 600,
    n_employee: int = 900,
    seed_bank: int = 42,
    seed_emp: int = 43,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    df_b = generate_banking_transactions(n_banking, seed_bank)
    df_e = generate_employee_activity_logs(n_employee, seed_emp)
    events = []
    for _, r in df_b.iterrows():
        events.append(banking_row_to_event(r.to_dict()))
    for _, r in df_e.iterrows():
        events.append(employee_row_to_event(r.to_dict()))

    events.sort(key=lambda e: e["timestamp"])
    profile = {
        "avg_ops_per_hour": 20,
        "normal_delete_limit": 3,
        "normal_modify_limit": 6,
        "work_start_time": "08:00",
        "work_end_time": "17:00",
    }
    return events, profile


def attach_event_history(events: List[Dict[str, Any]]) -> None:
    for i, e in enumerate(events):
        e["event_history"] = events[max(0, i - 50) : i]


def export_csvs_to_dataset_folder() -> Dict[str, str]:
    _ensure_dir()
    b_path = os.path.join(SYNTHETIC_DIR, "banking_transactions_synthetic.csv")
    e_path = os.path.join(SYNTHETIC_DIR, "employee_activity_synthetic.csv")
    generate_banking_transactions().to_csv(b_path, index=False)
    generate_employee_activity_logs().to_csv(e_path, index=False)
    return {"banking_csv": b_path, "employee_csv": e_path}


def load_guardian_events_from_csv(
    banking_csv: Optional[str] = None,
    employee_csv: Optional[str] = None,
) -> Optional[Tuple[List[Dict[str, Any]], Dict[str, Any]]]:
    if banking_csv is None:
        banking_csv = os.path.join(SYNTHETIC_DIR, "banking_transactions_synthetic.csv")
    if employee_csv is None:
        employee_csv = os.path.join(SYNTHETIC_DIR, "employee_activity_synthetic.csv")
    if not (os.path.exists(banking_csv) and os.path.exists(employee_csv)):
        return None
    df_b = pd.read_csv(banking_csv)
    df_e = pd.read_csv(employee_csv)
    events = []
    for _, r in df_b.iterrows():
        events.append(banking_row_to_event(r.to_dict()))
    for _, r in df_e.iterrows():
        events.append(employee_row_to_event(r.to_dict()))
    events.sort(key=lambda e: e["timestamp"])
    profile = {
        "avg_ops_per_hour": 20,
        "normal_delete_limit": 3,
        "normal_modify_limit": 6,
        "work_start_time": "08:00",
        "work_end_time": "17:00",
    }
    return events, profile
