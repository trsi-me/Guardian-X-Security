# Guardian-X Live Test Scenarios
# Run: python test_scenarios.py
# Make sure app.py is running first!

import requests
import time

SERVER = "http://127.0.0.1:5000"

def send_event(user_id, activity_type, file_path, description):
    try:
        r = requests.post(f"{SERVER}/api/events", json={
            "user_id": user_id,
            "activity_type": activity_type,
            "file_path": file_path
        }, timeout=10)
        data = r.json()
        risk = data.get('risk_level', '?')
        reason = data.get('reason', '')[:70]
        icon = 'HIGH RISK' if risk == 'High Risk' else 'SUSPICIOUS' if risk == 'Suspicious' else 'NORMAL   '
        print(f"  [{icon}] {description}")
        print(f"            Reason: {reason}")
        print()
        return risk
    except Exception as e:
        print(f"  [ERROR] {description}: {e}")
        return None

def send_transaction(user_id, amount, tx_type, description):
    try:
        r = requests.post(f"{SERVER}/api/simulate/transaction", json={
            "user_id": user_id,
            "amount": amount,
            "transaction_type": tx_type
        }, timeout=10)
        data = r.json()
        risk = data.get('risk_level', '?')
        reason = data.get('reason', '')[:70]
        icon = 'HIGH RISK' if risk == 'High Risk' else 'SUSPICIOUS' if risk == 'Suspicious' else 'NORMAL   '
        print(f"  [{icon}] {description}")
        print(f"            Reason: {reason}")
        print()
        return risk
    except Exception as e:
        print(f"  [ERROR] {description}: {e}")
        return None

print("=" * 60)
print("GUARDIAN-X LIVE TEST SCENARIOS")
print("=" * 60)
print()

# TEST 1: Normal activity
print("TEST 1 — Normal Activity")
send_event("ahmed.finance", "Read", "/finance/Q1_report.xlsx",
           "Normal file read during work hours")
time.sleep(0.5)

# TEST 2: USB Copy - Data Theft
print("TEST 2 — USB Copy (Data Theft)")
send_event("contractor_x", "FileCopy",
           "/secure/vault/customer_pii.csv|D:/USB_STICK/exfil.csv",
           "Contractor copies PII to USB drive")
time.sleep(0.5)

# TEST 3: Bangladesh Attack
print("TEST 3 — Bangladesh Attack ($81M wire at 2AM)")
send_transaction("emp.finance01", 81000000, "wire",
                 "$81,000,000 SWIFT transfer")
time.sleep(0.5)

# TEST 4: Mass deletion (all sent together with history)
print("TEST 4 — Mass Deletion (Ransomware simulation)")
for i in range(6):
    send_event("attacker", "Delete", f"/finance/record_{i}.xlsx",
               f"Delete finance file {i+1} of 6")
    time.sleep(0.3)

# TEST 5: Malware installation
print("TEST 5 — Malware Installation in System32")
send_event("attacker", "Create",
           "C:/Windows/System32/malware.exe",
           "Executable created in System32 — possible malware")
time.sleep(0.5)

# TEST 6: Sensitive file modification
print("TEST 6 — Sensitive File Modification")
send_event("insider", "Modify", "/config/settings.env",
           "Employee modifies server config file")

print("=" * 60)
print("Done! Check your dashboard for all events.")
print("Click EXPLAIN on any High Risk event to see AI explanation.")
print("=" * 60)
