import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rules import apply_rules

profile = {
    'work_start_time': '08:00',
    'work_end_time': '17:00',
    'normal_delete_limit': 3,
    'normal_modify_limit': 5
}
context = {
    'delete_count_10min': 0,
    'modify_count_hour': 0,
    'same_file_access_count': 0,
    'transaction_count_10min': 0
}

tests = [
    ('Create', 'C:/Windows/System32/malware.exe',               '2026-05-30 10:00:00', 'High Risk'),
    ('Modify', 'C:/Windows/System32/drivers/etc/hosts',         '2026-05-30 10:00:00', 'Suspicious'),
    ('Delete', 'C:/Windows/System32/winevt/Logs/Security.evtx', '2026-05-30 03:00:00', 'High Risk'),
    ('Read',   'C:/Users/Ahmed/Documents/report.pdf',           '2026-05-30 10:00:00', 'Normal'),
    ('Delete', 'C:/data/backup.zip',                            '2026-05-30 03:00:00', 'High Risk'),
    ('Modify', 'C:/config/settings.env',                        '2026-05-30 10:00:00', 'Suspicious'),
    ('FileCopy', '/secure/vault/customer_pii.csv|D:/USB_STICK/leak.csv', '2026-05-30 10:00:00', 'High Risk'),
]

print("=" * 60)
print("RULES TEST")
print("=" * 60)
passed = 0
for act, path, ts, expected in tests:
    risk, reason = apply_rules(act, path, ts, context, profile)
    ok = risk == expected
    if ok:
        passed += 1
    status = "PASS" if ok else "FAIL"
    filename = path.split("/")[-1]
    print(f"[{status}] [{risk:10}] {act} {filename}")
    print(f"       Reason: {reason}")
    print()

print(f"Results: {passed}/{len(tests)} passed")
