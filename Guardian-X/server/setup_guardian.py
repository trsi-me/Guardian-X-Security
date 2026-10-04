import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import db
from datetime import datetime, timedelta
import random
random.seed(42)

db.init_db()

# Reset profile
db.update_behavior_profile(15, 3, 5, '08:00', '17:00')
print('Profile reset OK')

# Normal events - work hours
users = ['ahmed.finance', 'sara.hr', 'mohammed.it', 'fatima.analyst', 'admin']
normal_files = [
    '/finance/Q1_report.xlsx',
    '/hr/employee_list.docx',
    '/shared/meeting_notes.pdf',
    '/projects/specs.md',
    '/data/sales_2026.xlsx',
]
base = datetime.now() - timedelta(days=7)

for day in range(7):
    for _ in range(20):
        user = random.choice(users)
        hour = random.randint(8, 16)
        minute = random.randint(0, 59)
        ts = base + timedelta(days=day, hours=hour, minutes=minute)
        ts_str = ts.strftime('%Y-%m-%d %H:%M:%S')
        act = random.choice(['Read', 'Read', 'Read', 'Create', 'Modify'])
        path = random.choice(normal_files)
        db.add_file_event(user, act, path, 'Normal', 'Normal work activity', ts_str)

print('Normal events added OK')

# Suspicious events
sus = [
    ('sara.hr', 'Modify', '/config/settings.env', 'Modification of sensitive file', '2026-05-29 10:00:00'),
    ('ahmed.finance', 'FileDownload', '/exports/customer_data.zip', 'Download of sensitive file', '2026-05-29 11:00:00'),
    ('contractor_x', 'Read', '/finance/ledger_gl.db', 'Unusual access to finance DB', '2026-05-29 14:00:00'),
    ('mohammed.it', 'Modify', '/keys/signing_key.pem', 'Modification of key file', '2026-05-28 09:00:00'),
    ('fatima.analyst', 'FileDownload', '/hr/salaries_2026.xlsx', 'Download of sensitive HR file', '2026-05-28 15:00:00'),
]
for user, act, path, reason, ts_str in sus:
    eid = db.add_file_event(user, act, path, 'Suspicious', reason, ts_str)
    ts = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S')
    detect = ts + timedelta(milliseconds=37)
    detect_str = detect.strftime('%Y-%m-%d %H:%M:%S')
    db.add_alert(user, 'Suspicious', reason, str(eid),
                 event_time=ts_str, detect_time=detect_str, mttd_seconds=0.037)

print('Suspicious events added OK')

# High Risk - Bangladesh attack
hr = [
    ('emp.finance01', 'Read', '/finance/ledger_gl.db', 'Normal morning access', '2026-05-28 09:00:00', 'Normal'),
    ('emp.finance01', 'Transaction', 'transfer:500.00:branch:1', 'Small routine transfer', '2026-05-28 09:30:00', 'Normal'),
    ('emp.finance01', 'Transaction', 'wire:25000.00:swift:1', 'Large wire at 2AM', '2026-05-28 02:15:00', 'Suspicious'),
    ('emp.finance01', 'Transaction', 'wire:81000000.00:swift:8', 'MASSIVE SWIFT transfer', '2026-05-28 02:17:00', 'High Risk'),
    ('emp.finance01', 'FileDownload', '/exports/customer_data.zip', 'Data exfiltration', '2026-05-28 02:18:00', 'Suspicious'),
    ('emp.finance01', 'Delete', '/logs/transaction_log.txt', 'Covering tracks', '2026-05-28 02:19:00', 'High Risk'),
    ('contractor_x', 'Delete', '/finance/record_1.xlsx', 'Mass deletion', '2026-05-27 03:10:00', 'High Risk'),
    ('contractor_x', 'Delete', '/finance/record_2.xlsx', 'Mass deletion', '2026-05-27 03:11:00', 'High Risk'),
    ('contractor_x', 'Delete', '/finance/record_3.xlsx', 'Mass deletion', '2026-05-27 03:12:00', 'High Risk'),
    ('contractor_x', 'Delete', '/finance/record_4.xlsx', 'Excessive deletions more than 3 in 10 min', '2026-05-27 03:13:00', 'High Risk'),
    ('insider_threat', 'FileCopy', '/secure/vault/customer_pii.csv|D:/USB_STICK/exfil.csv', 'Unauthorized USB copy', '2026-05-26 14:30:00', 'High Risk'),
    ('attacker', 'Create', 'C:/Windows/System32/malware.exe', 'Malware in system directory', '2026-05-26 03:00:00', 'High Risk'),
]
for user, act, path, reason, ts_str, risk in hr:
    eid = db.add_file_event(user, act, path, risk, reason, ts_str)
    if risk in ['Suspicious', 'High Risk']:
        ts = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S')
        detect = ts + timedelta(milliseconds=37)
        detect_str = detect.strftime('%Y-%m-%d %H:%M:%S')
        aid = db.add_alert(user, risk, reason, str(eid),
                           event_time=ts_str, detect_time=detect_str, mttd_seconds=0.037)
        if risk == 'High Risk':
            db.add_containment_action(aid, eid, 'block',
                                      'Auto block: account suspended',
                                      alert_time=detect_str,
                                      mttr_seconds=0.206)

print('High Risk events added OK')

# Agents
db.upsert_agent('demo-laptop', hostname='GUARDIAN-DEMO', source='simulated')
db.upsert_agent('finance-pc', hostname='FINANCE-PC-01', source='simulated')
print('Agents added OK')

# Verify
stats = db.get_dashboard_stats()
mttd, mttr = db.get_mttd_mttr()
profile = db.get_behavior_profile()
print()
print('=== FINAL RESULT ===')
print('Total events  : ' + str(stats['total_events']))
print('High Risk     : ' + str(stats['high_risk']))
print('Suspicious    : ' + str(stats['suspicious']))
print('Total alerts  : ' + str(stats['total_alerts']))
print('Active agents : ' + str(stats['active_agents']))
print('MTTD          : ' + str(mttd) + ' sec')
print('MTTR          : ' + str(mttr) + ' sec')
print('Work hours    : ' + profile['work_start_time'] + ' - ' + profile['work_end_time'])
print()
print('Done. Now restart app.py and refresh dashboard.')
