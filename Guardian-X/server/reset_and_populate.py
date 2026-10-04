import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import db
from datetime import datetime, timedelta
import random

random.seed(42)

def reset_database():
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM file_events')
    cursor.execute('DELETE FROM alerts')
    cursor.execute('DELETE FROM containment_actions')
    cursor.execute('DELETE FROM explanations')
    cursor.execute('DELETE FROM agents')
    cursor.execute('DELETE FROM login_attempts')
    conn.commit()
    conn.close()
    print('Database cleared')

def reset_profile():
    db.update_behavior_profile(15, 3, 5, '08:00', '17:00')
    print('Profile reset: 08:00-17:00, delete limit=3, ops=15/hr')

def populate():
    users = ['ahmed.finance', 'sara.hr', 'mohammed.it', 'fatima.analyst', 'admin']
    normal_files = [
        '/finance/Q1_report.xlsx',
        '/hr/employee_list.docx',
        '/shared/meeting_notes.pdf',
        '/projects/specs.md',
        '/data/sales_2026.xlsx',
    ]

    base = datetime.now() - timedelta(days=7)
    events_added = 0
    alerts_added = 0

    # Normal events during work hours
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
            events_added += 1

    # Suspicious events
    suspicious_events = [
        ('sara.hr', 'Modify', '/config/settings.env', 'Modification of sensitive file'),
        ('ahmed.finance', 'FileDownload', '/exports/customer_data.zip', 'Download of sensitive file'),
        ('contractor_x', 'Read', '/finance/ledger_gl.db', 'Unusual access to finance DB'),
        ('mohammed.it', 'Modify', '/keys/signing_key.pem', 'Modification of sensitive file'),
        ('fatima.analyst', 'FileDownload', '/hr/salaries_2026.xlsx', 'Download of sensitive HR file'),
    ]
    for user, act, path, reason in suspicious_events:
        day = random.randint(0, 6)
        hour = random.randint(8, 16)
        ts = base + timedelta(days=day, hours=hour, minutes=random.randint(0, 59))
        ts_str = ts.strftime('%Y-%m-%d %H:%M:%S')
        eid = db.add_file_event(user, act, path, 'Suspicious', reason, ts_str)
        detect = ts + timedelta(milliseconds=37)
        detect_str = detect.strftime('%Y-%m-%d %H:%M:%S')
        db.add_alert(user, 'Suspicious', reason, str(eid),
                     event_time=ts_str, detect_time=detect_str, mttd_seconds=0.037)
        events_added += 1
        alerts_added += 1

    # High Risk events
    high_risk_events = [
        ('emp.finance01', 'Transaction', 'wire:81000000.00:swift:8',
         '2026-05-28 02:17:00', 'Large transaction outside working hours'),
        ('emp.finance01', 'Delete', '/logs/transaction_log.txt',
         '2026-05-28 02:19:00', 'File deletion outside working hours'),
        ('contractor_x', 'Delete', '/finance/record_1.xlsx',
         '2026-05-27 03:10:00', 'Excessive deletions outside working hours'),
        ('contractor_x', 'Delete', '/finance/record_2.xlsx',
         '2026-05-27 03:11:00', 'Excessive deletions outside working hours'),
        ('contractor_x', 'Delete', '/finance/record_3.xlsx',
         '2026-05-27 03:12:00', 'Excessive deletions outside working hours'),
        ('contractor_x', 'Delete', '/finance/record_4.xlsx',
         '2026-05-27 03:13:00', 'Excessive deletions more than 3 in 10 min'),
        ('insider_threat', 'FileCopy',
         '/secure/vault/customer_pii.csv|D:/USB_STICK/exfil.csv',
         '2026-05-26 14:30:00', 'Unauthorized copy of sensitive data to external path'),
    ]
    for user, act, path, ts_str, reason in high_risk_events:
        eid = db.add_file_event(user, act, path, 'High Risk', reason, ts_str)
        ts = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S')
        detect = ts + timedelta(milliseconds=37)
        detect_str = detect.strftime('%Y-%m-%d %H:%M:%S')
        aid = db.add_alert(user, 'High Risk', reason, str(eid),
                           event_time=ts_str, detect_time=detect_str, mttd_seconds=0.037)
        respond = detect + timedelta(milliseconds=206)
        respond_str = respond.strftime('%Y-%m-%d %H:%M:%S')
        db.add_containment_action(aid, eid, 'block',
                                  'Auto block: account suspended',
                                  alert_time=detect_str,
                                  mttr_seconds=0.206)
        events_added += 1
        alerts_added += 1

    # Register agents
    db.upsert_agent('demo-laptop', hostname='GUARDIAN-DEMO', source='simulated')
    db.upsert_agent('finance-pc', hostname='FINANCE-PC-01', source='simulated')

    return events_added, alerts_added

def verify():
    stats = db.get_dashboard_stats()
    mttd, mttr = db.get_mttd_mttr()
    profile = db.get_behavior_profile()
    print()
    print('=== VERIFICATION ===')
    total = stats['total_events']
    high = stats['high_risk']
    susp = stats['suspicious']
    total_alerts = stats['total_alerts']
    agents = stats['active_agents']
    work_start = profile['work_start_time']
    work_end = profile['work_end_time']
    delete_limit = profile['normal_delete_limit']
    ops = profile['avg_ops_per_hour']
    print('Total events  : ' + str(total))
    print('High Risk     : ' + str(high))
    print('Suspicious    : ' + str(susp))
    print('Total alerts  : ' + str(total_alerts))
    print('Active agents : ' + str(agents))
    print('MTTD avg      : ' + str(mttd) + ' sec')
    print('MTTR avg      : ' + str(mttr) + ' sec')
    print('Work hours    : ' + work_start + ' - ' + work_end)
    print('Delete limit  : ' + str(delete_limit))
    print('Avg ops/hr    : ' + str(ops))

if __name__ == '__main__':
    print('Guardian-X Database Reset and Population')
    print('=' * 40)
    db.init_db()
    reset_database()
    reset_profile()
    print('Populating with realistic events...')
    added, alerts = populate()
    print('Added ' + str(added) + ' events and ' + str(alerts) + ' alerts')
    verify()
    print()
    print('Done. Restart app.py and refresh the dashboard.')
