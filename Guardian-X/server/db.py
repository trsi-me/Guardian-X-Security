# -*- coding: utf-8 -*-
import sqlite3
import os
from datetime import datetime, timezone, timedelta

DB_PATH = os.path.join(os.path.dirname(__file__), 'guardian.db')

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("SELECT DATETIME('now', '+3 hours')")
    conn.create_function('CURRENT_TIMESTAMP', 0, 
        lambda: __import__('datetime').datetime.now(
            __import__('datetime').timezone(
                __import__('datetime').timedelta(hours=3)
            )
        ).strftime('%Y-%m-%d %H:%M:%S'))
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS behavior_profile (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            avg_ops_per_hour INTEGER DEFAULT 15,
            normal_delete_limit INTEGER DEFAULT 3,
            normal_modify_limit INTEGER DEFAULT 5,
            work_start_time TEXT DEFAULT '08:00',
            work_end_time TEXT DEFAULT '17:00',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            activity_type TEXT NOT NULL,
            file_path TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            details TEXT,
            event_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            reason TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            file_event_ids TEXT,
            event_time TIMESTAMP,
            detect_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            mttd_seconds REAL DEFAULT 0
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS explanations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_event_id INTEGER NOT NULL,
            shap_json TEXT,
            lime_json TEXT,
            summary_text TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (file_event_id) REFERENCES file_events(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS containment_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER,
            file_event_id INTEGER,
            action_type TEXT NOT NULL,
            status TEXT DEFAULT 'simulated',
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            alert_time TIMESTAMP,
            respond_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            mttr_seconds REAL DEFAULT 0
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS agents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT UNIQUE NOT NULL,
            hostname TEXT DEFAULT 'simulated',
            status TEXT DEFAULT 'Online',
            source TEXT DEFAULT 'simulated',
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()

    cursor.execute('SELECT COUNT(*) FROM behavior_profile')
    if cursor.fetchone()[0] == 0:
        cursor.execute('''
            INSERT INTO behavior_profile
            (avg_ops_per_hour, normal_delete_limit, normal_modify_limit, work_start_time, work_end_time)
            VALUES (15, 3, 5, '08:00', '17:00')
        ''')
        conn.commit()

    cursor.execute('SELECT COUNT(*) FROM file_events')
    if cursor.fetchone()[0] == 0:
        default_events = [
            ('user01', 'Create', 'report.pdf', 'Normal', '2025-02-16 09:10:00', 'File created during work hours'),
            ('user01', 'Read', 'data.xlsx', 'Normal', '2025-02-16 09:15:00', 'Normal read access'),
            ('user01', 'Modify', 'config.ini', 'Suspicious', '2025-02-16 09:20:00', 'Config file modification'),
            ('user01', 'Delete', 'backup.zip', 'High Risk', '2025-02-16 02:30:00', 'Deletion outside working hours'),
            ('admin', 'Read', 'logs.txt', 'Suspicious', '2025-02-16 10:01:00', 'Repeated access within 1 minute'),
            ('admin', 'Read', 'logs.txt', 'Suspicious', '2025-02-16 10:01:30', 'Repeated access within 1 minute'),
            ('admin', 'Read', 'logs.txt', 'Suspicious', '2025-02-16 10:02:00', 'Repeated access within 1 minute'),
            ('admin', 'Delete', 'temp1.tmp', 'High Risk', '2025-02-16 10:05:00', 'Excessive deletions'),
            ('admin', 'Delete', 'temp2.tmp', 'High Risk', '2025-02-16 10:06:00', 'Excessive deletions'),
            ('admin', 'Delete', 'temp3.tmp', 'High Risk', '2025-02-16 10:07:00', 'Excessive deletions'),
            ('admin', 'Delete', 'temp4.tmp', 'High Risk', '2025-02-16 10:08:00', 'Excessive deletions'),
            ('admin', 'Delete', 'temp5.tmp', 'High Risk', '2025-02-16 10:09:00', 'Excessive deletions'),
            ('admin', 'Delete', 'temp6.tmp', 'High Risk', '2025-02-16 10:10:00', 'Excessive deletions'),
        ]
        for event in default_events:
            cursor.execute('''
                INSERT INTO file_events (user_id, activity_type, file_path, risk_level, timestamp, details)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', event)
        conn.commit()

    cursor.execute('SELECT COUNT(*) FROM alerts')
    if cursor.fetchone()[0] == 0:
        default_alerts = [
            ('user01', 'High Risk', 'File deletion outside working hours'),
            ('admin', 'Suspicious', 'Excessive file access frequency'),
            ('admin', 'High Risk', 'More than 5 file deletions within 10 minutes'),
        ]
        for alert in default_alerts:
            cursor.execute('''
                INSERT INTO alerts (user_id, risk_level, reason)
                VALUES (?, ?, ?)
            ''', alert)
        conn.commit()

    conn.close()

def get_file_events(limit=50):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM file_events ORDER BY timestamp DESC LIMIT ?', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_alerts(limit=50):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_behavior_profile():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM behavior_profile LIMIT 1')
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def update_behavior_profile(avg_ops_per_hour, normal_delete_limit, normal_modify_limit,
                            work_start_time, work_end_time):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE behavior_profile SET
            avg_ops_per_hour = ?,
            normal_delete_limit = ?,
            normal_modify_limit = ?,
            work_start_time = ?,
            work_end_time = ?
        WHERE id = (SELECT id FROM behavior_profile LIMIT 1)
    ''', (avg_ops_per_hour, normal_delete_limit, normal_modify_limit, work_start_time, work_end_time))
    conn.commit()
    conn.close()

def add_file_event(user_id, activity_type, file_path, risk_level, details='', event_time=None):
    from datetime import datetime, timezone, timedelta
    RIYADH_TZ = timezone(timedelta(hours=3))
    now_riyadh = datetime.now(RIYADH_TZ).strftime('%Y-%m-%d %H:%M:%S')
    
    if not event_time:
        event_time = now_riyadh
    
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO file_events (user_id, activity_type, file_path, risk_level, details, timestamp, event_time)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (user_id, activity_type, file_path, risk_level, details, event_time, event_time))
    event_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return event_id

def add_alert(user_id, risk_level, reason, file_event_ids='', event_time=None, detect_time=None, mttd_seconds=0):
    from datetime import datetime, timezone, timedelta
    RIYADH_TZ = timezone(timedelta(hours=3))
    now_riyadh = datetime.now(RIYADH_TZ).strftime('%Y-%m-%d %H:%M:%S')

    if not event_time:
        event_time = now_riyadh
    if not detect_time:
        detect_time = now_riyadh

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO alerts (user_id, risk_level, reason, file_event_ids, event_time, detect_time, mttd_seconds, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (user_id, risk_level, reason, file_event_ids, event_time, detect_time, mttd_seconds, now_riyadh))
    alert_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return alert_id

def get_event_by_id(event_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM file_events WHERE id = ?', (event_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def add_explanation(file_event_id, shap_json=None, lime_json=None, summary_text=None):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO explanations (file_event_id, shap_json, lime_json, summary_text)
        VALUES (?, ?, ?, ?)
    ''', (file_event_id, shap_json, lime_json, summary_text))
    exp_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return exp_id

def get_explanation_by_event_id(file_event_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM explanations WHERE file_event_id = ? ORDER BY created_at DESC LIMIT 1',
                   (file_event_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def add_containment_action(alert_id, file_event_id, action_type, details='', alert_time=None, mttr_seconds=0):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO containment_actions (alert_id, file_event_id, action_type, details, alert_time, mttr_seconds)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (alert_id, file_event_id, action_type, details, alert_time, mttr_seconds))
    aid = cursor.lastrowid
    conn.commit()
    conn.close()
    return aid

def get_containment_actions(limit=20):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM containment_actions ORDER BY created_at DESC LIMIT ?', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_dashboard_stats():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT COUNT(*) FROM file_events WHERE risk_level = "High Risk"')
    high_risk_count = cursor.fetchone()[0]

    cursor.execute('SELECT COUNT(*) FROM file_events WHERE risk_level = "Suspicious"')
    suspicious_count = cursor.fetchone()[0]

    cursor.execute('SELECT COUNT(*) FROM alerts')
    alerts_count = cursor.fetchone()[0]

    cursor.execute('SELECT COUNT(*) FROM file_events')
    total_events = cursor.fetchone()[0]

    cursor.execute('SELECT COUNT(*) FROM agents WHERE status = "Online"')
    active_agents = cursor.fetchone()[0]

    conn.close()
    return {
        'high_risk': high_risk_count,
        'suspicious': suspicious_count,
        'total_alerts': alerts_count,
        'total_events': total_events,
        'active_agents': active_agents
    }

def get_mttd_mttr():
    # MTTD: حدث → تنبيه | MTTR: تنبيه → إجراء احتواء
    conn = get_connection()
    cursor = conn.cursor()

    # MTTD: من event_time إلى detect_time في جدول alerts
    cursor.execute('''
        SELECT AVG(mttd_seconds) FROM alerts
        WHERE mttd_seconds > 0
    ''')
    row = cursor.fetchone()
    avg_mttd = row[0] if row and row[0] else 0

    # MTTR: من alert_time إلى respond_time في جدول containment_actions
    cursor.execute('''
        SELECT AVG(mttr_seconds) FROM containment_actions
        WHERE mttr_seconds > 0
    ''')
    row = cursor.fetchone()
    avg_mttr = row[0] if row and row[0] else 0

    conn.close()
    return round(avg_mttd, 3), round(avg_mttr, 3)

def upsert_agent(agent_id, hostname='simulated', source='simulated'):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM agents WHERE agent_id = ?', (agent_id,))
    if cursor.fetchone():
        cursor.execute('''
            UPDATE agents SET hostname=?, status='Online', last_seen=CURRENT_TIMESTAMP
            WHERE agent_id = ?
        ''', (hostname, agent_id))
    else:
        cursor.execute('''
            INSERT INTO agents (agent_id, hostname, status, source, last_seen)
            VALUES (?, ?, 'Online', ?, CURRENT_TIMESTAMP)
        ''', (agent_id, hostname, source))
    conn.commit()
    conn.close()

def get_agents(limit=20):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM agents ORDER BY last_seen DESC LIMIT ?', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]
