# -*- coding: utf-8 -*-
from datetime import datetime, timedelta
import os

# Sensitive extensions from rules
SENSITIVE_EXTENSIONS = ['.ini', '.config', '.env', '.key', '.pem', '.crt', '.xml']


def _parse_ts(ts):
    if ts is None:
        return datetime.now()
    if isinstance(ts, datetime):
        return ts
    try:
        s = str(ts)[:19]
        return datetime.strptime(s, '%Y-%m-%d %H:%M:%S')
    except Exception:
        return datetime.now()


def extract_features_single(user_id, activity_type, file_path, timestamp, event_history, profile):
    ts = _parse_ts(timestamp)
    ten_min_ago = ts - timedelta(minutes=10)
    hour_ago = ts - timedelta(hours=1)

    # Activity type encoding (مع Transaction و FileDownload و FileCopy)
    act_map = {
        'Create': 0, 'Read': 1, 'Modify': 2, 'Delete': 3,
        'FileDownload': 1, 'Transaction': 4, 'FileCopy': 5,
    }
    activity_encoded = act_map.get(activity_type, 1)

    # File path features (يدعم Transaction بصيغة transfer:5000 أو wire:1200:mobile:3)
    path_lower = (file_path or '').lower()
    path_str = file_path or ''
    if activity_type == 'Transaction' and ':' in path_str:
        amount = 0
        for p in path_str.split(':')[1:]:
            try:
                amount = float(p)
                break
            except ValueError:
                continue
        path_length = min(amount / 10000.0, 50)  # تطبيع المبلغ
        is_sensitive = 1 if amount > 10000 else 0
        path_depth = 2
    else:
        path_depth = len(path_str.replace('\\', '/').split('/'))
        path_length = min(len(path_str), 500) / 100.0
        is_sensitive = 1 if any(path_lower.endswith(ext) for ext in SENSITIVE_EXTENSIONS) else 0
    if activity_type == 'FileDownload' and any(s in path_lower for s in ['customer', 'confidential', 'secret', '.zip']):
        is_sensitive = 1
    if activity_type == 'FileCopy':
        if any(m in path_lower for m in ('usb', 'exfil', 'unauth', 'customer_pii', 'vault/', 'signing_key', '|d:')):
            is_sensitive = 1

    # Time features
    hour_of_day = ts.hour
    minute = ts.minute
    is_weekend = 1 if ts.weekday() >= 5 else 0
    work_start = profile.get('work_start_time', '08:00')
    work_end = profile.get('work_end_time', '17:00')
    try:
        start_h, start_m = map(int, work_start.split(':'))
        end_h, end_m = map(int, work_end.split(':'))
        t_minutes = ts.hour * 60 + ts.minute
        start_minutes = start_h * 60 + start_m
        end_minutes = end_h * 60 + end_m
        is_work_hours = 1 if start_minutes <= t_minutes <= end_minutes else 0
    except Exception:
        is_work_hours = 1

    # Context from history (same user)
    delete_count_10min = 0
    modify_count_hour = 0
    same_file_access = 0
    create_count_hour = 0
    read_count_hour = 0
    total_ops_hour = 0

    for e in (event_history or []):
        et = _parse_ts(e.get('timestamp'))
        if e.get('user_id') != user_id:
            continue
        if ten_min_ago <= et <= ts and e.get('activity_type') == 'Delete':
            delete_count_10min += 1
        if hour_ago <= et <= ts:
            total_ops_hour += 1
            if e.get('activity_type') == 'Modify':
                modify_count_hour += 1
            elif e.get('activity_type') == 'Create':
                create_count_hour += 1
            elif e.get('activity_type') in ('Read', 'FileDownload', 'FileCopy'):
                read_count_hour += 1
            elif e.get('activity_type') == 'Transaction':
                read_count_hour += 1  # معاملة = نشاط
        if e.get('file_path') == file_path and (ts - et).total_seconds() < 60:
            same_file_access += 1

    # Profile-based normalized features
    avg_ops = profile.get('avg_ops_per_hour', 15)
    delete_limit = profile.get('normal_delete_limit', 3)
    modify_limit = profile.get('normal_modify_limit', 5)
    ops_ratio = total_ops_hour / max(avg_ops, 1)
    delete_ratio = delete_count_10min / max(delete_limit, 1)
    modify_ratio = modify_count_hour / max(modify_limit, 1)

    features = {
        'activity_type': activity_encoded,
        'path_depth': min(path_depth, 20),
        'path_length': min(path_length, 500) / 100.0,
        'is_sensitive_file': is_sensitive,
        'hour_of_day': hour_of_day,
        'minute': minute,
        'is_weekend': is_weekend,
        'is_work_hours': is_work_hours,
        'delete_count_10min': delete_count_10min,
        'modify_count_hour': modify_count_hour,
        'same_file_access': same_file_access,
        'create_count_hour': create_count_hour,
        'read_count_hour': read_count_hour,
        'total_ops_hour': total_ops_hour,
        'ops_ratio': min(ops_ratio, 10.0),
        'delete_ratio': min(delete_ratio, 10.0),
        'modify_ratio': min(modify_ratio, 10.0),
    }
    return features


def get_feature_names():
    return [
        'activity_type', 'path_depth', 'path_length', 'is_sensitive_file',
        'hour_of_day', 'minute', 'is_weekend', 'is_work_hours',
        'delete_count_10min', 'modify_count_hour', 'same_file_access',
        'create_count_hour', 'read_count_hour', 'total_ops_hour',
        'ops_ratio', 'delete_ratio', 'modify_ratio'
    ]


def features_to_vector(features):
    names = get_feature_names()
    return [float(features.get(n, 0)) for n in names]
