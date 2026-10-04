# -*- coding: utf-8 -*-
import os
import random
from datetime import datetime, timedelta

import numpy as np
import pandas as pd

from feature_extractor import extract_features_single, get_feature_names, features_to_vector
from ml_models import (
    train_isolation_forest, train_lightgbm, train_autoencoder,
    MLEnsemble
)


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


def generate_synthetic_events(n_normal=500, n_anomaly=150):
    users = ['user01', 'user02', 'admin', 'analyst', 'dev01', 'dev02']
    normal_files = ['report.pdf', 'data.xlsx', 'notes.txt', 'doc.docx', 'image.png', 'log.txt']
    sensitive_files = ['config.ini', 'settings.env', 'key.pem', 'cert.crt']
    base_ts = datetime.now() - timedelta(days=7)
    events = []
    profile = {'avg_ops_per_hour': 15, 'normal_delete_limit': 3,
               'normal_modify_limit': 5, 'work_start_time': '08:00', 'work_end_time': '17:00'}

    for _ in range(n_normal):
        user = random.choice(users)
        ts = base_ts + timedelta(
            days=random.randint(0, 6),
            hours=random.randint(8, 16),
            minutes=random.randint(0, 59)
        )
        if random.random() < 0.9:
            act = random.choice(['Create', 'Read', 'Read', 'Read', 'Modify'])
            f = random.choice(normal_files)
        else:
            act = 'Delete'
            f = random.choice(normal_files)
        events.append({
            'user_id': user,
            'activity_type': act,
            'file_path': f'/data/{f}',
            'timestamp': ts.strftime('%Y-%m-%d %H:%M:%S'),
            'risk_level': 'Normal',
            'event_history': []
        })

    for _ in range(n_anomaly):
        user = random.choice(users)
        r = random.random()
        if r < 0.3:
            ts = base_ts + timedelta(
                days=random.randint(0, 6),
                hours=random.choice([2, 3, 22, 23]),
                minutes=random.randint(0, 59)
            )
            act = 'Delete'
            f = random.choice(normal_files)
        elif r < 0.5:
            ts = base_ts + timedelta(
                days=random.randint(0, 6),
                hours=random.randint(8, 16),
                minutes=random.randint(0, 59)
            )
            act = 'Modify'
            f = random.choice(sensitive_files)
        elif r < 0.7:
            ts = base_ts + timedelta(
                days=random.randint(0, 6),
                hours=random.randint(8, 16),
                minutes=random.randint(0, 59)
            )
            act = 'Delete'
            f = f'temp{random.randint(1,20)}.tmp'
        else:
            ts = base_ts + timedelta(
                days=random.randint(0, 6),
                hours=random.randint(8, 16),
                minutes=random.randint(0, 59)
            )
            act = 'Read'
            f = 'logs.txt'
        events.append({
            'user_id': user,
            'activity_type': act,
            'file_path': f'/data/{f}',
            'timestamp': ts.strftime('%Y-%m-%d %H:%M:%S'),
            'risk_level': 'High Risk' if r < 0.5 else 'Suspicious',
            'event_history': []
        })

    events.sort(key=lambda e: _parse_ts(e['timestamp']))
    for i, e in enumerate(events):
        e['event_history'] = events[max(0, i - 50):i]

    return events, profile


def events_to_training_data(events, profile):
    X_list = []
    y_list = []
    for e in events:
        feats = extract_features_single(
            e['user_id'], e['activity_type'], e['file_path'],
            e['timestamp'], e.get('event_history', []), profile
        )
        X_list.append(features_to_vector(feats))
        if e.get('ground_truth_anomaly') is not None:
            y_list.append(1 if int(e['ground_truth_anomaly']) else 0)
        else:
            risk = e.get('risk_level', 'Normal')
            y_list.append(1 if risk in ['Suspicious', 'High Risk'] else 0)
    return np.array(X_list, dtype=np.float64), np.array(y_list)


def train_from_db(db_get_events, db_get_profile):
    events = db_get_events(500) if callable(db_get_events) else (db_get_events or [])
    profile = db_get_profile()
    if not profile:
        profile = {'avg_ops_per_hour': 15, 'normal_delete_limit': 3,
                   'normal_modify_limit': 5, 'work_start_time': '08:00', 'work_end_time': '17:00'}

    events_sorted = sorted(events, key=lambda e: _parse_ts(e.get('timestamp')))
    for i, e in enumerate(events_sorted):
        e['event_history'] = events_sorted[max(0, i - 50):i]

    if len(events) < 50:
        syn_events, profile = generate_synthetic_events(500, 150)
        X, y = events_to_training_data(syn_events, profile)
    else:
        X, y = events_to_training_data(events_sorted, profile)

    if len(np.unique(y)) < 2:
        syn_events, _ = generate_synthetic_events(200, 100)
        X2, y2 = events_to_training_data(syn_events, profile)
        X = np.vstack([X, X2])
        y = np.concatenate([y, y2])

    train_isolation_forest(X, contamination=0.15)
    train_lightgbm(X, y)
    train_autoencoder(X, encoding_dim=8, epochs=30, batch_size=32)

    return {'samples': len(X), 'anomalies': int(y.sum()), 'normal': int(len(y) - y.sum())}


def train_from_synthetic():
    events, profile = generate_synthetic_events(600, 200)
    X, y = events_to_training_data(events, profile)
    train_isolation_forest(X, contamination=0.2)
    train_lightgbm(X, y)
    train_autoencoder(X, encoding_dim=8, epochs=30, batch_size=32)
    return {'samples': len(X), 'anomalies': int(y.sum()), 'normal': int(len(y) - y.sum())}


def train_from_guardian_synthetic(n_banking=650, n_employee=950, export_csv=False):
    from synthetic_dataset import (
        build_guardian_events_from_synthetic,
        attach_event_history,
        export_csvs_to_dataset_folder,
    )

    if export_csv:
        export_csvs_to_dataset_folder()
    events, profile = build_guardian_events_from_synthetic(n_banking, n_employee)
    attach_event_history(events)
    X, y = events_to_training_data(events, profile)
    if len(np.unique(y)) < 2:
        syn_events, profile2 = generate_synthetic_events(300, 120)
        X2, y2 = events_to_training_data(syn_events, profile2)
        X = np.vstack([X, X2])
        y = np.concatenate([y, y2])

    contam = min(0.25, max(0.08, float(y.sum()) / max(len(y), 1)))
    train_isolation_forest(X, contamination=contam)
    train_lightgbm(X, y)
    train_autoencoder(X, encoding_dim=8, epochs=30, batch_size=32)
    return {
        'samples': len(X),
        'anomalies': int(y.sum()),
        'normal': int(len(y) - y.sum()),
        'dataset': 'guardian_banking_employee_synthetic',
    }


DATASETS_DIR = os.path.join(os.path.dirname(__file__), '..', 'datasets')

UNSW_NUMERIC_COLS = [
    'dur', 'sbytes', 'dbytes', 'sttl', 'dttl', 'sloss', 'dloss',
    'Sload', 'Dload', 'Spkts', 'Dpkts', 'swin', 'dwin', 'stcpb', 'dtcpb',
    'smeansz', 'dmeansz', 'trans_depth', 'res_bdy_len', 'Sjit', 'Djit',
    'Sintpkt', 'Dintpkt', 'tcprtt', 'synack', 'ackdat',
    'is_sm_ips_ports', 'ct_state_ttl', 'ct_srv_src', 'ct_srv_dst',
    'ct_dst_ltm', 'ct_src_ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm'
]


def load_unsw_nb15_from_huggingface(max_samples=50000):
    try:
        from datasets import load_dataset
        ds = load_dataset("Mouwiya/UNSW-NB15", split="train")
        df = ds.to_pandas()
        if len(df) > max_samples:
            df = df.sample(n=max_samples, random_state=42)
        numeric_cols = [c for c in UNSW_NUMERIC_COLS if c in df.columns]
        if not numeric_cols:
            all_num = [c for c in df.select_dtypes(include=[np.number]).columns if c != 'label']
            numeric_cols = all_num[:17] if all_num else []
        else:
            numeric_cols = numeric_cols[:17]
        label_col = 'label' if 'label' in df.columns else 'Label'
        if label_col not in df.columns:
            return None, None
        X = df[numeric_cols].fillna(0).values.astype(np.float64)
        y = df[label_col].values
        y_binary = (y != 0).astype(int) if y.max() > 1 else y.astype(int)
        return X, y_binary
    except Exception as e:
        print(f"HuggingFace load error: {e}")
        return None, None


def load_unsw_nb15_if_available(csv_path=None):
    X, y = load_unsw_nb15_from_huggingface()
    if X is not None:
        return X, y
    if csv_path is None:
        csv_path = os.path.join(DATASETS_DIR, 'UNSW-NB15', 'UNSW_NB15_training-set.csv')
    if not os.path.exists(csv_path):
        return None, None
    try:
        df = pd.read_csv(csv_path, nrows=50000)
        label_col = 'label' if 'label' in df.columns else 'Label'
        if label_col not in df.columns:
            return None, None
        numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        if label_col in numeric_cols:
            numeric_cols.remove(label_col)
        X = df[numeric_cols[:20]].fillna(0).values
        y = df[label_col].values
        y_binary = (y != 0).astype(int) if y.max() > 1 else y
        return X, y_binary
    except Exception:
        return None, None


def load_cicids2017_if_available(csv_path=None):
    if csv_path is None:
        if os.path.exists(DATASETS_DIR):
            for name in os.listdir(DATASETS_DIR):
                folder = os.path.join(DATASETS_DIR, name)
                if os.path.isdir(folder) and ('CICIDS' in name or 'cicids' in name.lower()):
                    for f in os.listdir(folder):
                        if f.endswith('.csv'):
                            x, y = load_cicids2017_from_file(os.path.join(folder, f))
                            if x is not None:
                                return x, y
        return None, None
    return load_cicids2017_from_file(csv_path)


def load_cicids2017_from_file(path):
    try:
        df = pd.read_csv(path, nrows=30000)
        label_col = 'Label' if 'Label' in df.columns else 'label'
        if label_col not in df.columns:
            return None, None
        numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        if label_col in numeric_cols:
            numeric_cols.remove(label_col)
        X = df[numeric_cols[:20]].fillna(0).values
        y = df[label_col]
        y_binary = (y != 'BENIGN').astype(int) if y.dtype == object else (y != 0).astype(int)
        return X, y_binary
    except Exception:
        return None, None
