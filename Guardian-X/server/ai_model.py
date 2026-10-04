# -*- coding: utf-8 -*-
from datetime import datetime, timedelta

from rules import apply_rules
from feature_extractor import extract_features_single, features_to_vector
from ml_models import MLEnsemble

_ensemble = None


def _get_ensemble():
    global _ensemble
    if _ensemble is None:
        _ensemble = MLEnsemble()
    return _ensemble


def _parse_ts(ts):
    if ts is None:
        return datetime.now()
    if isinstance(ts, datetime):
        return ts
    try:
        return datetime.strptime(str(ts)[:19], '%Y-%m-%d %H:%M:%S')
    except Exception:
        return datetime.now()


def _threshold_fallback(events, profile):
    if not events:
        return 0, 'Normal'
    score = 0
    delete_limit = profile.get('normal_delete_limit', 3)
    modify_limit = profile.get('normal_modify_limit', 5)
    avg_ops = profile.get('avg_ops_per_hour', 15)

    delete_count = sum(1 for e in events if e.get('activity_type') == 'Delete')
    modify_count = sum(1 for e in events if e.get('activity_type') == 'Modify')
    hour_ago = datetime.now() - timedelta(hours=1)
    recent = [e for e in events if _parse_ts(e.get('timestamp')) > hour_ago]
    ops_per_hour = len(recent)

    if delete_count > delete_limit * 2:
        score += 50
    elif delete_count > delete_limit:
        score += 25
    if modify_count > modify_limit * 2:
        score += 30
    elif modify_count > modify_limit:
        score += 15
    if ops_per_hour > avg_ops * 3:
        score += 40
    elif ops_per_hour > avg_ops * 2:
        score += 20

    score = min(100, score)
    risk = 'High Risk' if score >= 70 else 'Suspicious' if score >= 35 else 'Normal'
    return score, risk


def analyze_event(user_id, activity_type, file_path, timestamp, event_history, profile,
                  return_features=False):
    context = {
        'delete_count_10min': 0,
        'modify_count_hour': 0,
        'same_file_access_count': 0,
        'transaction_count_10min': 0
    }

    ts = _parse_ts(timestamp)
    ten_min_ago = ts - timedelta(minutes=10)
    hour_ago = ts - timedelta(hours=1)

    for e in (event_history or []):
        et = _parse_ts(e.get('timestamp'))
        if e.get('user_id') != user_id:
            continue
        if ten_min_ago <= et <= ts and e.get('activity_type') == 'Delete':
            context['delete_count_10min'] += 1
        if hour_ago <= et <= ts and e.get('activity_type') == 'Modify':
            context['modify_count_hour'] += 1
        if ten_min_ago <= et <= ts and e.get('activity_type') == 'Transaction':
            context['transaction_count_10min'] += 1
        if e.get('file_path') == file_path and (ts - et).total_seconds() < 60:
            context['same_file_access_count'] += 1

    # Layer 1: Rule-based
    risk_level, reason = apply_rules(activity_type, file_path, timestamp, context, profile)

    # Layer 2: ML Ensemble
    ensemble = _get_ensemble()
    combined_events = list(event_history or []) + [{
        'user_id': user_id,
        'activity_type': activity_type,
        'file_path': file_path,
        'timestamp': timestamp
    }]

    if ensemble.is_ready():
        feats = extract_features_single(
            user_id, activity_type, file_path, timestamp,
            event_history, profile
        )
        X = [features_to_vector(feats)]
        ml_score, ml_risk = ensemble.predict(X)
        # Combine: take higher risk
        if ml_risk == 'High Risk' or risk_level == 'High Risk':
            risk_level = 'High Risk'
            if 'AI detected anomaly' not in reason and ml_risk == 'High Risk':
                reason = reason + '; AI ensemble: High Risk' if reason != 'Normal activity' else 'AI ensemble: High Risk'
        elif ml_risk == 'Suspicious' and risk_level == 'Normal':
            risk_level = 'Suspicious'
            reason = reason + '; AI anomaly score elevated' if reason != 'Normal activity' else 'AI anomaly score elevated'
        score = ml_score
        features_dict = feats if return_features else None
    else:
        score, _ = _threshold_fallback(combined_events, profile)
        if _ == 'High Risk' and risk_level != 'High Risk':
            risk_level = 'High Risk'
            reason = reason + '; Threshold anomaly' if reason != 'Normal activity' else 'Threshold anomaly'
        elif _ == 'Suspicious' and risk_level == 'Normal':
            risk_level = 'Suspicious'
            reason = reason + '; Threshold elevated' if reason != 'Normal activity' else 'Threshold elevated'
        features_dict = extract_features_single(
            user_id, activity_type, file_path, timestamp,
            event_history, profile
        ) if return_features else None

    if return_features:
        return risk_level, reason, score, features_dict
    return risk_level, reason, score
