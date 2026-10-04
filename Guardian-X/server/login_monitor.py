# -*- coding: utf-8 -*-
from datetime import datetime, timedelta
from collections import defaultdict

# قاموس لتخزين محاولات الدخول في الذاكرة
_login_attempts = defaultdict(list)
_known_locations = defaultdict(set)


def _parse_ts(ts):
    if isinstance(ts, datetime):
        return ts
    try:
        return datetime.strptime(str(ts)[:19], '%Y-%m-%d %H:%M:%S')
    except Exception:
        return datetime.now()


def analyze_login(user_id, ip_address, success, timestamp=None, user_agent=None):
    ts = _parse_ts(timestamp) if timestamp else datetime.now()
    reasons = []
    risk_level = 'Normal'

    # تسجيل المحاولة
    _login_attempts[user_id].append({
        'ip': ip_address,
        'success': success,
        'timestamp': ts,
        'user_agent': user_agent
    })

    # الاحتفاظ بآخر 100 محاولة فقط
    if len(_login_attempts[user_id]) > 100:
        _login_attempts[user_id] = _login_attempts[user_id][-100:]

    attempts = _login_attempts[user_id]

    # --- قاعدة 1: محاولات فاشلة متكررة (Brute Force) ---
    five_min_ago = ts - timedelta(minutes=5)
    recent_failures = [
        a for a in attempts
        if not a['success'] and _parse_ts(a['timestamp']) >= five_min_ago
    ]
    if len(recent_failures) >= 5:
        risk_level = 'High Risk'
        reasons.append(f'محاولات دخول فاشلة متكررة ({len(recent_failures)} في 5 دقائق) - Brute Force')

    # --- قاعدة 2: دخول من موقع جديد بعد فشل ---
    if success and ip_address not in _known_locations[user_id]:
        recent_failures_before = [
            a for a in attempts
            if not a['success'] and _parse_ts(a['timestamp']) >= ts - timedelta(hours=1)
        ]
        if recent_failures_before:
            if risk_level != 'High Risk':
                risk_level = 'High Risk'
            reasons.append(f'دخول ناجح من IP جديد ({ip_address}) بعد محاولات فاشلة - Account Takeover')
        else:
            if risk_level == 'Normal':
                risk_level = 'Suspicious'
            reasons.append(f'دخول من موقع جديد غير مسجل ({ip_address})')

    # --- قاعدة 3: دخول في وقت غير عادي ---
    hour = ts.hour
    if hour < 6 or hour > 22:
        if risk_level == 'Normal':
            risk_level = 'Suspicious'
        reasons.append(f'محاولة دخول في وقت غير عادي ({ts.strftime("%H:%M")})')

    # --- قاعدة 4: دخول من أجهزة مختلفة في وقت قصير ---
    if user_agent:
        one_hour_ago = ts - timedelta(hours=1)
        recent_agents = set(
            a['user_agent'] for a in attempts
            if a.get('user_agent') and _parse_ts(a['timestamp']) >= one_hour_ago
        )
        if len(recent_agents) >= 3:
            if risk_level == 'Normal':
                risk_level = 'Suspicious'
            reasons.append(f'دخول من {len(recent_agents)} أجهزة مختلفة في ساعة واحدة')

    # تسجيل الموقع لو الدخول ناجح
    if success:
        _known_locations[user_id].add(ip_address)

    reason = ' | '.join(reasons) if reasons else 'محاولة دخول طبيعية'
    return risk_level, reason


def get_login_stats(user_id):
    attempts = _login_attempts.get(user_id, [])
    if not attempts:
        return {'total': 0, 'success': 0, 'failed': 0, 'known_locations': 0}

    return {
        'total': len(attempts),
        'success': sum(1 for a in attempts if a['success']),
        'failed': sum(1 for a in attempts if not a['success']),
        'known_locations': len(_known_locations.get(user_id, set()))
    }
