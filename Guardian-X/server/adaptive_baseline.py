# -*- coding: utf-8 -*-
from datetime import datetime, timedelta
from collections import defaultdict


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


def compute_behavioral_stats(events, lookback_hours=168):
    if not events:
        return None

    cutoff = datetime.now() - timedelta(hours=lookback_hours)
    recent = [e for e in events if _parse_ts(e.get('timestamp')) >= cutoff]
    if len(recent) < 20:
        return None

    by_user = defaultdict(list)
    for e in recent:
        uid = e.get('user_id') or 'anonymous'
        by_user[uid].append(e)

    all_ops_per_hour = []
    all_deletes_per_10min = []
    all_modifies_per_hour = []
    work_hour_counts = defaultdict(int)
    hour_slots = list(range(24))

    for uid, user_events in by_user.items():
        user_events_sorted = sorted(user_events, key=lambda x: _parse_ts(x.get('timestamp')))

        for i, e in enumerate(user_events_sorted):
            ts = _parse_ts(e.get('timestamp'))
            hour_ago = ts - timedelta(hours=1)
            ten_min_ago = ts - timedelta(minutes=10)

            ops_last_hour = sum(1 for x in user_events_sorted
                               if hour_ago <= _parse_ts(x.get('timestamp')) <= ts)
            deletes_10min = sum(1 for x in user_events_sorted
                               if ten_min_ago <= _parse_ts(x.get('timestamp')) <= ts
                               and x.get('activity_type') == 'Delete')
            modifies_hour = sum(1 for x in user_events_sorted
                               if hour_ago <= _parse_ts(x.get('timestamp')) <= ts
                               and x.get('activity_type') == 'Modify')

            all_ops_per_hour.append(ops_last_hour)
            all_deletes_per_10min.append(deletes_10min)
            all_modifies_per_hour.append(modifies_hour)
            work_hour_counts[ts.hour] += 1

    if not all_ops_per_hour:
        return None

    avg_ops = max(1, int(sum(all_ops_per_hour) / len(all_ops_per_hour)))
    p95_ops = sorted(all_ops_per_hour)[int(len(all_ops_per_hour) * 0.95)] if all_ops_per_hour else avg_ops * 2

    delete_counts = [x for x in all_deletes_per_10min if x > 0]
    delete_limit = max(2, int(sum(delete_counts) / max(1, len(delete_counts)) * 1.5)) if delete_counts else 3

    modify_counts = [x for x in all_modifies_per_hour if x > 0]
    modify_limit = max(2, int(sum(modify_counts) / max(1, len(modify_counts)) * 1.5)) if modify_counts else 5

    if work_hour_counts:
        sorted_hours = sorted(work_hour_counts.items(), key=lambda x: -x[1])
        work_start_h = sorted_hours[0][0]
        work_end_h = max(h for h, _ in sorted_hours[:8]) if len(sorted_hours) > 1 else work_start_h + 8
        work_start = f"{work_start_h:02d}:00"
        work_end = f"{min(23, work_end_h):02d}:00"
    else:
        work_start = "08:00"
        work_end = "17:00"

    return {
        'avg_ops_per_hour': min(100, max(5, avg_ops)),
        'normal_delete_limit': min(10, max(2, delete_limit)),
        'normal_modify_limit': min(20, max(2, modify_limit)),
        'work_start_time': work_start,
        'work_end_time': work_end,
    }


def update_profile_from_events(get_events_fn, update_profile_fn, min_events=50):
    events = get_events_fn() if callable(get_events_fn) else (get_events_fn or [])
    stats = compute_behavioral_stats(events)
    if stats and update_profile_fn:
        update_profile_fn(stats)
        return stats
    return None
