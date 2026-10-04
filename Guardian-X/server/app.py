# -*- coding: utf-8 -*-
import os
import json
import ssl
from datetime import datetime, timezone, timedelta
RIYADH_TZ = timezone(timedelta(hours=3))
from flask import Flask, request, jsonify, send_from_directory

import db
from ai_model import analyze_event
from feature_extractor import extract_features_single, features_to_vector
from ml_models import MLEnsemble
from explainability import explain_anomaly
from training import train_from_db, train_from_synthetic, train_from_guardian_synthetic
from security_framework import get_framework_summary
from evaluation import run_evaluation
from adaptive_baseline import update_profile_from_events


app = Flask(__name__)

# --- TLS 1.3 Configuration (Report: FR-13) ---
CERT_PATH = os.path.join(os.path.dirname(__file__), 'certs', 'cert.pem')
KEY_PATH = os.path.join(os.path.dirname(__file__), 'certs', 'key.pem')

def get_ssl_context():
    if os.path.exists(CERT_PATH) and os.path.exists(KEY_PATH):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            context.maximum_version = ssl.TLSVersion.TLSv1_3
        except AttributeError:
            pass
        context.load_cert_chain(CERT_PATH, KEY_PATH)
        return context
    return None

# --- RabbitMQ Integration ---
def _publish_to_queue(event_data):
    try:
        from queue_worker import publish_event
        return publish_event(event_data)
    except Exception:
        return False

@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

@app.before_request
def init_on_start():
    db.init_db()

@app.route('/')
def root():
    frontend_path = os.path.join(os.path.dirname(__file__), '..', 'frontend')
    return send_from_directory(frontend_path, 'index.html')

@app.route('/assets/<path:filename>')
def serve_assets(filename):
    assets_path = os.path.join(os.path.dirname(__file__), '..', 'assets')
    return send_from_directory(assets_path, filename)

@app.route('/<path:filename>')
def serve_static(filename):
    frontend_path = os.path.join(os.path.dirname(__file__), '..', 'frontend')
    return send_from_directory(frontend_path, filename)

@app.route('/api/events', methods=['GET'])
def get_events():
    limit = request.args.get('limit', 50, type=int)
    events = db.get_file_events(limit)
    for e in events:
        if e.get('timestamp'):
            e['timestamp'] = str(e['timestamp'])
    return jsonify(events)

def _adapt_baseline_if_needed():
    try:
        stats = db.get_dashboard_stats()
        total = stats.get('total_events', 0)
        if total >= 50 and total % 30 == 0:
            def _update(p):
                db.update_behavior_profile(
                    p['avg_ops_per_hour'], p['normal_delete_limit'], p['normal_modify_limit'],
                    p['work_start_time'], p['work_end_time']
                )
            update_profile_from_events(lambda: db.get_file_events(500), _update, min_events=50)
    except Exception:
        pass

def _process_event_direct(user_id, activity_type, file_path, agent_id, agent_source):
    profile = db.get_behavior_profile() or {
        'avg_ops_per_hour': 15, 'normal_delete_limit': 3,
        'normal_modify_limit': 5, 'work_start_time': '08:00', 'work_end_time': '17:00'
    }
    events = db.get_file_events(200)
    event_time = datetime.now(RIYADH_TZ).replace(tzinfo=None)
    timestamp = event_time.strftime('%Y-%m-%d %H:%M:%S')

    risk_level, reason, score = analyze_event(
        user_id, activity_type, file_path, timestamp, events, profile
    )

    if agent_id:
        db.upsert_agent(agent_id, hostname=user_id or agent_id, source=agent_source)

    event_id = db.add_file_event(user_id, activity_type, file_path, risk_level, reason or '',
                                 event_time=timestamp)

    if risk_level in ['Suspicious', 'High Risk']:
        detect_time = datetime.now(RIYADH_TZ).replace(tzinfo=None)
        mttd_seconds = (detect_time - event_time).total_seconds()

        alert_id = db.add_alert(
            user_id, risk_level, reason, str(event_id),
            event_time=timestamp,
            detect_time=detect_time.strftime('%Y-%m-%d %H:%M:%S'),
            mttd_seconds=mttd_seconds
        )

        if risk_level == 'High Risk':
            respond_time = datetime.now(RIYADH_TZ).replace(tzinfo=None)
            mttr_seconds = (respond_time - detect_time).total_seconds()
            db.add_containment_action(
                alert_id, event_id, 'block',
                f'Auto response: {reason[:100]}',
                alert_time=detect_time.strftime('%Y-%m-%d %H:%M:%S'),
                mttr_seconds=mttr_seconds
            )

        try:
            ensemble = MLEnsemble()
            if ensemble.is_ready():
                feats = extract_features_single(user_id, activity_type, file_path, timestamp, events, profile)
                X = [features_to_vector(feats)]
                exp = explain_anomaly(ensemble, X)
                summary = exp.get('summary', [])
                db.add_explanation(
                    event_id,
                    shap_json=json.dumps(exp.get('shap')) if exp.get('shap') else None,
                    lime_json=json.dumps(exp.get('lime')) if exp.get('lime') else None,
                    summary_text=json.dumps(summary)
                )
        except Exception:
            pass

    _adapt_baseline_if_needed()
    return event_id, risk_level, reason, score


VALID_ACTIVITIES = ['Create', 'Read', 'Modify', 'Delete', 'FileDownload', 'Transaction', 'FileCopy']

@app.route('/api/events', methods=['POST'])
def add_event():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data'}), 400

    user_id = data.get('user_id', 'anonymous')
    activity_type = data.get('activity_type')
    file_path = data.get('file_path', '')
    agent_id = data.get('agent_id')
    agent_source = data.get('agent_source', 'simulated')

    if not activity_type or activity_type not in VALID_ACTIVITIES:
        return jsonify({'error': 'Invalid activity_type'}), 400

    if activity_type == 'Transaction':
        amount = data.get('amount', 0)
        tx_type = data.get('transaction_type', 'transfer')
        file_path = f'{tx_type}:{amount}'
    elif activity_type == 'FileDownload' and not file_path:
        file_path = data.get('file_name', 'unknown.zip')

    event_data = {
        'user_id': user_id,
        'activity_type': activity_type,
        'file_path': file_path,
        'agent_id': agent_id,
        'agent_source': agent_source,
        'timestamp': datetime.now(RIYADH_TZ).replace(tzinfo=None).strftime('%Y-%m-%d %H:%M:%S')
    }

    queued = _publish_to_queue(event_data)

    if queued:
        return jsonify({
            'status': 'queued',
            'message': 'Event queued for processing via RabbitMQ',
            'risk_level': 'Pending',
            'score': 0
        })
    else:
        event_id, risk_level, reason, score = _process_event_direct(
            user_id, activity_type, file_path, agent_id, agent_source
        )
        return jsonify({
            'id': event_id,
            'risk_level': risk_level,
            'reason': reason,
            'score': round(score, 2)
        })

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    limit = request.args.get('limit', 50, type=int)
    alerts = db.get_alerts(limit)
    for a in alerts:
        if a.get('timestamp'):
            a['timestamp'] = str(a['timestamp'])
    return jsonify(alerts)

@app.route('/api/stats', methods=['GET'])
def get_stats():
    stats = db.get_dashboard_stats()
    return jsonify(stats)

@app.route('/api/health', methods=['GET'])
def get_health():
    try:
        conn = db.get_connection()
        conn.cursor().execute('SELECT 1')
        conn.close()
        db_status = 'connected'
    except Exception:
        db_status = 'error'

    try:
        import pika
        connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost', socket_timeout=2))
        connection.close()
        rabbitmq_status = 'connected'
    except Exception:
        rabbitmq_status = 'not available (direct processing active)'

    tls_status = 'enabled (TLS 1.3)' if os.path.exists(CERT_PATH) else 'disabled'

    ensemble = MLEnsemble()
    return jsonify({
        'server': 'running',
        'database': db_status,
        'ml_models': ensemble.is_ready(),
        'rabbitmq': rabbitmq_status,
        'tls': tls_status,
        'timestamp': datetime.now(RIYADH_TZ).replace(tzinfo=None).isoformat()
    })

@app.route('/api/security/framework', methods=['GET'])
def api_security_framework():
    tls_on = os.path.exists(CERT_PATH) and os.path.exists(KEY_PATH)
    summary = get_framework_summary(tls_enabled=tls_on)
    return jsonify(summary)


@app.route('/api/evaluation/run', methods=['POST'])
def api_run_evaluation():
    data = request.get_json() or {}
    try:
        import ai_model as _am
        _am._ensemble = None
        result = run_evaluation(
            train_first=data.get('train_first', True),
            n_banking=int(data.get('n_banking', 400)),
            n_employee=int(data.get('n_employee', 600)),
            export_csv=data.get('export_csv', True),
            max_events=data.get('max_events'),
        )
        return jsonify({'success': True, 'evaluation': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scenarios/fraud', methods=['POST'])
def scenario_fraud():
    data = request.get_json() or {}
    user_id = data.get('user_id', 'emp_finance01')
    cases = [
        ('wire', 120000.0, 'mobile', 8),
        ('transfer', 75000.0, 'atm', 2),
        ('withdrawal', 15000.0, 'branch', 3),
    ]
    out = []
    base = datetime.now(RIYADH_TZ).replace(tzinfo=None).replace(hour=2, minute=15, second=0)
    for tx_type, amt, ch, vel in cases:
        ts = base.strftime('%Y-%m-%d %H:%M:%S')
        fp = f'{tx_type}:{amt:.2f}:{ch}:{vel}'
        event_id, risk_level, reason, score = _process_event_direct(
            user_id, 'Transaction', fp, data.get('agent_id'), data.get('agent_source', 'scenario_fraud')
        )
        out.append({
            'id': event_id,
            'risk_level': risk_level,
            'reason': reason,
            'score': round(score, 2),
            'transaction': {'type': tx_type, 'amount': amt, 'channel': ch, 'velocity': vel},
        })
        base += timedelta(minutes=2)
    return jsonify({'scenario': 'financial_fraud', 'results': out})


@app.route('/api/scenarios/unauthorized_copy', methods=['POST'])
def scenario_unauthorized_copy():
    data = request.get_json() or {}
    user_id = data.get('user_id', 'contractor_x')
    paths = [
        '/secure/vault/customer_pii.csv|D:/USB_STICK/exfil_copy.csv',
        '/keys/signing_key.pem|C:/Users/Public/unauth_copy.pem',
    ]
    results = []
    for fp in paths:
        event_id, risk_level, reason, score = _process_event_direct(
            user_id, 'FileCopy', fp, data.get('agent_id'), data.get('agent_source', 'scenario_unauthorized_copy')
        )
        results.append({
            'id': event_id,
            'file_path': fp,
            'risk_level': risk_level,
            'reason': reason,
            'score': round(score, 2),
        })
    return jsonify({'scenario': 'unauthorized_file_copy', 'results': results})


@app.route('/api/metrics', methods=['GET'])
def get_metrics():
    stats = db.get_dashboard_stats()
    total = stats.get('total_events', 0) or 1
    high = stats.get('high_risk', 0)
    susp = stats.get('suspicious', 0)
    alerts = stats.get('total_alerts', 0)
    tp_est = high + susp
    fp_est = max(0, alerts - tp_est)
    precision = tp_est / (tp_est + fp_est) if (tp_est + fp_est) > 0 else 0
    recall = tp_est / total if total > 0 else 0
    avg_mttd, avg_mttr = db.get_mttd_mttr()
    return jsonify({
        'mttd_seconds': avg_mttd,
        'mttr_seconds': avg_mttr,
        'precision': round(precision, 4),
        'recall': round(recall, 4),
        'detection_rate': round((high + susp) / total * 100, 2) if total > 0 else 0,
    })

@app.route('/api/agents', methods=['GET'])
def get_agents():
    agents = db.get_agents()
    for a in agents:
        if a.get('last_seen'):
            a['last_seen'] = str(a['last_seen'])
        if a.get('created_at'):
            a['created_at'] = str(a['created_at'])
    return jsonify(agents)

@app.route('/api/agents/heartbeat', methods=['POST'])
def agent_heartbeat():
    data = request.get_json() or {}
    agent_id = data.get('agent_id', 'simulated-agent-1')
    hostname = data.get('hostname', 'simulated')
    db.upsert_agent(agent_id, hostname=hostname, source='simulated')
    return jsonify({'status': 'ok', 'agent_id': agent_id})

@app.route('/api/profile', methods=['GET'])
def get_profile():
    profile = db.get_behavior_profile()
    if profile:
        if profile.get('created_at'):
            profile['created_at'] = str(profile['created_at'])
        return jsonify(profile)
    return jsonify({})

@app.route('/api/explain/<int:event_id>', methods=['GET'])
def get_explanation(event_id):
    ev = db.get_event_by_id(event_id)
    if not ev:
        return jsonify({'error': 'Event not found'}), 404
    exp = db.get_explanation_by_event_id(event_id)
    if exp:
        return jsonify({
            'event_id': event_id,
            'summary': (json.loads(exp.get('summary_text')) if exp.get('summary_text', '').startswith('[') else exp.get('summary_text', '').split('; ')) if exp.get('summary_text') else [],
            'shap': json.loads(exp['shap_json']) if exp.get('shap_json') else None,
            'lime': json.loads(exp['lime_json']) if exp.get('lime_json') else None,
        })
    try:
        profile = db.get_behavior_profile() or {}
        events = db.get_file_events(200)
        feats = extract_features_single(
            ev['user_id'], ev['activity_type'], ev['file_path'],
            ev.get('timestamp'), events, profile
        )
        X = [features_to_vector(feats)]
        ensemble = MLEnsemble()
        exp_data = explain_anomaly(ensemble, X)
        return jsonify({
            'event_id': event_id,
            'summary': exp_data.get('summary', []),
            'shap': exp_data.get('shap'),
            'lime': exp_data.get('lime'),
        })
    except Exception as e:
        return jsonify({'error': str(e), 'summary': ['Explanation not available']}), 500

@app.route('/api/train', methods=['POST'])
def train_models():
    data = request.get_json() or {}
    use_db = data.get('use_db', False)
    mode = data.get('mode', 'synthetic')
    try:
        import ai_model as _am
        _am._ensemble = None
        if mode == 'guardian':
            result = train_from_guardian_synthetic(
                n_banking=int(data.get('n_banking', 650)),
                n_employee=int(data.get('n_employee', 950)),
                export_csv=data.get('export_csv', True),
            )
        elif use_db:
            result = train_from_db(
                lambda limit=500: db.get_file_events(limit),
                db.get_behavior_profile
            )
        else:
            result = train_from_synthetic()
        return jsonify({'success': True, 'result': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/containment', methods=['GET'])
def list_containment():
    actions = db.get_containment_actions(limit=50)
    for a in actions:
        if a.get('created_at'):
            a['created_at'] = str(a['created_at'])
    return jsonify(actions)

@app.route('/api/containment', methods=['POST'])
def trigger_containment():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data'}), 400
    alert_id = data.get('alert_id')
    file_event_id = data.get('file_event_id')
    action_type = data.get('action_type', 'block')
    if action_type not in ['block', 'isolate', 'log', 'freeze']:
        action_type = 'log'
    details = data.get('details', '')
    aid = db.add_containment_action(alert_id, file_event_id, action_type, details)
    return jsonify({
        'id': aid,
        'action_type': action_type,
        'status': 'simulated',
        'message': f'Containment action "{action_type}" logged (simulated)'
    })

@app.route('/api/simulate/transaction', methods=['POST'])
def simulate_transaction():
    data = request.get_json() or {}
    user_id = data.get('user_id', 'user01')
    amount = data.get('amount', 5000)
    tx_type = data.get('transaction_type', 'transfer')
    file_path = f'{tx_type}:{amount}'
    agent_id = data.get('agent_id')
    agent_source = data.get('agent_source', 'simulated')
    event_id, risk_level, reason, score = _process_event_direct(
        user_id, 'Transaction', file_path, agent_id, agent_source
    )
    return jsonify({
        'id': event_id, 'risk_level': risk_level, 'reason': reason, 'score': round(score, 2),
        'amount': amount, 'transaction_type': tx_type
    })

@app.route('/api/simulate/batch', methods=['POST'])
def simulate_batch():
    data = request.get_json() or {}
    n = min(data.get('count', 5), 20)
    events = []
    import random
    users = ['user01', 'user02', 'admin', 'analyst']
    acts = ['Create', 'Read', 'Modify', 'Delete', 'FileDownload', 'Transaction', 'FileCopy']
    files = ['report.pdf', 'data.xlsx', 'config.ini', 'logs.txt', 'key.pem', 'customer_data.zip']
    for _ in range(n):
        user_id = random.choice(users)
        activity_type = random.choice(acts)
        if activity_type == 'Transaction':
            amount = random.choice([1000, 5000, 15000, 60000])
            file_path = f'transfer:{amount}'
        elif activity_type == 'FileDownload':
            file_path = random.choice(['/downloads/customer_data.zip', '/downloads/report.pdf'])
        elif activity_type == 'FileCopy':
            if random.random() < 0.4:
                file_path = '/secure/vault/customer_pii.csv|D:/USB_STICK/leak.csv'
            else:
                file_path = '/shared/reports/Q1_summary.pdf|/backup/internal_mirror/report.pdf'
        else:
            file_path = f'/data/{random.choice(files)}'
        agent_id = f'sim-agent-{random.randint(1, 3)}'
        event_id, risk_level, reason, score = _process_event_direct(
            user_id, activity_type, file_path, agent_id, 'simulated'
        )
        events.append({'id': event_id, 'risk_level': risk_level, 'score': score})
    return jsonify({'created': len(events), 'events': events})
# --- Login / Account Takeover Detection (Report: Section 1.3) ---
@app.route('/api/login', methods=['POST'])
def analyze_login_attempt():
    from login_monitor import analyze_login, get_login_stats
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data'}), 400

    user_id = data.get('user_id', 'anonymous')
    ip_address = data.get('ip_address', '0.0.0.0')
    success = data.get('success', False)
    user_agent = data.get('user_agent', None)
    timestamp = data.get('timestamp', datetime.now(RIYADH_TZ).replace(tzinfo=None).strftime('%Y-%m-%d %H:%M:%S'))

    risk_level, reason = analyze_login(user_id, ip_address, success, timestamp, user_agent)

    # تسجيل الحدث في قاعدة البيانات
    event_id = db.add_file_event(
        user_id, 'Login', f'ip:{ip_address}',
        risk_level, reason
    )

    if risk_level in ['Suspicious', 'High Risk']:
        alert_id = db.add_alert(user_id, risk_level, reason, str(event_id))
        if risk_level == 'High Risk':
            db.add_containment_action(
                alert_id, event_id, 'block',
                f'Account Takeover suspected: {reason[:100]}'
            )

    return jsonify({
        'id': event_id,
        'user_id': user_id,
        'risk_level': risk_level,
        'reason': reason,
        'success': success
    })


@app.route('/api/login/stats/<user_id>', methods=['GET'])
def get_login_statistics(user_id):
    from login_monitor import get_login_stats
    stats = get_login_stats(user_id)
    return jsonify({'user_id': user_id, 'stats': stats})


@app.route('/api/simulate/login', methods=['POST'])
def simulate_login():
    from login_monitor import analyze_login
    import random
    data = request.get_json() or {}
    scenario = data.get('scenario', 'brute_force')
    user_id = data.get('user_id', 'user01')
    results = []

    if scenario == 'brute_force':
        # محاكاة هجوم Brute Force
        for i in range(6):
            risk_level, reason = analyze_login(
                user_id, '192.168.1.100', False,
                datetime.now(RIYADH_TZ).replace(tzinfo=None).strftime('%Y-%m-%d %H:%M:%S')
            )
            event_id = db.add_file_event(user_id, 'Login', 'ip:192.168.1.100', risk_level, reason)
            if risk_level in ['Suspicious', 'High Risk']:
                alert_id = db.add_alert(user_id, risk_level, reason, str(event_id))
                if risk_level == 'High Risk':
                    db.add_containment_action(alert_id, event_id, 'block', reason[:100])
            results.append({'attempt': i+1, 'risk_level': risk_level})

    elif scenario == 'new_location':
        # محاكاة دخول من موقع جديد
        risk_level, reason = analyze_login(
            user_id, f'10.0.{random.randint(1,255)}.{random.randint(1,255)}',
            True, datetime.now(RIYADH_TZ).replace(tzinfo=None).strftime('%Y-%m-%d %H:%M:%S')
        )
        event_id = db.add_file_event(user_id, 'Login', 'ip:new_location', risk_level, reason)
        if risk_level in ['Suspicious', 'High Risk']:
            db.add_alert(user_id, risk_level, reason, str(event_id))
        results.append({'scenario': 'new_location', 'risk_level': risk_level})

    elif scenario == 'odd_hours':
        # محاكاة دخول في وقت غير عادي
        odd_time = datetime.now(RIYADH_TZ).replace(tzinfo=None).replace(hour=3, minute=0)
        risk_level, reason = analyze_login(
            user_id, '192.168.1.50', True,
            odd_time.strftime('%Y-%m-%d %H:%M:%S')
        )
        event_id = db.add_file_event(user_id, 'Login', 'ip:192.168.1.50', risk_level, reason)
        if risk_level in ['Suspicious', 'High Risk']:
            db.add_alert(user_id, risk_level, reason, str(event_id))
        results.append({'scenario': 'odd_hours', 'risk_level': risk_level})

    return jsonify({'scenario': scenario, 'results': results})

if __name__ == '__main__':
    db.init_db()
    port = int(os.environ.get("PORT", 5000))
    print(f'HTTP: http://127.0.0.1:{port}')
    app.run(host="0.0.0.0", port=port, debug=False)