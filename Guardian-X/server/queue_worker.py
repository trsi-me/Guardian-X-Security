# -*- coding: utf-8 -*-
import json
import pika
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))

import db
from ai_model import analyze_event
from feature_extractor import extract_features_single, features_to_vector
from ml_models import MLEnsemble
from explainability import explain_anomaly

RABBITMQ_HOST = 'localhost'
QUEUE_NAME = 'guardian_events'


def process_event(event_data):
    user_id = event_data.get('user_id', 'anonymous')
    activity_type = event_data.get('activity_type', 'Read')
    file_path = event_data.get('file_path', '')
    timestamp = event_data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    event_time = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')

    profile = db.get_behavior_profile() or {
        'avg_ops_per_hour': 15, 'normal_delete_limit': 3,
        'normal_modify_limit': 5, 'work_start_time': '08:00', 'work_end_time': '17:00'
    }
    events = db.get_file_events(200)

    risk_level, reason, score = analyze_event(
        user_id, activity_type, file_path, timestamp, events, profile
    )

    event_id = db.add_file_event(user_id, activity_type, file_path, risk_level, reason, event_time=timestamp)

    if risk_level in ['Suspicious', 'High Risk']:
        detect_time = datetime.now()
        mttd_seconds = (detect_time - event_time).total_seconds()

        alert_id = db.add_alert(
            user_id, risk_level, reason, str(event_id),
            event_time=timestamp,
            detect_time=detect_time.strftime('%Y-%m-%d %H:%M:%S'),
            mttd_seconds=mttd_seconds
        )

        if risk_level == 'High Risk':
            respond_time = datetime.now()
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
                summary = '; '.join(exp.get('summary', []))
                db.add_explanation(
                    event_id,
                    shap_json=json.dumps(exp.get('shap')) if exp.get('shap') else None,
                    lime_json=json.dumps(exp.get('lime')) if exp.get('lime') else None,
                    summary_text=summary
                )
        except Exception:
            pass

    print(f"[{datetime.now().strftime('%H:%M:%S')}] Processed: {activity_type} by {user_id} -> {risk_level} (score: {score:.1f})")
    return risk_level, score


def callback(ch, method, properties, body):
    try:
        event_data = json.loads(body)
        process_event(event_data)
        ch.basic_ack(delivery_tag=method.delivery_tag)
    except Exception as e:
        print(f"Error processing event: {e}")
        ch.basic_nack(delivery_tag=method.delivery_tag)


def start_worker():
    db.init_db()
    connection = pika.BlockingConnection(pika.ConnectionParameters(host=RABBITMQ_HOST))
    channel = connection.channel()
    channel.queue_declare(queue=QUEUE_NAME, durable=True)
    channel.basic_qos(prefetch_count=1)
    channel.basic_consume(queue=QUEUE_NAME, on_message_callback=callback)

    print(f"Guardian-X Queue Worker started")
    print(f"Listening on queue: {QUEUE_NAME}")
    print("Waiting for events... (Ctrl+C to stop)\n")

    try:
        channel.start_consuming()
    except KeyboardInterrupt:
        channel.stop_consuming()
    connection.close()


def publish_event(event_data):
    try:
        connection = pika.BlockingConnection(pika.ConnectionParameters(host=RABBITMQ_HOST))
        channel = connection.channel()
        channel.queue_declare(queue=QUEUE_NAME, durable=True)
        channel.basic_publish(
            exchange='',
            routing_key=QUEUE_NAME,
            body=json.dumps(event_data),
            properties=pika.BasicProperties(delivery_mode=2)
        )
        connection.close()
        return True
    except Exception as e:
        print(f"RabbitMQ publish error: {e}")
        return False


if __name__ == '__main__':
    start_worker()
