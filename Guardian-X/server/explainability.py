# -*- coding: utf-8 -*-
import numpy as np
import pandas as pd
from feature_extractor import get_feature_names


def _to_df(X, feature_names):
    if isinstance(X, pd.DataFrame):
        return X
    return pd.DataFrame(X, columns=feature_names)


def _generate_background(n=50):
    import random
    from feature_extractor import extract_features_single, features_to_vector
    random.seed(42)
    profile = {'avg_ops_per_hour': 15, 'normal_delete_limit': 3,
               'normal_modify_limit': 5, 'work_start_time': '08:00', 'work_end_time': '17:00'}
    users = ['user01', 'user02', 'admin', 'analyst']
    acts = ['Read', 'Create', 'Modify', 'Delete', 'Transaction', 'FileCopy']
    files = ['/data/report.pdf', '/config/settings.env',
             'wire:5000:branch:1', '/data/notes.txt', '/shared/doc.docx']
    rows = []
    for i in range(n):
        hour = random.randint(8, 17) if i < int(n * 0.8) else random.choice([2, 3, 22, 23])
        ts = f'2026-05-{random.randint(1,28):02d} {hour:02d}:{random.randint(0,59):02d}:00'
        feats = extract_features_single(
            random.choice(users), random.choice(acts), random.choice(files), ts, [], profile)
        rows.append(features_to_vector(feats))
    return np.array(rows, dtype=np.float64)


def get_explanation_shap(model, X_sample, feature_names=None):
    try:
        import shap
    except ImportError:
        return {'available': False, 'reason': 'SHAP not installed'}

    if feature_names is None:
        feature_names = get_feature_names()

    try:
        X = np.array(X_sample, dtype=np.float64)
        if X.ndim == 1:
            X = X.reshape(1, -1)
        X_df = _to_df(X, feature_names)

        if hasattr(model, 'predict_proba'):
            # LightGBM — use fast TreeExplainer with proper background DataFrame
            background = _generate_background(50)
            bg_df = _to_df(background, feature_names)
            explainer = shap.TreeExplainer(model, bg_df)
            shap_values = explainer.shap_values(X_df)
            # shap_values is array of shape (n_samples, n_features) for binary class 1
            if isinstance(shap_values, list):
                vals = shap_values[1][0] if len(shap_values) > 1 else shap_values[0][0]
            else:
                vals = shap_values[0]

        elif hasattr(model, 'decision_function'):
            # Isolation Forest — use TreeExplainer directly (sklearn IF is tree-based)
            explainer = shap.TreeExplainer(model)
            shap_values = explainer.shap_values(X_df)
            vals = shap_values[0] if shap_values.ndim > 1 else shap_values
        else:
            return {'available': False, 'reason': 'Model type not supported for SHAP'}

        contributions = []
        for i, name in enumerate(feature_names):
            if i < len(vals):
                contributions.append({
                    'feature': name,
                    'value': float(X[0, i]),
                    'contribution': float(vals[i])
                })
        contributions.sort(key=lambda x: abs(x['contribution']), reverse=True)
        return {
            'available': True,
            'method': 'SHAP',
            'top_contributors': contributions[:8],
            'all_contributions': contributions
        }
    except Exception as e:
        return {'available': False, 'reason': str(e)}


def get_explanation_lime(model, X_sample, feature_names=None, predict_fn=None):
    try:
        import lime
        import lime.lime_tabular
    except ImportError:
        return {'available': False, 'reason': 'LIME not installed'}

    if feature_names is None:
        feature_names = get_feature_names()

    try:
        X = np.array(X_sample, dtype=np.float64)
        if X.ndim == 1:
            X = X.reshape(1, -1)

        # Build background for LIME training data
        background = _generate_background(50)

        if predict_fn is None:
            if hasattr(model, 'predict_proba'):
                def predict_fn(x):
                    x_df = pd.DataFrame(x, columns=feature_names)
                    return model.predict_proba(x_df)[:, 1]
            elif hasattr(model, 'decision_function'):
                def predict_fn(x):
                    return -model.decision_function(x)
            else:
                return {'available': False, 'reason': 'No predict function'}

        explainer = lime.lime_tabular.LimeTabularExplainer(
            background,
            feature_names=feature_names,
            mode='regression',
            verbose=False
        )
        exp = explainer.explain_instance(
            X[0],
            predict_fn,
            num_features=min(8, len(feature_names))
        )
        contributions = []
        for feat, weight in exp.as_list():
            contributions.append({
                'feature': feat,
                'contribution': float(weight)
            })
        contributions.sort(key=lambda x: abs(x['contribution']), reverse=True)
        return {
            'available': True,
            'method': 'LIME',
            'top_contributors': contributions,
            'all_contributions': contributions
        }
    except Exception as e:
        return {'available': False, 'reason': str(e)}


def explain_anomaly(ml_ensemble, X_sample, use_shap=True, use_lime=True):
    result = {
        'shap': None,
        'lime': None,
        'summary': []
    }

    # Prefer LightGBM for explainability
    model = ml_ensemble.lgb_model if ml_ensemble.lgb_model is not None else ml_ensemble.if_model
    if model is None:
        return {'summary': ['ML models not yet trained. Run training first.']}

    X = np.array(X_sample, dtype=np.float64)
    if X.ndim == 1:
        X = X.reshape(1, -1)

    feature_names = get_feature_names()

    if use_shap:
        result['shap'] = get_explanation_shap(model, X, feature_names)

    if use_lime:
        predict_fn = None
        if ml_ensemble.lgb_model is not None:
            def predict_fn(x):
                x_df = pd.DataFrame(x, columns=feature_names)
                return ml_ensemble.lgb_model.predict_proba(x_df)[:, 1]
        elif ml_ensemble.if_model is not None:
            predict_fn = lambda x: -ml_ensemble.if_model.decision_function(x)
        result['lime'] = get_explanation_lime(model, X, feature_names, predict_fn)

    # Human-readable summary for non-technical users
    if result.get('shap', {}).get('available'):
        top = [c for c in result['shap'].get('top_contributors', []) if abs(c['contribution']) > 0.001][:5]
        for c in top:
            s = c['contribution']
            feat = c['feature']
            val = c['value']

            if feat == 'activity_type':
                act_map = {0: 'Create', 1: 'Read', 2: 'Modify', 3: 'Delete', 4: 'Transaction', 5: 'FileCopy'}
                act_name = act_map.get(int(val), 'Unknown')
                if s > 0:
                    msg = 'HIGH RISK SIGNAL — Action type is ' + act_name + '. Delete and Transaction actions are the most common in insider threat and fraud attacks.'
                else:
                    msg = 'LOW RISK SIGNAL — Action type is ' + act_name + '. This type of action is generally considered safe.'

            elif feat == 'hour_of_day':
                hour = int(val)
                ampm = 'AM' if hour < 12 else 'PM'
                hour12 = hour if hour <= 12 else hour - 12
                if s > 0:
                    if 8 <= hour <= 17:
                        msg = 'MODERATE SIGNAL — This happened at ' + str(hour12) + ':00 ' + ampm + '. Although within working hours, the overall activity pattern raised the risk score.'
                    else:
                        msg = 'HIGH RISK SIGNAL — This happened at ' + str(hour12) + ':00 ' + ampm + '. Legitimate employees rarely perform sensitive actions outside working hours (08:00 - 17:00).'
                else:
                    msg = 'SAFE SIGNAL — This happened during normal working hours (' + str(hour12) + ':00 ' + ampm + '). No time-based risk detected.'

            elif feat == 'is_work_hours':
                if s > 0:
                    msg = 'HIGH RISK SIGNAL — This action occurred outside working hours. This is a strong indicator of suspicious behavior.'
                else:
                    msg = 'SAFE SIGNAL — This action occurred within normal working hours (08:00 - 17:00).'

            elif feat == 'is_sensitive_file':
                if s > 0:
                    msg = 'HIGH RISK SIGNAL — The file involved is a sensitive type (.env, .key, .pem, .config). Accessing these files without authorization is a serious security concern.'
                else:
                    msg = 'LOW RISK SIGNAL — The file type is not classified as sensitive. This reduces the overall risk score.'

            elif feat == 'delete_count_10min':
                if s > 0:
                    msg = 'HIGH RISK SIGNAL — ' + str(int(val)) + ' files were deleted in the last 10 minutes. Mass deletion is a key indicator of ransomware or insider sabotage.'
                else:
                    msg = 'SAFE SIGNAL — Deletion rate is within normal limits.'

            elif feat == 'path_length':
                if s > 0:
                    msg = 'HIGH RISK SIGNAL — The transaction amount or file path suggests an unusually large or deep operation. Large financial transactions trigger fraud detection.'
                else:
                    msg = 'SAFE SIGNAL — Transaction amount and file path are within normal range.'

            elif feat == 'ops_ratio':
                if s > 0:
                    msg = 'HIGH RISK SIGNAL — This user is performing ' + str(round(val, 1)) + 'x more operations than their normal rate. Unusually high activity can indicate automated attacks or data exfiltration.'
                else:
                    msg = 'SAFE SIGNAL — Activity rate is within this users normal range.'

            elif feat == 'delete_ratio':
                if s > 0:
                    msg = 'HIGH RISK SIGNAL — Deletion rate is ' + str(round(val, 1)) + 'x above normal. This pattern matches ransomware or deliberate data destruction.'
                else:
                    msg = 'SAFE SIGNAL — Deletion rate is normal.'

            elif feat == 'same_file_access':
                if s > 0:
                    msg = 'HIGH RISK SIGNAL — The same file was accessed ' + str(int(val)) + ' times in a short period. Repeated access can indicate data harvesting or reconnaissance.'
                else:
                    msg = 'SAFE SIGNAL — No repeated access pattern detected.'

            elif feat == 'is_weekend':
                if s > 0:
                    msg = 'MODERATE RISK SIGNAL — This action occurred on a weekend. Most employees do not perform sensitive operations outside business days.'
                else:
                    msg = 'SAFE SIGNAL — This occurred on a regular working day.'

            else:
                if s > 0:
                    msg = 'RISK SIGNAL — ' + feat.replace('_', ' ').title() + ' contributed to raising the anomaly score (strength: ' + str(round(abs(s), 2)) + ').'
                else:
                    msg = 'SAFE SIGNAL — ' + feat.replace('_', ' ').title() + ' helped reduce the anomaly score.'

            icon = 'INCREASES RISK' if s > 0 else 'DECREASES RISK'
            result['summary'].append(icon + ' — ' + msg)

    if result.get('lime', {}).get('available'):
        lime_top = [c for c in result['lime'].get('top_contributors', []) if abs(c['contribution']) > 0.05][:2]
        for c in lime_top:
            direction = 'CONFIRMS RISK' if c['contribution'] > 0 else 'REDUCES RISK'
            feat_raw = c['feature']
            if 'sensitive' in feat_raw:
                feat_plain = 'file sensitivity check'
            elif 'activity' in feat_raw:
                feat_plain = 'action type check'
            elif 'hour' in feat_raw:
                feat_plain = 'time of day check'
            elif 'work' in feat_raw:
                feat_plain = 'working hours check'
            elif 'delete' in feat_raw:
                feat_plain = 'deletion rate check'
            elif 'path' in feat_raw:
                feat_plain = 'file path or transaction amount check'
            elif 'weekend' in feat_raw:
                feat_plain = 'day of week check'
            elif 'minute' in feat_raw:
                feat_plain = 'timing pattern check'
            else:
                feat_plain = feat_raw
            result['summary'].append(
                direction + ' — Second AI method (LIME) independently confirms: ' + feat_plain + ' (confidence: ' + str(round(abs(c['contribution']), 2)) + ')'
            )

    if not result['summary']:
        result['summary'] = ['Anomaly detected by ML ensemble. Retrain models for detailed explanation.']

    return result
