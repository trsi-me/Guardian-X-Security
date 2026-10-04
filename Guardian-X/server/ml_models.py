# -*- coding: utf-8 -*-
import os
import json
import pickle
import numpy as np
from datetime import datetime

MODELS_DIR = os.path.join(os.path.dirname(__file__), 'models')
os.makedirs(MODELS_DIR, exist_ok=True)


def _ensure_models_dir():
    os.makedirs(MODELS_DIR, exist_ok=True)


# --- Isolation Forest ---
def train_isolation_forest(X, contamination=0.1, n_estimators=100):
    from sklearn.ensemble import IsolationForest
    _ensure_models_dir()
    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X)
    path = os.path.join(MODELS_DIR, 'isolation_forest.pkl')
    with open(path, 'wb') as f:
        pickle.dump(model, f)
    return model


def load_isolation_forest():
    path = os.path.join(MODELS_DIR, 'isolation_forest.pkl')
    if not os.path.exists(path):
        return None
    with open(path, 'rb') as f:
        return pickle.load(f)


def predict_isolation_forest(model, X):
    if model is None:
        return np.zeros(len(X))
    pred = model.decision_function(X)  # lower = more anomalous
    # Normalize to 0-100 (higher = more anomalous)
    if len(pred.shape) > 1:
        pred = pred.flatten()
    return np.clip((1 - (pred - pred.min()) / (pred.max() - pred.min() + 1e-8)) * 100, 0, 100)


# --- LightGBM ---
def train_lightgbm(X, y, num_leaves=31, n_estimators=100):
    try:
        import lightgbm as lgb
    except ImportError:
        return None
    _ensure_models_dir()
    # y: 0=normal, 1=anomaly
    model = lgb.LGBMClassifier(
        num_leaves=num_leaves,
        n_estimators=n_estimators,
        random_state=42,
        verbose=-1
    )
    model.fit(X, y)
    path = os.path.join(MODELS_DIR, 'lightgbm.pkl')
    with open(path, 'wb') as f:
        pickle.dump(model, f)
    return model


def load_lightgbm():
    path = os.path.join(MODELS_DIR, 'lightgbm.pkl')
    if not os.path.exists(path):
        return None
    with open(path, 'rb') as f:
        return pickle.load(f)


def predict_lightgbm(model, X):
    if model is None:
        return np.zeros(len(X))
    try:
        import pandas as pd
        from feature_extractor import get_feature_names
        X_df = pd.DataFrame(X, columns=get_feature_names())
        proba = model.predict_proba(X_df)
    except Exception:
        proba = model.predict_proba(X)
    # proba[:, 1] = anomaly probability
    if proba.shape[1] >= 2:
        return proba[:, 1] * 100
    return np.zeros(len(X))


# --- Autoencoder (TensorFlow/Keras or sklearn MLP fallback) ---
def train_autoencoder(X, encoding_dim=8, epochs=50, batch_size=32):
    _ensure_models_dir()
    n_features = X.shape[1]
    # Try TensorFlow first (report: TensorFlow/Keras)
    try:
        import tensorflow as tf
        from tensorflow import keras
        from tensorflow.keras import layers
        encoder = keras.Sequential([
            layers.Input(shape=(n_features,)),
            layers.Dense(32, activation='relu'),
            layers.Dense(encoding_dim, activation='relu'),
        ])
        decoder = keras.Sequential([
            layers.Input(shape=(encoding_dim,)),
            layers.Dense(32, activation='relu'),
            layers.Dense(n_features, activation='linear'),
        ])
        autoencoder = keras.Sequential([encoder, decoder])
        autoencoder.compile(optimizer='adam', loss='mse')
        autoencoder.fit(X, X, epochs=epochs, batch_size=batch_size, verbose=0)
        path = os.path.join(MODELS_DIR, 'autoencoder')
        autoencoder.save(path)
        return autoencoder
    except ImportError:
        pass
    # Fallback: sklearn MLPRegressor as simple autoencoder
    from sklearn.neural_network import MLPRegressor
    model = MLPRegressor(hidden_layer_sizes=(32, encoding_dim, 32), max_iter=epochs * 10,
                         random_state=42, early_stopping=True)
    model.fit(X, X)
    path = os.path.join(MODELS_DIR, 'autoencoder_sklearn.pkl')
    with open(path, 'wb') as f:
        pickle.dump(model, f)
    return model


def load_autoencoder():
    path_tf = os.path.join(MODELS_DIR, 'autoencoder')
    path_sk = os.path.join(MODELS_DIR, 'autoencoder_sklearn.pkl')
    if os.path.exists(path_tf):
        try:
            from tensorflow import keras
            return keras.models.load_model(path_tf)
        except ImportError:
            pass
    if os.path.exists(path_sk):
        with open(path_sk, 'rb') as f:
            return pickle.load(f)
    return None


def predict_autoencoder(model, X):
    if model is None:
        return np.zeros(len(X))
    if hasattr(model, 'predict'):
        reconstructed = model.predict(X)
    else:
        reconstructed = model.predict(X, verbose=0)
    if len(reconstructed.shape) > 1 and reconstructed.shape[1] != X.shape[1]:
        reconstructed = reconstructed.reshape(X.shape)
    mse = np.mean(np.square(X - reconstructed), axis=1)
    mse_min, mse_max = mse.min(), mse.max()
    if mse_max - mse_min < 1e-8:
        return np.zeros(len(X))
    return np.clip((mse - mse_min) / (mse_max - mse_min) * 100, 0, 100)


# --- Ensemble ---
class MLEnsemble:

    def __init__(self):
        self.if_model = load_isolation_forest()
        self.lgb_model = load_lightgbm()
        self.ae_model = load_autoencoder()
        self.feature_names = None

    def is_ready(self):
        return self.if_model is not None or self.lgb_model is not None or self.ae_model is not None

    def predict(self, X):
        if not isinstance(X, np.ndarray):
            X = np.array(X, dtype=np.float64)
        if len(X.shape) == 1:
            X = X.reshape(1, -1)

        scores = []
        if self.if_model is not None:
            s = predict_isolation_forest(self.if_model, X)
            scores.append(s)
        if self.lgb_model is not None:
            s = predict_lightgbm(self.lgb_model, X)
            scores.append(s)
        if self.ae_model is not None:
            s = predict_autoencoder(self.ae_model, X)
            scores.append(s)

        if not scores:
            return 0.0, 'Normal'

        # Weighted average (equal weights)
        avg_score = np.mean(scores, axis=0)
        if np.isscalar(avg_score):
            avg_score = float(avg_score)
        else:
            avg_score = float(avg_score[0])

        if avg_score >= 70:
            risk = 'High Risk'
        elif avg_score >= 35:
            risk = 'Suspicious'
        else:
            risk = 'Normal'

        return avg_score, risk
