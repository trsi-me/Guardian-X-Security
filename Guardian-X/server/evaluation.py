# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import sys
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

try:
    import psutil
except ImportError:
    psutil = None


def _ensure_path():
    d = os.path.dirname(os.path.abspath(__file__))
    if d not in sys.path:
        sys.path.insert(0, d)


def _pred_is_anomaly(risk_level: str) -> int:
    return 1 if risk_level in ("Suspicious", "High Risk") else 0


def run_evaluation(
    train_first: bool = True,
    n_banking: int = 450,
    n_employee: int = 650,
    export_csv: bool = True,
    max_events: Optional[int] = None,
) -> Dict[str, Any]:
    _ensure_path()
    import ai_model
    from synthetic_dataset import build_guardian_events_from_synthetic, attach_event_history
    from training import train_from_guardian_synthetic

    proc = psutil.Process(os.getpid()) if psutil else None
    if proc:
        proc.cpu_percent(interval=0.05)

    if train_first:
        train_from_guardian_synthetic(
            n_banking=max(300, n_banking),
            n_employee=max(400, n_employee),
            export_csv=export_csv,
        )

    ai_model._ensemble = None

    events, profile = build_guardian_events_from_synthetic(n_banking, n_employee)
    attach_event_history(events)
    if max_events is not None:
        events = events[: max_events]

    from ai_model import analyze_event

    y_true: List[int] = []
    y_pred: List[int] = []
    cpu_samples: List[float] = []
    ram_mb_samples: List[float] = []

    fraud_mask_true: List[int] = []
    fraud_mask_pred: List[int] = []
    copy_mask_true: List[int] = []
    copy_mask_pred: List[int] = []

    for i, e in enumerate(events):
        hist = e.get("event_history", [])
        risk, reason, score = analyze_event(
            e["user_id"],
            e["activity_type"],
            e["file_path"],
            e["timestamp"],
            hist,
            profile,
        )
        gt = int(e.get("ground_truth_anomaly", 0))
        pr = _pred_is_anomaly(risk)
        y_true.append(gt)
        y_pred.append(pr)

        if e.get("activity_type") == "Transaction":
            fraud_mask_true.append(gt)
            fraud_mask_pred.append(pr)
        if e.get("activity_type") == "FileCopy":
            copy_mask_true.append(gt)
            copy_mask_pred.append(pr)

        if proc and i % 40 == 0:
            cpu_samples.append(proc.cpu_percent(interval=0.02))
            ram_mb_samples.append(proc.memory_info().rss / (1024 * 1024))

    yt = np.array(y_true, dtype=np.int32)
    yp = np.array(y_pred, dtype=np.int32)
    accuracy = float((yt == yp).mean()) if len(yt) else 0.0

    tp = int(np.sum((yt == 1) & (yp == 1)))
    fp = int(np.sum((yt == 0) & (yp == 1)))
    fn = int(np.sum((yt == 1) & (yp == 0)))
    tn = int(np.sum((yt == 0) & (yp == 0)))
    precision = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1 = (
        float(2 * precision * recall / (precision + recall))
        if (precision + recall) > 0
        else 0.0
    )

    def _acc(a, b):
        if not a:
            return None
        aa = np.array(a, dtype=np.int32)
        bb = np.array(b, dtype=np.int32)
        return float((aa == bb).mean())

    out: Dict[str, Any] = {
        "samples_evaluated": len(events),
        "accuracy": accuracy,
        "precision_anomaly": precision,
        "recall_anomaly": recall,
        "f1_anomaly": f1,
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "scenario_accuracy": {
            "fraud_transactions": _acc(fraud_mask_true, fraud_mask_pred),
            "unauthorized_file_copy": _acc(copy_mask_true, copy_mask_pred),
        },
        "resource_usage": {
            "cpu_percent_mean": float(np.mean(cpu_samples)) if cpu_samples else None,
            "cpu_percent_max": float(np.max(cpu_samples)) if cpu_samples else None,
            "ram_rss_mb_peak": float(np.max(ram_mb_samples)) if ram_mb_samples else None,
            "ram_rss_mb_mean": float(np.mean(ram_mb_samples)) if ram_mb_samples else None,
            "psutil_available": psutil is not None,
        },
    }
    return out


def main():
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Guardian-X evaluation on synthetic banking + employee data")
    parser.add_argument("--no-train", action="store_true", help="Skip training; use existing models")
    parser.add_argument("--banking", type=int, default=450)
    parser.add_argument("--employee", type=int, default=650)
    parser.add_argument("--max-events", type=int, default=None)
    parser.add_argument("--no-export-csv", action="store_true")
    args = parser.parse_args()

    r = run_evaluation(
        train_first=not args.no_train,
        n_banking=args.banking,
        n_employee=args.employee,
        export_csv=not args.no_export_csv,
        max_events=args.max_events,
    )
    print(json.dumps(r, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
