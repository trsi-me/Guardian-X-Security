#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Usage: python train_models.py | python train_models.py --db | python train_models.py --dataset unsw
import sys
import os

# Ensure server dir is in path
sys.path.insert(0, os.path.dirname(__file__))

import db
from training import (
    train_from_synthetic,
    train_from_db,
    train_from_guardian_synthetic,
    load_unsw_nb15_if_available,
    load_cicids2017_if_available
)
from ml_models import train_isolation_forest, train_lightgbm, train_autoencoder
import numpy as np


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--db', action='store_true', help='Train from database')
    parser.add_argument(
        '--dataset',
        choices=['unsw', 'cicids', 'guardian'],
        help='unsw|cicids benchmark or guardian (banking + employee synthetic)',
    )
    parser.add_argument('--synthetic', action='store_true', help='Train from synthetic only (default)')
    args = parser.parse_args()

    db.init_db()

    if args.dataset == 'unsw':
        print('Loading UNSW-NB15 from HuggingFace (Mouwiya/UNSW-NB15)...')
        X, y = load_unsw_nb15_if_available()
        if X is None:
            print('UNSW-NB15 not found. Install: pip install datasets')
            return 1
        print(f'Loaded UNSW-NB15: {len(X)} samples, {int(y.sum())} anomalies')
        train_isolation_forest(X, contamination=0.15)
        train_lightgbm(X, y)
        train_autoencoder(X, encoding_dim=8, epochs=30, batch_size=32)
        print('Training complete (UNSW-NB15).')

    elif args.dataset == 'cicids':
        X, y = load_cicids2017_if_available()
        if X is None:
            print('CICIDS-2017 not found. Place CSV in datasets/CICIDS-2017/')
            print('See DATASETS.md for download links.')
            return 1
        print(f'Loaded CICIDS-2017: {len(X)} samples, {int(y.sum())} anomalies')
        train_isolation_forest(X, contamination=0.15)
        train_lightgbm(X, y)
        train_autoencoder(X, encoding_dim=8, epochs=30, batch_size=32)
        print('Training complete (CICIDS-2017).')

    elif args.dataset == 'guardian':
        result = train_from_guardian_synthetic(export_csv=True)
        print(f'Training complete (Guardian synthetic): {result}')

    elif args.db:
        result = train_from_db(db.get_file_events, db.get_behavior_profile)
        print(f'Trained from DB: {result}')

    else:
        result = train_from_synthetic()
        print(f'Trained from synthetic: {result}')

    print('Models saved to server/models/')
    return 0


if __name__ == '__main__':
    sys.exit(main())
