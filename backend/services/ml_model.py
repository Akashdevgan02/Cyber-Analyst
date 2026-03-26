"""Isolation Forest anomaly detection on event features."""

from typing import List

import numpy as np
from sklearn.ensemble import IsolationForest

from sqlalchemy.orm import Session
from backend.db.models import Event
from backend.config import ISOLATION_FOREST_CONTAMINATION


def run_anomaly_detection(events: List[Event], db: Session) -> List[Event]:
    """Fit an Isolation Forest on the batch features and flag outliers."""
    if len(events) < 5:
        return []

    feature_matrix = []
    valid_events = []
    for e in events:
        f = e.features
        if f:
            feature_matrix.append([
                f.get("event_count_per_host", 1),
                f.get("failed_auth_ratio", 0.0),
                f.get("avg_time_delta", 0.0),
                f.get("unique_ports", 1),
            ])
            valid_events.append(e)

    if len(feature_matrix) < 5:
        return []

    X = np.array(feature_matrix)
    model = IsolationForest(
        contamination=ISOLATION_FOREST_CONTAMINATION,
        random_state=42,
        n_estimators=100,
    )
    predictions = model.fit_predict(X)

    anomalies = []
    for event, pred in zip(valid_events, predictions):
        if pred == -1:
            event.is_anomaly = True
            anomalies.append(event)

    db.commit()
    return anomalies
