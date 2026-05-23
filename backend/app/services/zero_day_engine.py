"""Zero-Day Threat Detection Engine using Unsupervised Machine Learning.

This module implements an Isolation Forest model (Zero-Knowledge) to detect
anomalies in log events without relying on static rules or signatures.
"""

import logging
import time
from typing import Dict, List, Optional
import numpy as np
from sklearn.ensemble import IsolationForest

from app.models.alert import Alert, LogEntry

logger = logging.getLogger(__name__)

# Maintain a rolling window of recent numerical features for training/predicting
_feature_history: List[List[float]] = []
_MAX_HISTORY_SIZE = 1000

# The Unsupervised Model
# contamination=0.01 means we expect roughly 1% of traffic to be truly anomalous.
_iso_forest = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
_is_fitted = False

# Rate limiting for model retraining (e.g., retrain only every 100 new logs)
_logs_since_last_train = 0
_last_baseline_features = np.array([])
_drift_detected = False
_historical_features: List[List[float]] = []

def _extract_features(log: LogEntry) -> List[float]:
    """Convert a log entry into numerical features for the ML model."""
    try:
        t = time.gmtime(log.timestamp)
        hour = t.tm_hour
        day_of_week = t.tm_wday # 0-6 (Mon-Sun)
    except Exception:
        t = time.gmtime()
        hour = t.tm_hour
        day_of_week = t.tm_wday
        
    # Cyclical time encoding
    # 24 hours in a day
    hour_sin = np.sin(2 * np.pi * hour / 24.0)
    hour_cos = np.cos(2 * np.pi * hour / 24.0)
    
    # 7 days in a week
    day_sin = np.sin(2 * np.pi * day_of_week / 7.0)
    day_cos = np.cos(2 * np.pi * day_of_week / 7.0)
        
    # Feature 2: Length of the raw message (longer messages might be SQLi, large payloads)
    msg_length = len(log.raw_message)
    
    # Feature 3: Is it an API event? (1 or 0)
    is_api = 1.0 if "api" in log.event_type.lower() else 0.0
    
    # Feature 4: Is it an Auth event? (1 or 0)
    is_auth = 1.0 if "login" in log.event_type.lower() or "auth" in log.event_type.lower() else 0.0
    
    # Feature: Does it contain failed/error keywords? (1 or 0)
    has_error = 1.0 if "fail" in log.raw_message.lower() or "error" in log.raw_message.lower() else 0.0

    return [float(hour_sin), float(hour_cos), float(day_sin), float(day_cos), float(msg_length), is_api, is_auth, has_error]

def _compute_psi(baseline: np.ndarray, current: np.ndarray, buckets: int = 10) -> float:
    """Compute Population Stability Index for a single feature."""
    if len(baseline) == 0 or len(current) == 0:
        return 0.0
        
    # Add small noise to avoid identical percentiles
    baseline_jitter = baseline + np.random.normal(0, 1e-6, len(baseline))
    breakpoints = np.percentile(baseline_jitter, np.linspace(0, 100, buckets + 1))
    # Ensure breakpoints are strictly increasing to avoid histogram errors
    breakpoints = np.unique(breakpoints)
    if len(breakpoints) < 2:
        return 0.0
    
    # Expand the bounds slightly to catch min/max values
    breakpoints[0] -= 1e-5
    breakpoints[-1] += 1e-5

    baseline_counts, _ = np.histogram(baseline, bins=breakpoints)
    current_counts, _ = np.histogram(current, bins=breakpoints)
    
    baseline_counts = baseline_counts + 1e-6
    current_counts = current_counts + 1e-6
    
    baseline_pct = baseline_counts / baseline_counts.sum()
    current_pct = current_counts / current_counts.sum()
    
    return float(np.sum((current_pct - baseline_pct) * np.log(current_pct / baseline_pct)))

def _check_drift(recent_features: List[List[float]]) -> bool:
    """Distribution drift check using PSI (Population Stability Index)."""
    global _last_baseline_features
    if _last_baseline_features.size == 0 or len(recent_features) < 50:
        return False
        
    current_arr = np.array(recent_features[-50:])
    
    # Check PSI for each feature independently
    # If any feature's PSI > 0.2, trigger drift
    for i in range(current_arr.shape[1]):
        psi = _compute_psi(_last_baseline_features[:, i], current_arr[:, i])
        if psi > 0.2:
            logger.warning("Drift detected on feature %d (PSI: %.3f)", i, psi)
            return True
            
    return False

def analyze_for_zero_day(log: LogEntry) -> Optional[Alert]:
    """Analyze a log entry using the Isolation Forest model."""
    global _feature_history, _iso_forest, _is_fitted, _logs_since_last_train, _last_baseline_features, _drift_detected, _historical_features

    features = _extract_features(log)
    
    # Add to history
    _feature_history.append(features)
    if len(_feature_history) > _MAX_HISTORY_SIZE:
        _feature_history.pop(0)
    
    _logs_since_last_train += 1

    # Check for drift every 50 logs
    if _is_fitted and _logs_since_last_train % 50 == 0:
        if _check_drift(_feature_history):
            logger.warning("Distribution drift detected! Model may be stale. Triggering refit...")
            _drift_detected = True

    # Retrain model if we have enough baseline data and haven't trained recently, or if drift detected
    if len(_feature_history) > 50 and (not _is_fitted or _logs_since_last_train > 200 or _drift_detected):
        try:
            recent_arr = np.array(_feature_history)
            
            # Weighted refit: blend historical and recent data
            if len(_historical_features) > 100:
                hist_arr = np.array(_historical_features)
                # Sample 80% from history, 20% from recent
                hist_idx = np.random.choice(len(hist_arr), size=int(len(hist_arr) * 0.8), replace=False)
                recent_idx = np.random.choice(len(recent_arr), size=int(len(recent_arr) * 0.2), replace=True)
                refit_data = np.vstack((hist_arr[hist_idx], recent_arr[recent_idx]))
            else:
                refit_data = recent_arr
                
            _iso_forest.fit(refit_data)
            _last_baseline_features = refit_data.copy()
            
            # Move recent to historical
            _historical_features.extend(_feature_history)
            if len(_historical_features) > 5000:
                _historical_features = _historical_features[-5000:]
                
            _is_fitted = True
            _drift_detected = False
            _logs_since_last_train = 0
            logger.info("Retrained Zero-Day Isolation Forest model on %d samples (PSI drift resolved)", len(refit_data))
        except Exception as e:
            logger.warning("Failed to train Isolation Forest: %s", e)

    # If the model is not yet fitted, we can't predict
    if not _is_fitted:
        return None

    # Predict: -1 means anomaly, 1 means normal
    try:
        prediction = _iso_forest.predict([features])[0]
        # Get the anomaly score (lower is more anomalous)
        score = _iso_forest.decision_function([features])[0]
    except Exception as e:
        logger.warning("Prediction failed: %s", e)
        return None

    if prediction == -1:
        import uuid
        # Calculate a pseudo-confidence (scale standard score from [-0.5, 0] to [0.5, 1.0])
        confidence = min(1.0, max(0.5, 0.5 - score))
        
        # Downgrade confidence if model is stale
        if _drift_detected:
            confidence = confidence * 0.7
        
        return Alert(
            id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
            timestamp=log.timestamp,
            rule_id="DET-009",
            event_type="zero_day_anomaly",
            user=log.user,
            ip_address=log.ip_address,
            location=log.location,
            device=log.device,
            severity="high",
            raw_message=f"Zero-Day Anomaly Detected: Log features (time of day, length, event types) deviated significantly from historical baseline (Anomaly Score: {score:.3f}). Model Staleness Warning: {'Active' if _drift_detected else 'None'}. Original log: {log.raw_message[:100]}...",
            confidence_score=round(confidence, 2),
            status="open",
        )
        
    return None
