import json
from pathlib import Path
from typing import Dict, Tuple

import joblib
import pandas as pd

from ml.anomaly_detection.feature_preprocessor import (
    FEATURE_COLUMNS,
    FeaturePreprocessingError,
    preprocess_features,
)


MODEL_PATH = Path(".devsecops/anomaly_detection/models/anomaly_model.pkl")
METADATA_PATH = Path(".devsecops/anomaly_detection/models/anomaly_model_metadata.json")


class ML3DetectionError(RuntimeError):
    pass


def load_model_and_metadata(
    model_path: Path | None = None,
    metadata_path: Path | None = None,
) -> Tuple[object, Dict[str, object]]:
    model_path = model_path or MODEL_PATH
    metadata_path = metadata_path or METADATA_PATH

    if not model_path.exists():
        raise ML3DetectionError("ML3 model file is missing")

    if not metadata_path.exists():
        raise ML3DetectionError("ML3 metadata file is missing")

    try:
        model = joblib.load(model_path)
    except Exception as exc:
        raise ML3DetectionError(f"ML3 model load failed: {exc}") from exc

    try:
        with open(metadata_path, "r", encoding="utf-8") as handle:
            metadata = json.load(handle)
    except Exception as exc:
        raise ML3DetectionError(f"ML3 metadata load failed: {exc}") from exc

    if not isinstance(metadata, dict):
        raise ML3DetectionError("ML3 metadata is not a JSON object")

    metadata_features = metadata.get("features")
    if metadata_features != FEATURE_COLUMNS:
        raise ML3DetectionError(
            "ML3 metadata feature schema mismatch with runtime preprocessor"
        )

    return model, metadata


def evaluate_current_metrics(
    current_df: pd.DataFrame,
    model: object,
    metadata: Dict[str, object],
) -> Dict[str, object]:
    try:
        feature_df = preprocess_features(current_df, FEATURE_COLUMNS)
    except FeaturePreprocessingError as exc:
        raise ML3DetectionError(str(exc)) from exc

    try:
        prediction = int(model.predict(feature_df)[0])
    except Exception as exc:
        raise ML3DetectionError(f"ML3 inference failed: {exc}") from exc

    anomaly_score = ""
    if hasattr(model, "decision_function"):
        try:
            anomaly_score = round(float(model.decision_function(feature_df)[0]), 6)
        except Exception as exc:
            raise ML3DetectionError(f"ML3 decision score failed: {exc}") from exc

    anomaly_status = "ANOMALOUS" if prediction == -1 else "NORMAL"

    return {
        "anomaly_status": anomaly_status,
        "is_anomaly": anomaly_status == "ANOMALOUS",
        "anomaly_score": anomaly_score,
        "selected_model": str(metadata.get("algorithm", "IsolationForest")),
        "reason": "Scored using trained ML3 IsolationForest model",
        "failure_reason": "",
    }
