from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Tuple

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

from ml.anomaly_detection.feature_preprocessor import (
    FEATURE_COLUMNS,
    FeaturePreprocessingError,
    preprocess_features,
)


MODEL_PATH = Path(".devsecops/anomaly_detection/models/anomaly_model.pkl")
METADATA_PATH = Path(".devsecops/anomaly_detection/models/anomaly_model_metadata.json")


class ML3TrainingError(RuntimeError):
    pass


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def train_isolation_forest(
    history_df: pd.DataFrame,
    contamination: float,
    random_state: int = 42,
) -> IsolationForest:
    try:
        feature_df = preprocess_features(history_df, FEATURE_COLUMNS)
    except FeaturePreprocessingError as exc:
        raise ML3TrainingError(str(exc)) from exc

    if feature_df.empty:
        raise ML3TrainingError("No valid ML3 feature rows available for training")

    try:
        model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=random_state,
        )
        model.fit(feature_df)
    except Exception as exc:
        raise ML3TrainingError(f"ML3 IsolationForest training failed: {exc}") from exc

    return model


def build_metadata(
    repository: str,
    training_records: int,
    minimum_history: int,
    retraining_interval: int,
    contamination: float,
    existing_metadata: Dict[str, object] | None,
) -> Dict[str, object]:
    existing_metadata = existing_metadata or {}

    try:
        current_version = int(existing_metadata.get("model_version", 0))
    except Exception:
        current_version = 0

    model_version = current_version + 1
    next_retraining = training_records + retraining_interval

    return {
        "algorithm": "IsolationForest",
        "repository": repository,
        "model_version": model_version,
        "training_records": int(training_records),
        "minimum_history": int(minimum_history),
        "retraining_interval": int(retraining_interval),
        "last_trained_history_count": int(training_records),
        "next_retraining_history_count": int(next_retraining),
        "trained_at": _utc_now_iso(),
        "features": FEATURE_COLUMNS,
        "contamination": float(contamination),
        "random_state": 42,
        "framework_version": str(existing_metadata.get("framework_version", "frozen-ml3-v2")),
        "model_path": str(MODEL_PATH),
        "training_status": "TRAINED",
    }


def save_model_and_metadata(
    model: IsolationForest,
    metadata: Dict[str, object],
    model_path: Path | None = None,
    metadata_path: Path | None = None,
) -> None:
    model_path = model_path or MODEL_PATH
    metadata_path = metadata_path or METADATA_PATH
    model_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        joblib.dump(model, model_path)
    except Exception as exc:
        raise ML3TrainingError(f"Failed to save ML3 model: {exc}") from exc

    try:
        import json

        with open(metadata_path, "w", encoding="utf-8") as handle:
            json.dump(metadata, handle, indent=2)
    except Exception as exc:
        raise ML3TrainingError(f"Failed to save ML3 metadata: {exc}") from exc


def train_and_persist(
    history_df: pd.DataFrame,
    repository: str,
    minimum_history: int,
    retraining_interval: int,
    contamination: float,
    existing_metadata: Dict[str, object] | None,
) -> Tuple[IsolationForest, Dict[str, object]]:
    if len(history_df) < minimum_history:
        raise ML3TrainingError(
            f"Insufficient history for training: {len(history_df)} < {minimum_history}"
        )

    model = train_isolation_forest(
        history_df=history_df,
        contamination=contamination,
        random_state=42,
    )

    metadata = build_metadata(
        repository=repository,
        training_records=len(history_df),
        minimum_history=minimum_history,
        retraining_interval=retraining_interval,
        contamination=contamination,
        existing_metadata=existing_metadata,
    )

    save_model_and_metadata(model=model, metadata=metadata)
    return model, metadata


def main() -> None:
    history_file = Path(".devsecops/anomaly_detection/pipeline_metrics.csv")
    if not history_file.exists():
        raise SystemExit("ML3 history file not found")

    history_df = pd.read_csv(history_file)
    minimum_history = 30
    retraining_interval = 20
    contamination = 0.1

    if len(history_df) < minimum_history:
        raise SystemExit(
            f"Insufficient history for training: {len(history_df)} < {minimum_history}"
        )

    _, metadata = train_and_persist(
        history_df=history_df,
        repository=str(Path.cwd()),
        minimum_history=minimum_history,
        retraining_interval=retraining_interval,
        contamination=contamination,
        existing_metadata=None,
    )
    print(f"ML3 model trained. Version: {metadata['model_version']}")


if __name__ == "__main__":
    # Training is orchestrated by ml3_orchestrator.py in production.
    main()
