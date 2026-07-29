import json
import os
from pathlib import Path
from typing import Dict, Tuple

import pandas as pd

from ml.anomaly_detection.feature_preprocessor import FEATURE_COLUMNS


HISTORY_DIR = Path(".devsecops/anomaly_detection")
HISTORY_FILE = HISTORY_DIR / "pipeline_metrics.csv"
MODEL_DIR = HISTORY_DIR / "models"
MODEL_PATH = MODEL_DIR / "anomaly_model.pkl"
METADATA_PATH = MODEL_DIR / "anomaly_model_metadata.json"


class ML3StateError(RuntimeError):
    pass


def get_run_identifier(current_row: Dict[str, object]) -> str:
    candidate = str(current_row.get("ml3_run_id", "")).strip()
    if candidate:
        return candidate

    github_run_id = str(current_row.get("github_run_id", "")).strip() or str(
        os.environ.get("GITHUB_RUN_ID", "")
    ).strip()
    commit_sha = str(current_row.get("commit_sha", "")).strip() or str(
        os.environ.get("GITHUB_SHA", "")
    ).strip()
    timestamp_value = str(current_row.get("timestamp", "")).strip()

    if github_run_id:
        return f"gh_run:{github_run_id}"
    if commit_sha and timestamp_value:
        return f"sha:{commit_sha}:{timestamp_value}"
    if commit_sha:
        return f"sha:{commit_sha}"
    if timestamp_value:
        return f"ts:{timestamp_value}"
    return ""


def load_history() -> pd.DataFrame:
    if not HISTORY_FILE.exists():
        return pd.DataFrame()

    try:
        history_df = pd.read_csv(HISTORY_FILE)
    except Exception as exc:
        raise ML3StateError(f"Malformed ML3 history file: {exc}") from exc

    if history_df.empty:
        return history_df

    missing_columns = [column for column in FEATURE_COLUMNS if column not in history_df.columns]
    if missing_columns:
        raise ML3StateError(
            "ML3 history schema missing required columns: " + ", ".join(missing_columns)
        )

    return history_df


def save_history(history_df: pd.DataFrame) -> None:
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    history_df.to_csv(HISTORY_FILE, index=False)


def append_trusted_row_once(
    history_df: pd.DataFrame,
    current_row: Dict[str, object],
    anomaly_status: str,
    reason: str,
    failure_reason: str,
) -> Tuple[pd.DataFrame, bool]:
    row = dict(current_row)
    row["ml3_outcome"] = anomaly_status
    row["ml3_reason"] = reason
    row["ml3_failure_reason"] = failure_reason

    run_id = get_run_identifier(row)
    if run_id:
        row["ml3_run_id"] = run_id

    new_row_df = pd.DataFrame([row])

    if history_df.empty:
        return new_row_df, True

    duplicate_found = False

    if run_id and "ml3_run_id" in history_df.columns:
        duplicate_found = history_df["ml3_run_id"].astype(str).eq(run_id).any()
    elif run_id and "github_run_id" in history_df.columns:
        github_run_id = str(row.get("github_run_id", "")).strip()
        if github_run_id:
            duplicate_found = history_df["github_run_id"].astype(str).eq(github_run_id).any()

    if duplicate_found:
        return history_df.copy(), False

    updated = pd.concat([history_df, new_row_df], ignore_index=True)
    return updated, True


def has_complete_model_state() -> bool:
    return MODEL_PATH.exists() and METADATA_PATH.exists()


def has_partial_model_state() -> bool:
    return MODEL_PATH.exists() != METADATA_PATH.exists()


def load_metadata() -> Dict[str, object]:
    if not METADATA_PATH.exists():
        raise ML3StateError("ML3 metadata file is missing")

    try:
        with open(METADATA_PATH, "r", encoding="utf-8") as handle:
            metadata = json.load(handle)
    except Exception as exc:
        raise ML3StateError(f"ML3 metadata load failed: {exc}") from exc

    if not isinstance(metadata, dict):
        raise ML3StateError("ML3 metadata is not a JSON object")

    return metadata


def next_retraining_history_count(
    metadata: Dict[str, object],
    minimum_history: int,
    retraining_interval: int,
) -> int:
    configured_next = metadata.get("next_retraining_history_count")
    if configured_next is not None:
        try:
            next_count = int(configured_next)
            if next_count > 0:
                return next_count
        except Exception:
            pass

    try:
        last_trained = int(metadata.get("last_trained_history_count", minimum_history))
    except Exception:
        last_trained = minimum_history

    return last_trained + retraining_interval


def training_due(
    history_count: int,
    model_exists: bool,
    metadata: Dict[str, object],
    minimum_history: int,
    retraining_interval: int,
) -> bool:
    if history_count < minimum_history:
        return False

    if not model_exists:
        return history_count >= minimum_history

    next_threshold = next_retraining_history_count(
        metadata=metadata,
        minimum_history=minimum_history,
        retraining_interval=retraining_interval,
    )
    return history_count >= next_threshold
