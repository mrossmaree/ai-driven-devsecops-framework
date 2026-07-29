import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pandas as pd

from ml.anomaly_detection import anomaly_detector
from ml.anomaly_detection import ml3_state_manager as state
from ml.anomaly_detection import train_anomaly_model
from ml.anomaly_detection.feature_preprocessor import FEATURE_COLUMNS, FeaturePreprocessingError, preprocess_features


REPORT_DIR = Path("reports/anomaly_detection")
CURRENT_METRICS_FILE = REPORT_DIR / "current_pipeline_metrics.csv"
ANOMALY_REPORT_FILE = REPORT_DIR / "anomaly_report.csv"

DEFAULT_MINIMUM_HISTORY = 30
DEFAULT_RETRAINING_INTERVAL = 20
DEFAULT_CONTAMINATION = 0.10


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _to_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def _read_int_env(name: str, default: int) -> int:
    raw = str(os.environ.get(name, str(default))).strip()
    try:
        value = int(raw)
        if value <= 0:
            raise ValueError
        return value
    except Exception:
        return default


def _read_float_env(name: str, default: float) -> float:
    raw = str(os.environ.get(name, str(default))).strip()
    try:
        value = float(raw)
        if not (0 < value < 0.5):
            raise ValueError
        return value
    except Exception:
        return default


def _load_current_metrics() -> pd.DataFrame:
    if not CURRENT_METRICS_FILE.exists():
        raise RuntimeError("CURRENT_METRICS_FILE_MISSING")

    try:
        current_df = pd.read_csv(CURRENT_METRICS_FILE)
    except Exception as exc:
        raise RuntimeError(f"CURRENT_METRICS_FILE_MALFORMED: {exc}") from exc

    if current_df.empty:
        raise RuntimeError("CURRENT_METRICS_FILE_EMPTY")

    if len(current_df) != 1:
        raise RuntimeError(f"CURRENT_METRICS_ROW_COUNT_INVALID:{len(current_df)}")

    return current_df


def _has_required_metric_statuses(current_row: Dict[str, object]) -> bool:
    required_statuses = [
        str(current_row.get("commit_risk_status", "")).upper(),
        str(current_row.get("commit_summary_status", "")).upper(),
        str(current_row.get("cppcheck_status", "")).upper(),
        str(current_row.get("clang_status", "")).upper(),
    ]
    return all(status == "OK" for status in required_statuses)


def _is_qualifying_change(current_row: Dict[str, object]) -> bool:
    if not _has_required_metric_statuses(current_row):
        return False

    try:
        feature_df = preprocess_features(pd.DataFrame([current_row]), FEATURE_COLUMNS)
    except FeaturePreprocessingError:
        return False

    total_files_scanned = float(feature_df.iloc[0]["total_files_scanned"])
    return total_files_scanned > 0


def _is_trusted_execution(current_row: Dict[str, object]) -> bool:
    event_name = str(os.environ.get("GITHUB_EVENT_NAME", "")).strip().lower()
    ref = str(os.environ.get("GITHUB_REF", "")).strip()

    if event_name != "push":
        return False

    if ref != "refs/heads/main":
        return False

    if _to_bool(current_row.get("ml3_scoring_blocked", False)):
        return False

    return _is_qualifying_change(current_row)


def _base_report(current_row: Dict[str, object], history_rows_before_append: int) -> Dict[str, object]:
    report = {
        "timestamp": _utc_now_iso(),
        "anomaly_status": "FAILED",
        "is_anomaly": "",
        "anomaly_score": "",
        "selected_model": "",
        "reason": "",
        "failure_reason": "",
        "ml3_scoring_blocked": _to_bool(current_row.get("ml3_scoring_blocked", False)),
        "ml3_scoring_block_reason": str(current_row.get("ml3_scoring_block_reason", "")),
        "history_rows_before_append": history_rows_before_append,
        "history_rows_after_append": history_rows_before_append,
        "current_run_appended": False,
        "trusted_execution": False,
        "state_persistence_required": False,
    }

    for name in [
        "commit_risk_status",
        "commit_summary_status",
        "cppcheck_status",
        "clang_status",
        "ml3_run_id",
        "github_run_id",
        "commit_sha",
    ]:
        if name in current_row:
            report[name] = current_row.get(name)

    return report


def _write_report(report: Dict[str, object]) -> None:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    pd.DataFrame([report]).to_csv(ANOMALY_REPORT_FILE, index=False)


def run_ml3_pipeline() -> Dict[str, object]:
    minimum_history = _read_int_env("ML3_MINIMUM_HISTORY", DEFAULT_MINIMUM_HISTORY)
    retraining_interval = _read_int_env("ML3_RETRAINING_INTERVAL", DEFAULT_RETRAINING_INTERVAL)
    contamination = _read_float_env("ML3_CONTAMINATION", DEFAULT_CONTAMINATION)

    repository = str(os.environ.get("GITHUB_REPOSITORY", "unknown/unknown")).strip() or "unknown/unknown"

    history_df = state.load_history()
    history_rows_before_append = int(len(history_df))

    current_df = _load_current_metrics()
    current_row = current_df.iloc[0].to_dict()
    current_row["ml3_run_id"] = state.get_run_identifier(current_row)

    report = _base_report(current_row, history_rows_before_append)
    trusted_execution = _is_trusted_execution(current_row)
    report["trusted_execution"] = trusted_execution

    if _to_bool(current_row.get("ml3_scoring_blocked", False)):
        report["anomaly_status"] = "FAILED"
        report["reason"] = "Current metrics were blocked due to upstream report errors"
        report["failure_reason"] = str(current_row.get("ml3_scoring_block_reason", "ML3_SCORING_BLOCKED"))
        _write_report(report)
        return report

    try:
        preprocess_features(current_df, FEATURE_COLUMNS)
    except FeaturePreprocessingError as exc:
        report["anomaly_status"] = "FAILED"
        report["reason"] = "Current metrics are invalid"
        report["failure_reason"] = str(exc)
        _write_report(report)
        return report

    if state.has_partial_model_state():
        report["anomaly_status"] = "FAILED"
        report["reason"] = "ML3 model state is incomplete"
        report["failure_reason"] = "PARTIAL_MODEL_STATE"
        _write_report(report)
        return report

    model_exists = state.has_complete_model_state()
    metadata = None

    if model_exists:
        try:
            model, metadata = anomaly_detector.load_model_and_metadata()
        except Exception as exc:
            report["anomaly_status"] = "FAILED"
            report["reason"] = "ML3 model or metadata could not be loaded"
            report["failure_reason"] = str(exc)
            _write_report(report)
            return report

        try:
            detection_result = anomaly_detector.evaluate_current_metrics(
                current_df=current_df,
                model=model,
                metadata=metadata,
            )
        except Exception as exc:
            report["anomaly_status"] = "FAILED"
            report["reason"] = "ML3 inference failed"
            report["failure_reason"] = str(exc)
            _write_report(report)
            return report

        report.update(detection_result)
    else:
        if history_rows_before_append >= minimum_history:
            report["anomaly_status"] = "FAILED"
            report["reason"] = "ML3 model is missing after bootstrap history threshold"
            report["failure_reason"] = "MODEL_NOT_AVAILABLE_AFTER_MINIMUM_HISTORY"
            _write_report(report)
            return report

        report["anomaly_status"] = "NOT_AVAILABLE"
        report["reason"] = "INSUFFICIENT_HISTORY"

    history_rows_after_append = history_rows_before_append

    if trusted_execution and report["anomaly_status"] != "FAILED":
        try:
            updated_history_df, appended = state.append_trusted_row_once(
                history_df=history_df,
                current_row=current_row,
                anomaly_status=str(report.get("anomaly_status", "")),
                reason=str(report.get("reason", "")),
                failure_reason=str(report.get("failure_reason", "")),
            )
            if appended:
                state.save_history(updated_history_df)
                history_df = updated_history_df
            history_rows_after_append = int(len(updated_history_df))
            report["current_run_appended"] = bool(appended)
        except Exception as exc:
            report["anomaly_status"] = "FAILED"
            report["reason"] = "ML3 state append failed"
            report["failure_reason"] = str(exc)
            report["current_run_appended"] = False
            _write_report(report)
            return report

    report["history_rows_after_append"] = history_rows_after_append

    # Train after append only when execution is trusted and history threshold is due.
    if trusted_execution and report["anomaly_status"] != "FAILED":
        is_due = state.training_due(
            history_count=history_rows_after_append,
            model_exists=model_exists,
            metadata=metadata or {},
            minimum_history=minimum_history,
            retraining_interval=retraining_interval,
        )

        if is_due:
            try:
                _, new_metadata = train_anomaly_model.train_and_persist(
                    history_df=history_df,
                    repository=repository,
                    minimum_history=minimum_history,
                    retraining_interval=retraining_interval,
                    contamination=contamination,
                    existing_metadata=metadata,
                )
                report["selected_model"] = str(new_metadata.get("algorithm", "IsolationForest"))
            except Exception as exc:
                report["anomaly_status"] = "FAILED"
                report["reason"] = "ML3 training failed"
                report["failure_reason"] = str(exc)

    report["state_persistence_required"] = bool(trusted_execution and report["anomaly_status"] != "FAILED")
    _write_report(report)
    return report


def main() -> None:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    try:
        report = run_ml3_pipeline()
    except Exception as exc:
        fallback = {
            "timestamp": _utc_now_iso(),
            "anomaly_status": "FAILED",
            "reason": "ML3 orchestration failed",
            "failure_reason": str(exc),
            "current_run_appended": False,
            "trusted_execution": False,
            "state_persistence_required": False,
        }
        _write_report(fallback)
        print(f"ML3 orchestrator failed: {exc}")
        return

    print("ML3 orchestration completed")
    print(f"Status: {report.get('anomaly_status')}")
    print(f"Trusted execution: {report.get('trusted_execution')}")
    print(f"State persistence required: {report.get('state_persistence_required')}")


if __name__ == "__main__":
    main()
