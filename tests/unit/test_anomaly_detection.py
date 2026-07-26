import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

import ml.anomaly_detection.pipeline_metrics_collector as collector
import ml.anomaly_detection.anomaly_detector as detector


class _Scaler:
    def transform(self, x):
        return np.asarray(x, dtype=float)


class _ModelNormal:
    def predict(self, _x):
        return np.array([1])

    def decision_function(self, _x):
        return np.array([-0.25])


class _ModelAnomalous:
    def predict(self, _x):
        return np.array([-1])

    def decision_function(self, _x):
        return np.array([0.75])


def _write_csv(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(data).to_csv(path, index=False)


def _configure_collector_paths(tmp_path, monkeypatch):
    monkeypatch.setattr(collector, "COMMIT_RISK_REPORT", str(tmp_path / "reports/commit_risk/commit_risk_report.csv"))
    monkeypatch.setattr(collector, "COMMIT_RISK_SUMMARY_REPORT", str(tmp_path / "reports/commit_risk/commit_risk_summary.csv"))
    monkeypatch.setattr(collector, "CPPCHECK_REPORT", str(tmp_path / "reports/alert_prioritizer/cppcheck/prioritised-alerts.csv"))
    monkeypatch.setattr(collector, "CLANG_REPORT", str(tmp_path / "reports/alert_prioritizer/clang/prioritised-alerts.csv"))
    monkeypatch.setattr(collector, "HISTORY_OUTPUT_DIR", tmp_path / ".devsecops/anomaly_detection")
    monkeypatch.setattr(collector, "HISTORY_OUTPUT_FILE", tmp_path / ".devsecops/anomaly_detection/pipeline_metrics.csv")
    monkeypatch.setattr(collector, "REPORT_OUTPUT_DIR", tmp_path / "reports/anomaly_detection")
    monkeypatch.setattr(collector, "CURRENT_REPORT_OUTPUT_FILE", tmp_path / "reports/anomaly_detection/current_pipeline_metrics.csv")


def _configure_detector_paths(tmp_path, monkeypatch):
    monkeypatch.setattr(detector, "HISTORY_DIR", tmp_path / ".devsecops/anomaly_detection")
    monkeypatch.setattr(detector, "HISTORY_FILE", tmp_path / ".devsecops/anomaly_detection/pipeline_metrics.csv")
    monkeypatch.setattr(detector, "MODEL_PATH", tmp_path / ".devsecops/anomaly_detection/models/anomaly_model.pkl")
    monkeypatch.setattr(detector, "SCALER_PATH", tmp_path / ".devsecops/anomaly_detection/models/anomaly_scaler.pkl")
    monkeypatch.setattr(detector, "METADATA_PATH", tmp_path / ".devsecops/anomaly_detection/models/anomaly_model_metadata.json")
    monkeypatch.setattr(detector, "REPORT_DIR", tmp_path / "reports/anomaly_detection")
    monkeypatch.setattr(detector, "CURRENT_METRICS_FILE", tmp_path / "reports/anomaly_detection/current_pipeline_metrics.csv")
    monkeypatch.setattr(detector, "REPORT_FILE", tmp_path / "reports/anomaly_detection/anomaly_report.csv")


def _write_current_metrics(path: Path, overrides=None):
    row = {
        "timestamp": 1,
        "ml3_run_id": "run-1",
        "github_run_id": "123",
        "commit_sha": "abc",
        "total_files_scanned": 3,
        "total_alerts": 4,
        "high_alerts": 1,
        "medium_alerts": 2,
        "low_alerts": 1,
        "high_commit_risk": 0,
        "medium_commit_risk": 1,
        "low_commit_risk": 2,
        "alerts_per_file": 1.33,
        "commit_risk_status": "OK",
        "commit_summary_status": "OK",
        "cppcheck_status": "OK",
        "clang_status": "OK",
        "ml3_scoring_blocked": False,
        "ml3_scoring_block_reason": "",
    }
    if overrides:
        row.update(overrides)
    _write_csv(path, [row])


def test_pipeline_metrics_collector_outputs_expected_schema(tmp_path, monkeypatch):
    _configure_collector_paths(tmp_path, monkeypatch)
    _write_csv(Path(collector.COMMIT_RISK_REPORT), [{"risk_level": "LOW"}])
    _write_csv(Path(collector.COMMIT_RISK_SUMMARY_REPORT), [{"total_changed_files": 2}])
    _write_csv(Path(collector.CPPCHECK_REPORT), [{"priority": "LOW"}])
    _write_csv(Path(collector.CLANG_REPORT), [{"priority": "MEDIUM"}])

    collector.main()
    out = pd.read_csv(collector.CURRENT_REPORT_OUTPUT_FILE)

    required = {
        "total_files_scanned",
        "total_alerts",
        "high_alerts",
        "medium_alerts",
        "low_alerts",
        "high_commit_risk",
        "medium_commit_risk",
        "low_commit_risk",
        "alerts_per_file",
        "ml3_scoring_blocked",
    }
    assert required.issubset(set(out.columns))


def test_detector_handles_malformed_current_metrics(tmp_path, monkeypatch):
    _configure_detector_paths(tmp_path, monkeypatch)
    detector.main()

    out = pd.read_csv(detector.REPORT_FILE)
    assert out.iloc[0]["anomaly_status"] == "FAILED"
    assert "CURRENT_METRICS_FILE_MISSING" in out.iloc[0]["failure_reason"]


def test_detector_reports_not_available_when_insufficient_history_and_no_model(tmp_path, monkeypatch):
    _configure_detector_paths(tmp_path, monkeypatch)
    _write_current_metrics(detector.CURRENT_METRICS_FILE)

    monkeypatch.setenv("ML3_MIN_ROWS", "30")
    detector.main()

    out = pd.read_csv(detector.REPORT_FILE)
    assert out.iloc[0]["anomaly_status"] == "NOT_AVAILABLE"
    assert out.iloc[0]["reason"] == "INSUFFICIENT_HISTORY"


def test_detector_produces_normal_result_with_controlled_model(tmp_path, monkeypatch):
    _configure_detector_paths(tmp_path, monkeypatch)
    _write_current_metrics(detector.CURRENT_METRICS_FILE)

    detector.MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    metadata = {"feature_columns": detector.DEFAULT_FEATURE_COLUMNS, "selected_model": "IsolationForest"}
    detector.METADATA_PATH.write_text(json.dumps(metadata), encoding="utf-8")
    joblib.dump(_ModelNormal(), detector.MODEL_PATH)
    joblib.dump(_Scaler(), detector.SCALER_PATH)

    detector.main()
    out = pd.read_csv(detector.REPORT_FILE)

    assert out.iloc[0]["anomaly_status"] == "NORMAL"
    assert "Scored using trained ML3 anomaly model" in out.iloc[0]["reason"]


def test_detector_produces_anomalous_result_with_controlled_model(tmp_path, monkeypatch):
    _configure_detector_paths(tmp_path, monkeypatch)
    _write_current_metrics(detector.CURRENT_METRICS_FILE)

    detector.MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    metadata = {"feature_columns": detector.DEFAULT_FEATURE_COLUMNS, "selected_model": "IsolationForest"}
    detector.METADATA_PATH.write_text(json.dumps(metadata), encoding="utf-8")
    joblib.dump(_ModelAnomalous(), detector.MODEL_PATH)
    joblib.dump(_Scaler(), detector.SCALER_PATH)

    detector.main()
    out = pd.read_csv(detector.REPORT_FILE)

    assert out.iloc[0]["anomaly_status"] == "ANOMALOUS"


def test_detector_rejects_non_numeric_feature_input(tmp_path, monkeypatch):
    _configure_detector_paths(tmp_path, monkeypatch)
    _write_current_metrics(detector.CURRENT_METRICS_FILE, {"total_alerts": "not-a-number"})

    detector.MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    metadata = {"feature_columns": detector.DEFAULT_FEATURE_COLUMNS, "selected_model": "IsolationForest"}
    detector.METADATA_PATH.write_text(json.dumps(metadata), encoding="utf-8")
    joblib.dump(_ModelNormal(), detector.MODEL_PATH)
    joblib.dump(_Scaler(), detector.SCALER_PATH)

    detector.main()
    out = pd.read_csv(detector.REPORT_FILE)

    assert out.iloc[0]["anomaly_status"] == "FAILED"
    assert "CURRENT_METRICS_NON_NUMERIC_FEATURE" in out.iloc[0]["failure_reason"]


def test_detector_prevents_duplicate_current_run_append(tmp_path, monkeypatch):
    _configure_detector_paths(tmp_path, monkeypatch)
    _write_current_metrics(detector.CURRENT_METRICS_FILE, {"ml3_run_id": "stable-run"})

    detector.main()
    first = pd.read_csv(detector.HISTORY_FILE)
    assert len(first) == 1

    detector.main()
    second = pd.read_csv(detector.HISTORY_FILE)
    assert len(second) == 1

    report = pd.read_csv(detector.REPORT_FILE)
    assert bool(report.iloc[0]["current_run_appended"]) is False
