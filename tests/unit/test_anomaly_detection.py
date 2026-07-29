import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

import ml.anomaly_detection.anomaly_detector as detector
import ml.anomaly_detection.ml3_orchestrator as orchestrator
import ml.anomaly_detection.ml3_state_manager as state
from ml.anomaly_detection.feature_preprocessor import FEATURE_COLUMNS
import ml.anomaly_detection.train_anomaly_model as trainer


class _NormalModel:
    def predict(self, _x):
        return np.array([1])

    def decision_function(self, _x):
        return np.array([-0.25])


def _patch_paths(tmp_path, monkeypatch):
    history_dir = tmp_path / ".devsecops/anomaly_detection"
    model_dir = history_dir / "models"
    report_dir = tmp_path / "reports/anomaly_detection"

    monkeypatch.setattr(state, "HISTORY_DIR", history_dir)
    monkeypatch.setattr(state, "HISTORY_FILE", history_dir / "pipeline_metrics.csv")
    monkeypatch.setattr(state, "MODEL_DIR", model_dir)
    monkeypatch.setattr(state, "MODEL_PATH", model_dir / "anomaly_model.pkl")
    monkeypatch.setattr(state, "METADATA_PATH", model_dir / "anomaly_model_metadata.json")

    monkeypatch.setattr(detector, "MODEL_PATH", model_dir / "anomaly_model.pkl")
    monkeypatch.setattr(detector, "METADATA_PATH", model_dir / "anomaly_model_metadata.json")

    monkeypatch.setattr(trainer, "MODEL_PATH", model_dir / "anomaly_model.pkl")
    monkeypatch.setattr(trainer, "METADATA_PATH", model_dir / "anomaly_model_metadata.json")

    monkeypatch.setattr(orchestrator, "REPORT_DIR", report_dir)
    monkeypatch.setattr(orchestrator, "CURRENT_METRICS_FILE", report_dir / "current_pipeline_metrics.csv")
    monkeypatch.setattr(orchestrator, "ANOMALY_REPORT_FILE", report_dir / "anomaly_report.csv")


def _set_event(monkeypatch, event_name, ref):
    monkeypatch.setenv("GITHUB_EVENT_NAME", event_name)
    monkeypatch.setenv("GITHUB_REF", ref)
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    monkeypatch.setenv("GITHUB_SHA", "abc123")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")


def _write_csv(path: Path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(path, index=False)


def _valid_current_row(run_id="run-1"):
    return {
        "timestamp": 1,
        "ml3_run_id": run_id,
        "github_run_id": "123",
        "commit_sha": "abc123",
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


def _write_current_metrics(path: Path, row):
    _write_csv(path, [row])


def _history_rows(n):
    rows = []
    for i in range(n):
        row = _valid_current_row(run_id=f"run-{i+1}")
        row["timestamp"] = i + 1
        row["github_run_id"] = str(1000 + i)
        row["ml3_outcome"] = "NORMAL"
        row["ml3_reason"] = "ok"
        row["ml3_failure_reason"] = ""
        rows.append(row)
    return rows


def _write_history(path: Path, n):
    _write_csv(path, _history_rows(n))


def _write_model_and_metadata(model_path: Path, metadata_path: Path, version=1, last_count=30, next_count=50):
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(_NormalModel(), model_path)
    metadata = {
        "algorithm": "IsolationForest",
        "repository": "owner/repo",
        "model_version": version,
        "training_records": last_count,
        "minimum_history": 30,
        "retraining_interval": 20,
        "last_trained_history_count": last_count,
        "next_retraining_history_count": next_count,
        "trained_at": "2026-01-01T00:00:00+00:00",
        "features": FEATURE_COLUMNS,
        "contamination": 0.1,
        "random_state": 42,
        "framework_version": "ml3-v2",
        "model_path": str(model_path),
        "training_status": "TRAINED",
    }
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")


def _read_report(tmp_path):
    return pd.read_csv(tmp_path / "reports/anomaly_detection/anomaly_report.csv").iloc[0].to_dict()


def test_bootstrap_no_history_no_model_returns_not_available(tmp_path, monkeypatch):
    _patch_paths(tmp_path, monkeypatch)
    _set_event(monkeypatch, "workflow_dispatch", "refs/heads/main")
    _write_current_metrics(orchestrator.CURRENT_METRICS_FILE, _valid_current_row())

    orchestrator.main()
    report = _read_report(tmp_path)

    assert report["anomaly_status"] == "NOT_AVAILABLE"
    assert report["reason"] == "INSUFFICIENT_HISTORY"


def test_record_30_triggers_training_but_run_status_remains_not_available(tmp_path, monkeypatch):
    _patch_paths(tmp_path, monkeypatch)
    _set_event(monkeypatch, "push", "refs/heads/main")

    _write_history(state.HISTORY_FILE, 29)
    row = _valid_current_row(run_id="run-30")
    row["github_run_id"] = "1030"
    _write_current_metrics(orchestrator.CURRENT_METRICS_FILE, row)

    orchestrator.main()

    report = _read_report(tmp_path)
    history_df = pd.read_csv(state.HISTORY_FILE)

    assert report["anomaly_status"] == "NOT_AVAILABLE"
    assert report["reason"] == "INSUFFICIENT_HISTORY"
    assert len(history_df) == 30
    assert state.MODEL_PATH.exists()
    assert state.METADATA_PATH.exists()


def test_record_31_is_scored_then_appended(tmp_path, monkeypatch):
    _patch_paths(tmp_path, monkeypatch)
    _set_event(monkeypatch, "push", "refs/heads/main")

    _write_history(state.HISTORY_FILE, 30)
    _write_model_and_metadata(state.MODEL_PATH, state.METADATA_PATH, version=1, last_count=30, next_count=50)

    row = _valid_current_row(run_id="run-31")
    row["github_run_id"] = "1031"
    _write_current_metrics(orchestrator.CURRENT_METRICS_FILE, row)

    orchestrator.main()

    report = _read_report(tmp_path)
    history_df = pd.read_csv(state.HISTORY_FILE)

    assert report["anomaly_status"] == "NORMAL"
    assert bool(report["current_run_appended"]) is True
    assert len(history_df) == 31


def test_pull_request_execution_is_read_only_for_history(tmp_path, monkeypatch):
    _patch_paths(tmp_path, monkeypatch)
    _set_event(monkeypatch, "pull_request", "refs/pull/1/merge")

    _write_history(state.HISTORY_FILE, 30)
    _write_model_and_metadata(state.MODEL_PATH, state.METADATA_PATH)
    _write_current_metrics(orchestrator.CURRENT_METRICS_FILE, _valid_current_row(run_id="pr-run"))

    orchestrator.main()
    report = _read_report(tmp_path)
    history_df = pd.read_csv(state.HISTORY_FILE)

    assert len(history_df) == 30
    assert bool(report["current_run_appended"]) is False


def test_retraining_boundary_50_scores_before_retrain(tmp_path, monkeypatch):
    _patch_paths(tmp_path, monkeypatch)
    _set_event(monkeypatch, "push", "refs/heads/main")

    _write_history(state.HISTORY_FILE, 49)
    _write_model_and_metadata(state.MODEL_PATH, state.METADATA_PATH, version=1, last_count=30, next_count=50)

    row = _valid_current_row(run_id="run-50")
    row["github_run_id"] = "1050"
    _write_current_metrics(orchestrator.CURRENT_METRICS_FILE, row)

    call_order = []
    original_eval = detector.evaluate_current_metrics
    original_train = trainer.train_and_persist

    def tracked_eval(*args, **kwargs):
        call_order.append("inference")
        return original_eval(*args, **kwargs)

    def tracked_train(*args, **kwargs):
        call_order.append(f"train:{len(kwargs['history_df'])}")
        return original_train(*args, **kwargs)

    monkeypatch.setattr(detector, "evaluate_current_metrics", tracked_eval)
    monkeypatch.setattr(trainer, "train_and_persist", tracked_train)

    orchestrator.main()

    metadata = json.loads(state.METADATA_PATH.read_text(encoding="utf-8"))
    assert call_order[0] == "inference"
    assert "train:50" in call_order
    assert metadata["next_retraining_history_count"] == 70


def test_invalid_metrics_fail_and_do_not_append(tmp_path, monkeypatch):
    _patch_paths(tmp_path, monkeypatch)
    _set_event(monkeypatch, "push", "refs/heads/main")

    row = _valid_current_row(run_id="bad-metrics")
    del row["total_alerts"]
    _write_current_metrics(orchestrator.CURRENT_METRICS_FILE, row)

    orchestrator.main()
    report = _read_report(tmp_path)

    assert report["anomaly_status"] == "FAILED"
    assert not state.HISTORY_FILE.exists()


def test_duplicate_run_id_is_not_appended_twice(tmp_path, monkeypatch):
    _patch_paths(tmp_path, monkeypatch)
    _set_event(monkeypatch, "push", "refs/heads/main")

    _write_current_metrics(orchestrator.CURRENT_METRICS_FILE, _valid_current_row(run_id="dup-run"))
    orchestrator.main()
    orchestrator.main()

    history_df = pd.read_csv(state.HISTORY_FILE)
    assert len(history_df) == 1
