import pandas as pd
import pytest

import ml.decision_engine.security_decision_engine as sde


def _write_contract_reports(root, commit_levels, cpp_levels, clang_levels, anomaly_status):
    commit_rows = [{"risk_level": lvl, "file_path": f"src/c{i}.c", "risk_score": 0.5} for i, lvl in enumerate(commit_levels)]
    cpp_rows = [
        {"priority": lvl, "tool": "cppcheck", "file": f"src/p{i}.c", "line": 10 + i, "alert_id": f"P{i}", "message": "m"}
        for i, lvl in enumerate(cpp_levels)
    ]
    clang_rows = [
        {"priority": lvl, "tool": "clang", "file": f"src/l{i}.c", "line": 20 + i, "alert_id": f"L{i}", "message": "m"}
        for i, lvl in enumerate(clang_levels)
    ]
    anomaly_rows = [{"anomaly_status": anomaly_status, "anomaly_score": 0.1, "reason": "contract"}]

    (root / "reports/commit_risk").mkdir(parents=True, exist_ok=True)
    (root / "reports/alert_prioritizer/cppcheck").mkdir(parents=True, exist_ok=True)
    (root / "reports/alert_prioritizer/clang").mkdir(parents=True, exist_ok=True)
    (root / "reports/anomaly_detection").mkdir(parents=True, exist_ok=True)

    pd.DataFrame(commit_rows).to_csv(root / "reports/commit_risk/commit_risk_report.csv", index=False)
    pd.DataFrame(cpp_rows).to_csv(root / "reports/alert_prioritizer/cppcheck/prioritised-alerts.csv", index=False)
    pd.DataFrame(clang_rows).to_csv(root / "reports/alert_prioritizer/clang/prioritised-alerts.csv", index=False)
    pd.DataFrame(anomaly_rows).to_csv(root / "reports/anomaly_detection/anomaly_report.csv", index=False)


def _configure_paths(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sde, "COMMIT_RISK_REPORT", str(tmp_path / "reports/commit_risk/commit_risk_report.csv"))
    monkeypatch.setattr(sde, "CPPCHECK_REPORT", str(tmp_path / "reports/alert_prioritizer/cppcheck/prioritised-alerts.csv"))
    monkeypatch.setattr(sde, "CLANG_REPORT", str(tmp_path / "reports/alert_prioritizer/clang/prioritised-alerts.csv"))
    monkeypatch.setattr(sde, "ANOMALY_REPORT", str(tmp_path / "reports/anomaly_detection/anomaly_report.csv"))
    monkeypatch.setattr(sde, "OUTPUT_FILE", "reports/final_decision/security_decision.csv")


def test_contract_reports_produce_pass(tmp_path, monkeypatch):
    _configure_paths(tmp_path, monkeypatch)
    _write_contract_reports(tmp_path, ["LOW"], ["LOW"], ["LOW"], "NORMAL")

    sde.main()
    out = pd.read_csv(tmp_path / "reports/final_decision/security_decision.csv")
    assert out.iloc[0]["decision"] == "PASS"


def test_contract_reports_produce_review(tmp_path, monkeypatch):
    _configure_paths(tmp_path, monkeypatch)
    _write_contract_reports(tmp_path, ["LOW"], ["LOW"], ["LOW"], "ANOMALOUS")

    sde.main()
    out = pd.read_csv(tmp_path / "reports/final_decision/security_decision.csv")
    assert out.iloc[0]["decision"] == "REVIEW"


def test_contract_reports_produce_block(tmp_path, monkeypatch):
    _configure_paths(tmp_path, monkeypatch)
    _write_contract_reports(tmp_path, ["HIGH"], ["LOW"], ["LOW"], "NORMAL")

    with pytest.raises(SystemExit) as exc:
        sde.main()
    assert exc.value.code == 1

    out = pd.read_csv(tmp_path / "reports/final_decision/security_decision.csv")
    assert out.iloc[0]["decision"] == "BLOCK"
