import pandas as pd
import pytest

import ml.decision_engine.security_decision_engine as sde


def _commit_df(levels):
    return pd.DataFrame(
        [{"risk_level": lvl, "file_path": f"src/f{i}.c", "risk_score": i + 0.1} for i, lvl in enumerate(levels)]
    )


def _alert_df(priorities, tool="cppcheck"):
    return pd.DataFrame(
        [
            {
                "priority": p,
                "tool": tool,
                "file": f"src/a{i}.c",
                "line": 10 + i,
                "alert_id": f"A{i}",
                "message": "m",
            }
            for i, p in enumerate(priorities)
        ]
    )


def _anomaly_df(status="NORMAL", reason="ok", score=-0.2):
    return pd.DataFrame([{"anomaly_status": status, "anomaly_score": score, "reason": reason}])


def test_clean_inputs_produce_pass_and_counts():
    result = sde.calculate_decision(
        _commit_df(["LOW"]),
        _alert_df(["LOW"], tool="cppcheck"),
        _alert_df(["LOW"], tool="clang"),
        _anomaly_df("NORMAL"),
    )

    assert result["decision"] == "PASS"
    assert result["commit_low_count"] == 1
    assert result["alert_low_count"] == 2


def test_ml1_high_produces_block():
    result = sde.calculate_decision(_commit_df(["HIGH"]), pd.DataFrame(), pd.DataFrame(), _anomaly_df("NORMAL"))
    assert result["decision"] == "BLOCK"
    assert result["commit_high_count"] == 1


def test_ml2_high_produces_block_and_combined_counts():
    result = sde.calculate_decision(
        pd.DataFrame(),
        _alert_df(["HIGH", "MEDIUM"], tool="cppcheck"),
        _alert_df(["HIGH"], tool="clang"),
        _anomaly_df("NORMAL"),
    )

    assert result["decision"] == "BLOCK"
    assert result["alert_high_count"] == 2
    assert result["alert_medium_count"] == 1


@pytest.mark.parametrize(
    "commit_levels,alert_levels,expected_reason_fragment",
    [
        (["REVIEW_REQUIRED"], [], "manual review"),
        ([], ["MEDIUM"], "medium severity"),
    ],
)
def test_medium_or_review_required_produce_review(commit_levels, alert_levels, expected_reason_fragment):
    result = sde.calculate_decision(
        _commit_df(commit_levels) if commit_levels else pd.DataFrame(),
        _alert_df(alert_levels) if alert_levels else pd.DataFrame(),
        pd.DataFrame(),
        _anomaly_df("NORMAL"),
    )
    assert result["decision"] == "REVIEW"
    assert expected_reason_fragment.lower() in result["reason"].lower()


def test_ml3_anomaly_produces_review():
    result = sde.calculate_decision(pd.DataFrame(), pd.DataFrame(), pd.DataFrame(), _anomaly_df("ANOMALOUS", "spike", 0.8))
    assert result["decision"] == "REVIEW"


def test_block_overrides_review():
    result = sde.calculate_decision(
        pd.DataFrame(),
        _alert_df(["HIGH"], tool="cppcheck"),
        pd.DataFrame(),
        _anomaly_df("ANOMALOUS", "spike", 0.8),
    )
    assert result["decision"] == "BLOCK"


def test_missing_or_failed_component_policy():
    missing_result = sde.calculate_decision(pd.DataFrame(), pd.DataFrame(), pd.DataFrame(), pd.DataFrame())
    failed_result = sde.calculate_decision(pd.DataFrame(), pd.DataFrame(), pd.DataFrame(), _anomaly_df("FAILED", "runtime failure", 0.0))

    assert missing_result["decision"] == "PASS"
    assert failed_result["decision"] == "REVIEW"


def test_write_decision_outputs_required_schema(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = sde.calculate_decision(
        _commit_df(["LOW"]),
        _alert_df(["LOW"], tool="cppcheck"),
        _alert_df(["LOW"], tool="clang"),
        _anomaly_df("NORMAL"),
    )
    sde.write_decision(result)

    out = tmp_path / "reports/final_decision/security_decision.csv"
    df = pd.read_csv(out)

    required_cols = {
        "decision",
        "reason",
        "commit_high_count",
        "commit_review_required_count",
        "commit_medium_count",
        "commit_low_count",
        "alert_high_count",
        "alert_medium_count",
        "alert_low_count",
        "anomaly_status",
        "anomaly_score",
        "anomaly_reason",
    }
    assert required_cols.issubset(set(df.columns))


def test_cli_exit_behavior_block_and_non_block(monkeypatch):
    monkeypatch.setattr(sde, "load_report", lambda *_a, **_k: pd.DataFrame())
    monkeypatch.setattr(
        sde,
        "calculate_decision",
        lambda *_a, **_k: {
            "decision": "BLOCK",
            "reason": "x",
            "commit_high_count": 0,
            "commit_review_required_count": 0,
            "commit_medium_count": 0,
            "commit_low_count": 0,
            "alert_high_count": 0,
            "alert_medium_count": 0,
            "alert_low_count": 0,
            "anomaly_status": "NORMAL",
            "anomaly_score": "",
            "anomaly_reason": "",
            "commit_high_issues": "",
            "commit_review_required_issues": "",
            "commit_medium_issues": "",
            "commit_low_issues": "",
            "alert_high_issues": "",
            "alert_medium_issues": "",
            "alert_low_issues": "",
        },
    )
    monkeypatch.setattr(sde, "write_decision", lambda *_a, **_k: None)

    with pytest.raises(SystemExit) as exc:
        sde.main()
    assert exc.value.code == 1

    monkeypatch.setattr(
        sde,
        "calculate_decision",
        lambda *_a, **_k: {
            "decision": "REVIEW",
            "reason": "x",
            "commit_high_count": 0,
            "commit_review_required_count": 0,
            "commit_medium_count": 0,
            "commit_low_count": 0,
            "alert_high_count": 0,
            "alert_medium_count": 0,
            "alert_low_count": 0,
            "anomaly_status": "NORMAL",
            "anomaly_score": "",
            "anomaly_reason": "",
            "commit_high_issues": "",
            "commit_review_required_issues": "",
            "commit_medium_issues": "",
            "commit_low_issues": "",
            "alert_high_issues": "",
            "alert_medium_issues": "",
            "alert_low_issues": "",
        },
    )

    sde.main()
