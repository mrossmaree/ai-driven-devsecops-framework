import numpy as np
import pandas as pd
import pytest

import ml.commit_risk.commit_risk_predictor as crp


class _PredictProbaModel:
    def __init__(self, probs):
        self._probs = np.array(probs)

    def predict_proba(self, _features):
        return self._probs


def test_risk_level_threshold_boundaries():
    score_low, level_low = crp.get_risk_level(0.3999, medium_threshold=40, high_threshold=70)
    score_medium, level_medium = crp.get_risk_level(0.40, medium_threshold=40, high_threshold=70)
    score_high, level_high = crp.get_risk_level(0.70, medium_threshold=40, high_threshold=70)

    assert (score_low, level_low) == (39.99, "LOW")
    assert (score_medium, level_medium) == (40.0, "MEDIUM")
    assert (score_high, level_high) == (70.0, "HIGH")


def test_review_required_for_low_confidence_non_high():
    confidence = crp.calculate_confidence(0.51)

    assert crp.apply_review_required("LOW", confidence, 0.2) == "REVIEW_REQUIRED"
    assert crp.apply_review_required("MEDIUM", confidence, 0.2) == "REVIEW_REQUIRED"
    assert crp.apply_review_required("HIGH", confidence, 0.2) == "HIGH"


def test_invalid_repository_or_git_failure_raises(monkeypatch):
    monkeypatch.setattr(crp, "run_git_command", lambda *a, **k: "false")
    with pytest.raises(RuntimeError, match="not inside a Git working tree"):
        crp.ensure_git_working_tree()

    def _raise(*_a, **_k):
        raise crp.GitCommandError("boom")

    monkeypatch.setattr(crp, "run_git_command", _raise)
    with pytest.raises(crp.GitCommandError):
        crp.ensure_git_working_tree()


def test_changed_cpp_file_filtering(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "src").mkdir()
    (tmp_path / "docs").mkdir()
    (tmp_path / "src" / "main.c").write_text("int main(){return 0;}\n", encoding="utf-8")
    (tmp_path / "src" / "lib.hpp").write_text("#pragma once\n", encoding="utf-8")
    (tmp_path / "docs" / "readme.md").write_text("x\n", encoding="utf-8")

    monkeypatch.setattr(
        crp,
        "run_git_command",
        lambda *a, **k: "src/main.c\nsrc/lib.hpp\ndocs/readme.md\n",
    )

    changed = crp.get_changed_cpp_files("HEAD~1...HEAD", "src")
    assert changed == ["src/lib.hpp", "src/main.c"]


def test_extract_changed_functions_represents_detected_function(tmp_path):
    code = """
int untouched() { return 0; }

int target() {
    return 42;
}
""".strip()
    f = tmp_path / "sample.c"
    f.write_text(code + "\n", encoding="utf-8")

    rows = crp.extract_changed_functions(tmp_path, "sample.c", {4})
    assert len(rows) == 1
    assert rows[0]["function_name"] == "target"
    assert rows[0]["fallback_used"] is False


def test_extract_changed_functions_fallback_when_no_function(tmp_path):
    f = tmp_path / "globals.c"
    f.write_text("int global_value = 7;\n", encoding="utf-8")

    rows = crp.extract_changed_functions(tmp_path, "globals.c", {1})
    assert len(rows) == 1
    assert rows[0]["function_name"] == "__FILE_FALLBACK__"
    assert rows[0]["fallback_used"] is True


def test_supported_logistic_style_inference_uses_predict_proba():
    model = _PredictProbaModel([[0.1, 0.9], [0.7, 0.3]])
    scores = crp.model_positive_scores(model, features=np.array([[1], [2]]))
    assert np.allclose(scores, np.array([0.9, 0.3]))


def test_report_schema_contract_and_aggregation_precedence():
    df = crp.empty_report_df()

    expected_columns = {
        "commit_sha",
        "branch",
        "event_type",
        "author",
        "base_ref",
        "head_ref",
        "file_path",
        "function_name",
        "start_line",
        "end_line",
        "risk_score",
        "risk_level",
        "confidence",
        "review_confidence_threshold",
        "top_risky_terms",
        "risk_reason",
        "vectorization_time_ms",
        "model_inference_time_ms",
        "total_prediction_runtime_ms",
    }

    assert expected_columns.issubset(set(df.columns))
    assert crp.aggregate_commit_risk(["LOW", "MEDIUM", "REVIEW_REQUIRED"]) == "REVIEW_REQUIRED"
    assert crp.aggregate_commit_risk(["LOW", "REVIEW_REQUIRED", "HIGH"]) == "HIGH"


def test_get_changed_lines_by_file_parses_diff_hunks(monkeypatch):
    def _mock_git(args, context=""):
        if args[:2] == ["diff", "-U0"]:
            return "@@ -10,2 +20,3 @@"
        raise AssertionError(f"unexpected git call: {args} | {context}")

    monkeypatch.setattr(crp, "run_git_command", _mock_git)
    changed = crp.get_changed_lines_by_file("HEAD~1...HEAD", ["src/main.c"])
    assert changed["src/main.c"] == {20, 21, 22}
