import pandas as pd
import pytest

import ml.alert_prioritizer.cppcheck.cppcheck_prioritizer as cpp
import ml.alert_prioritizer.clang.clang_prioritizer as clang


class _LabelModel:
    def __init__(self, labels):
        self.labels = labels

    def predict(self, _df):
        return self.labels


class _CompatModel:
    def __init__(self, label=2):
        self._label = label
        self.named_steps = {"preprocessor": _DummyPreprocessor()}

    def predict(self, _df):
        return [self._label]


class _DummyPreprocessor:
    transformers = [
        ("passthrough", None, clang.REQUIRED_FEATURE_COLUMNS),
    ]


def test_cppcheck_parses_valid_report(tmp_path, monkeypatch):
    xml = """<?xml version='1.0'?>
<results>
  <errors>
    <error id='nullPointer' severity='error' msg='possible null pointer' cwe='476'>
      <location file='src/main.c' line='11'/>
    </error>
  </errors>
</results>
"""
    report = tmp_path / "cppcheck.xml"
    report.write_text(xml, encoding="utf-8")
    monkeypatch.setattr(cpp, "CPPCHECK_REPORT", str(report))

    alerts = cpp.parse_cppcheck_report()
    assert len(alerts) == 1
    assert alerts[0]["alert_id"] == "nullPointer"


def test_cppcheck_empty_findings_writes_header_only(tmp_path, monkeypatch):
    out = tmp_path / "prioritised-alerts.csv"
    monkeypatch.setattr(cpp, "OUTPUT_FILE", str(out))

    cpp.write_prioritised_alerts(pd.DataFrame())
    df = pd.read_csv(out)
    assert list(df.columns) == ["priority", "tool", "file", "line", "alert_id", "cwe", "severity", "message"]
    assert df.empty


def test_cppcheck_missing_or_malformed_input_raises(tmp_path, monkeypatch):
    missing_report = tmp_path / "missing.xml"
    monkeypatch.setattr(cpp, "CPPCHECK_REPORT", str(missing_report))
    with pytest.raises(cpp.PrioritizerRuntimeError, match="missing"):
        cpp.parse_cppcheck_tree()

    bad = tmp_path / "bad.xml"
    bad.write_text("<results><errors><error></results>", encoding="utf-8")
    monkeypatch.setattr(cpp, "CPPCHECK_REPORT", str(bad))
    with pytest.raises(cpp.PrioritizerRuntimeError, match="malformed"):
        cpp.parse_cppcheck_tree()


def test_cppcheck_priority_assignment_and_ranking(tmp_path, monkeypatch):
    df = pd.DataFrame(
        [
            {"tool": "cppcheck", "file": "a.c", "line": 1, "alert_id": "A", "cwe": "", "severity": "warning", "message": "m"},
            {"tool": "cppcheck", "file": "b.c", "line": 2, "alert_id": "B", "cwe": "", "severity": "error", "message": "n"},
        ]
    )
    features = cpp.prepare_features(df.to_dict("records"))
    scored = cpp.predict_priorities(features, _LabelModel([0, 2]))

    out = tmp_path / "prioritised-alerts.csv"
    monkeypatch.setattr(cpp, "OUTPUT_FILE", str(out))
    cpp.write_prioritised_alerts(scored)

    written = pd.read_csv(out)
    assert list(written["priority"]) == ["HIGH", "LOW"]


def test_clang_parses_valid_html_report(tmp_path, monkeypatch):
    report_dir = tmp_path / "clang-report"
    report_dir.mkdir()
    html = """
<!-- BUGDESC Null pointer dereference -->
<!-- BUGFILE src/lib.c -->
<!-- BUGLINE 42 -->
"""
    (report_dir / "report-1.html").write_text(html, encoding="utf-8")

    monkeypatch.setattr(clang, "CLANG_REPORT_DIR", str(report_dir))
    monkeypatch.setattr(clang, "SCAN_STATUS_FILE", str(report_dir / "scan-status.txt"))

    df, status = clang.parse_clang_reports(_CompatModel(label=2))
    assert status == ""
    assert len(df) == 1
    assert df.iloc[0]["priority"] == "HIGH"


def test_clang_no_findings_policy_returns_empty_with_no_source_status(tmp_path, monkeypatch):
    report_dir = tmp_path / "clang-report"
    report_dir.mkdir()
    (report_dir / "scan-status.txt").write_text("SCAN_COMPLETED_NO_SOURCE", encoding="utf-8")

    monkeypatch.setattr(clang, "CLANG_REPORT_DIR", str(report_dir))
    monkeypatch.setattr(clang, "SCAN_STATUS_FILE", str(report_dir / "scan-status.txt"))

    df, status = clang.parse_clang_reports(_CompatModel(label=1))
    assert df.empty
    assert status == "SCAN_COMPLETED_NO_SOURCE"


def test_clang_missing_input_raises(tmp_path, monkeypatch):
    missing_dir = tmp_path / "missing-clang-dir"
    monkeypatch.setattr(clang, "CLANG_REPORT_DIR", str(missing_dir))
    monkeypatch.setattr(clang, "SCAN_STATUS_FILE", str(missing_dir / "scan-status.txt"))

    with pytest.raises(FileNotFoundError):
        clang.parse_clang_reports(_CompatModel())


def test_clang_report_write_schema_and_ranking(tmp_path, monkeypatch):
    out = tmp_path / "clang-prioritised-alerts.csv"
    monkeypatch.setattr(clang, "OUTPUT_FILE", str(out))

    df = pd.DataFrame(
        [
            {"priority": "LOW", "tool": "clang", "file": "x.c", "line": 3, "alert_id": "clang-static-analyzer", "cwe": "", "severity": "warning", "message": "m"},
            {"priority": "HIGH", "tool": "clang", "file": "y.c", "line": 8, "alert_id": "clang-static-analyzer", "cwe": "", "severity": "warning", "message": "n"},
        ]
    )
    clang.write_prioritised_alerts(df)

    written = pd.read_csv(out)
    assert list(written.columns) == ["priority", "tool", "file", "line", "alert_id", "cwe", "severity", "message"]
    assert list(written["priority"]) == ["HIGH", "LOW"]


def test_clang_model_feature_compatibility_check_passes():
    clang.validate_model_feature_compatibility(_CompatModel())
