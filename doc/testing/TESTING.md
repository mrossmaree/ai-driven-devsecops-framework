# Automated Testing Strategy

## Purpose

The automated tests validate deterministic software behavior and report contracts across the framework runtime components. They are intentionally focused and compact for reproducibility and maintainability in an MSc research implementation.

## Test Directory Structure

```text
tests/
├── integration/
│   └── test_decision_engine_contracts.py
└── unit/
    ├── test_alert_prioritizers.py
    ├── test_anomaly_detection.py
    ├── test_commit_risk_predictor.py
    └── test_security_decision_engine.py
```

## Components and Final Test Counts

- ML1 Commit Risk Prediction: 9 tests
- ML2 Alert Prioritization (Cppcheck + Clang): 9 tests
- ML3 Pipeline Anomaly Detection: 7 tests
- Security Decision Engine: 10 tests
- Integration/contract: 3 tests
- Total: 38 tests

## Scope Covered by Automated Tests

- ML1 thresholding, confidence-gating behavior, changed-file filtering, git/error boundaries, changed-function extraction, fallback behavior, inference path through `predict_proba`, schema contract, and risk aggregation precedence.
- ML2 report parsing, missing/malformed input policies, empty/no-findings handling, priority assignment, deterministic ranking, and output schema/report writing.
- ML3 pipeline-metrics schema, missing-model/insufficient-history behavior, normal/anomalous outcomes using deterministic controlled fixtures, malformed input handling, report schema, and duplicate history append prevention.
- Decision Engine PASS/REVIEW/BLOCK semantics, precedence, missing/failed component policy, combined counts, final decision schema, and CLI exit behavior.
- Lightweight integration/contract checks proving ML1/ML2/ML3 report schemas are accepted by the Decision Engine and produce representative PASS/REVIEW/BLOCK outcomes.

## What Is Intentionally Not Unit Tested

- Full model retraining pipelines.
- Dataset download/preprocessing workflows.
- Statistical model-quality claims via pytest (precision/recall/F1 are evaluated offline).
- Network-dependent or remote GitHub Actions execution.
- Exhaustive coverage of every console message string.

## Test Design Notes

- Tests use `tmp_path` for isolated file/report writes.
- External boundaries are controlled with monkeypatch/mocks where needed (for example Git command boundaries and model loading paths).
- Test execution does not retrain full models or download datasets.

## Relation to Dissertation Evidence

Automated tests verify deterministic software contracts. Dissertation model-quality evidence is provided separately by offline validation and held-out test artifacts under `reports/` and `models/`.

## Expected Result

For the current repository state:

- 38 passed
- 0 failed
- 0 skipped
