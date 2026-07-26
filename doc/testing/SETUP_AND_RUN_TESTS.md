# Test Setup and Run Guide

## Prerequisites

- Python 3.13
- Git installed
- Repository cloned locally
- Virtual environment recommended

## Install Test Dependencies

```bash
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements-dev.txt
```

## Run All Tests

```bash
python3 -m pytest -q
```

Expected result:

- 38 passed
- 0 failed
- 0 skipped

## Run Component Test Groups

```bash
python3 -m pytest -q tests/unit/test_commit_risk_predictor.py
python3 -m pytest -q tests/unit/test_alert_prioritizers.py
python3 -m pytest -q tests/unit/test_anomaly_detection.py
python3 -m pytest -q tests/unit/test_security_decision_engine.py
python3 -m pytest -q tests/integration/test_decision_engine_contracts.py
```

## Component Totals

- ML1: 9 tests
- ML2: 9 tests
- ML3: 7 tests
- Security Decision Engine: 10 tests
- Integration/contract: 3 tests
- Total: 38 tests

## Execution Characteristics

- Tests use `tmp_path` and controlled fixtures for deterministic local runs.
- Tests do not download datasets.
- Tests do not retrain full ML models.
- Tests avoid network access and remote workflow calls.

## Validation Layers

Use this test suite as one layer in the overall framework evidence:

1. Focused automated software tests (this guide).
2. Offline ML validation and held-out test-set evaluation (reports and model metadata).
3. End-to-end GitHub Actions framework validation on scenario repositories.
