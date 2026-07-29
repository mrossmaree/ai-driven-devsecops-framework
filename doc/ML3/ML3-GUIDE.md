# ML3 User Guide

## Purpose

ML3 performs repository-specific CI/CD pipeline anomaly detection.

There is no universal pre-trained ML3 model in this framework repository. Each consuming repository must build and maintain its own trusted historical baseline and IsolationForest model.

## Why Repository-Specific Learning

Normal CI/CD behaviour differs between repositories because file churn, alert volumes, and commit-risk patterns differ by codebase and workflow. A shared model would produce unstable and misleading anomaly decisions across repositories.

## State Branch and Stored Artifacts

Each consuming repository stores ML3 state in the dedicated branch:

`devsecops-state`

State layout:

```text
.devsecops/
└── anomaly_detection/
    ├── pipeline_metrics.csv
    └── models/
        ├── anomaly_model.pkl
        └── anomaly_model_metadata.json
```

ML3 state must not be committed to `main`.

## Trusted Execution Rules

Only trusted executions update shared ML3 history.

A trusted execution is:

- `github.event_name == push`
- `github.ref == refs/heads/main`
- qualifying C/C++ change was processed
- required pipeline metrics were collected and validated

PR, manual, and feature-branch executions are read-only with respect to shared ML3 state.

## Runtime Lifecycle

ML3 runtime order:

1. Restore existing ML3 state from `devsecops-state`.
2. Collect current pipeline metrics.
3. Validate current metrics.
4. Load existing model and metadata if available.
5. Evaluate current execution using existing model.
6. Generate ML3 report.
7. Append current metrics only when execution is trusted.
8. Train initial model or retrain when required.
9. Update metadata.
10. Persist state to `devsecops-state`.
11. Run Security Decision Engine with ML3 result.

The current execution is always evaluated before append to prevent leakage.

## Bootstrap and Retraining

Defaults:

- minimum history: 30 trusted records
- retraining interval: 20 trusted records

Bootstrap behaviour:

- Records 1-29: append trusted row, no training, `anomaly_status=NOT_AVAILABLE`, `reason=INSUFFICIENT_HISTORY`.
- Record 30: append trusted row, train initial model, still `NOT_AVAILABLE` for that run.
- Record 31: first scored run using model trained on records 1-30.

Retraining thresholds with default interval:

- 30 initial training
- 50 retraining
- 70 retraining
- 90 retraining

At retraining thresholds, inference occurs first with previous model, then append, then retrain.

## Production Algorithm

Production ML3 uses only:

- IsolationForest (`random_state=42`)

Runtime production model-selection across multiple algorithms is not used.

## No Separate Scaler Artifact

ML3 does not persist or require `anomaly_scaler.pkl`.

Training and inference both use shared preprocessing logic from:

- `ml/anomaly_detection/feature_preprocessor.py`

## Shared Feature Preprocessing

Authoritative feature order:

1. `total_files_scanned`
2. `total_alerts`
3. `high_alerts`
4. `medium_alerts`
5. `low_alerts`
6. `high_commit_risk`
7. `medium_commit_risk`
8. `low_commit_risk`
9. `alerts_per_file`

Validation rules:

- required columns must exist
- numeric conversion must succeed
- missing values are rejected
- infinite values are rejected
- negative counts are rejected for count features

Schema mismatches fail explicitly.

## Status Semantics

ML3 statuses:

- `NORMAL`: scored successfully and no anomaly.
- `ANOMALOUS`: scored successfully and anomaly detected.
- `NOT_AVAILABLE`: bootstrap phase without trained model.
- `FAILED`: operational or validation failure.

Operational failures are never treated as normal behaviour.

## Metadata

`anomaly_model_metadata.json` tracks:

- algorithm (`IsolationForest`)
- repository
- model_version
- training_records
- minimum_history
- retraining_interval
- last_trained_history_count
- next_retraining_history_count
- trained_at
- features
- contamination
- random_state
- training_status

On retraining, version and counters are updated.

## Security Decision Engine Integration

Decision engine consumes `reports/anomaly_detection/anomaly_report.csv`.

Policy intent:

- `ANOMALOUS` contributes a review escalation signal.
- `FAILED` contributes a runtime-failure review escalation signal.
- `NOT_AVAILABLE` indicates bootstrap, not an anomaly.
- `NORMAL` contributes no ML3 escalation.

## Configuration

Action inputs:

- `ml3-minimum-history` (default `30`)
- `ml3-retraining-interval` (default `20`)
- `ml3-contamination` (default `0.1`)
- `ml3-state-branch` (default `devsecops-state`)

These inputs cannot override trusted-main safety.

## Inspecting or Resetting ML3 State

Inspect state branch contents in the consuming repository:

- checkout `devsecops-state`
- inspect `.devsecops/anomaly_detection/`

Reset behaviour should be done intentionally by maintainers on the state branch, not by workflow runs on PR/manual events.

## Local Testing

Run ML3 tests:

```bash
python3 -m pytest -q tests/unit/test_anomaly_detection.py
```

Run full suite:

```bash
python3 -m pytest -q
```
