# GitHub Integration Overview

The framework is a reusable composite action that runs ML1, ML2, ML3, and the Security Decision Engine in the consuming repository workflow.

## Trigger Ownership

- [composite action](../../action.yml): runtime logic.
- [workflow template](template/run-ai-devsecops-security-scan.yml): trigger events, permissions, checkout, concurrency.

## Default Integration Model

The consuming workflow should include:

- pull-request scans to `main` with C/C++ path filters
- direct push scans to `main` with C/C++ path filters
- optional manual dispatch

## ML3 State Branch Architecture

ML3 does not use a shared pre-trained model.

Each consuming repository maintains repository-specific state on:

- `devsecops-state`

State files:

- `.devsecops/anomaly_detection/pipeline_metrics.csv`
- `.devsecops/anomaly_detection/models/anomaly_model.pkl`
- `.devsecops/anomaly_detection/models/anomaly_model_metadata.json`

## Trusted Update Safety

State updates require trusted execution context:

- push event
- `refs/heads/main`
- qualifying C/C++ change
- valid current metrics

PR/manual/feature-branch runs do not modify shared ML3 state.

## Required Workflow Settings

```yaml
permissions:
  contents: write

concurrency:
  group: ml3-state-${{ github.repository }}
  cancel-in-progress: false
```

```yaml
- uses: actions/checkout@v4
  with:
    ref: ${{ github.head_ref || github.ref_name }}
    fetch-depth: 0
```

## Execution Order

1. Restore ML3 state from `devsecops-state`.
2. Collect current metrics.
3. Infer using existing model when available.
4. Append trusted row.
5. Train/retrain when threshold is due.
6. Persist state to `devsecops-state`.
7. Run Security Decision Engine.

Inference always occurs before append and before training/retraining.
