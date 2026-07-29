# GitHub Integration Overview

The AI-Driven DevSecOps Framework is distributed as a reusable composite GitHub Action. A consuming repository invokes the action from its own workflow to run ML1, ML2, ML3, and the Security Decision Engine.

## Trigger Ownership

The framework and consuming repository have separate responsibilities:

- [`action.yml`](../../action.yml) contains the framework runtime logic.
- [`run-ai-devsecops-security-scan.yml`](template/run-ai-devsecops-security-scan.yml) defines the consuming workflow triggers, permissions, checkout configuration, and concurrency settings.

## Default Integration Model

The consuming workflow should include:

- pull-request scans for C/C++ changes
- push scans to `main` for C/C++ changes
- optional manual execution with `workflow_dispatch`

Pull requests are used for preventive security checks before merge. Pushes to `main` provide trusted pipeline executions that may contribute to the ML3 historical baseline.

## ML3 State Architecture

ML3 uses repository-specific pipeline history rather than a shared pre-trained model.

Each consuming repository stores its ML3 state in:

```text
devsecops-state
```

The expected state structure is:

```text
.devsecops/
└── anomaly_detection/
    ├── pipeline_metrics.csv
    └── models/
        ├── anomaly_model.pkl
        └── anomaly_model_metadata.json
```

The state branch is separate from `main`. Generated ML3 history and model files are not committed to the source branch.

## Trusted State Updates

ML3 updates shared state only when all of the following conditions are met:

- the event is `push`
- the Git reference is `refs/heads/main`
- the workflow was triggered by a qualifying C/C++ change
- the current pipeline metrics are valid

Pull-request, manual, and feature-branch executions do not modify shared ML3 state.

## Required Workflow Configuration

The consuming workflow requires write access so ML3 can update `devsecops-state`:

```yaml
permissions:
  contents: write
```

Concurrency is used to reduce simultaneous updates to the state branch:

```yaml
concurrency:
  group: ml3-state-${{ github.repository }}
  cancel-in-progress: false
```

The repository checkout should include full Git history:

```yaml
- uses: actions/checkout@v4
  with:
    ref: ${{ github.head_ref || github.ref_name }}
    fetch-depth: 0
```

`fetch-depth: 0` supports reliable commit and diff analysis by ML1.

## ML3 Execution Order

ML3 follows this order:

1. Restore existing ML3 state from `devsecops-state`.
2. Collect and validate the current pipeline metrics.
3. Run inference using the existing model when available.
4. Generate the ML3 report.
5. Append the current record only for a trusted execution.
6. Train or retrain when the configured threshold is reached.
7. Persist updated state to `devsecops-state`.
8. Run the Security Decision Engine.

Inference always occurs before the current record is appended and before retraining.

## ML3 Lifecycle

With the default settings:

```text
Records 1–29
Collect trusted history
Return NOT_AVAILABLE

Record 30
Append the trusted record
Train the initial Isolation Forest model
Return NOT_AVAILABLE

Record 31
Run the first anomaly evaluation
Append the record after inference

Record 50
Evaluate using the existing model
Append the record
Retrain using all 50 trusted records

Records 70, 90, ...
Repeat retraining after each additional 20 trusted records
```

The default lifecycle is controlled by:

```text
ml3-minimum-history: 30
ml3-retraining-interval: 20
```
