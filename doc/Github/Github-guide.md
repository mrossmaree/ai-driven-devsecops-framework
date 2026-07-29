# GitHub Setup Guide for Consuming Repositories

This guide configures a consuming repository to run the framework with repository-specific ML3 state persisted to a dedicated state branch.

## 1. Add the Workflow

Use the template:

- [workflow template](template/run-ai-devsecops-security-scan.yml)

Create this workflow in the consuming repository:

```text
.github/workflows/security.yml
```

## 2. Required Triggers

Use C/C++ qualifying triggers for PR and push-to-main:

- `pull_request` with C/C++ path filters
- `push` on `main` with C/C++ path filters
- optional `workflow_dispatch`

## 3. Required Permissions and Concurrency

The workflow must allow ML3 state updates to the dedicated state branch:

```yaml
permissions:
  contents: write

concurrency:
  group: ml3-state-${{ github.repository }}
  cancel-in-progress: false
```

## 4. Checkout

Use full history:

```yaml
- uses: actions/checkout@v4
  with:
    ref: ${{ github.head_ref || github.ref_name }}
    fetch-depth: 0
```

`fetch-depth: 0` is required for reliable ML1 diff behavior.

## 5. Composite Action Responsibility

- [composite action](../../action.yml) defines runtime logic.
- The consuming workflow defines trigger events.
- ML3 state persistence is always scoped by trusted-main rules inside the action.

## 6. ML3 Trusted State Updates

Shared ML3 history/model updates occur only when all conditions are met:

- `github.event_name == push`
- `github.ref == refs/heads/main`
- qualifying C/C++ change
- valid current metrics

PR/manual/feature-branch runs are read-only for shared ML3 state.

## 7. Dedicated State Branch

ML3 state is stored only on:

- `devsecops-state`

State layout:

```text
.devsecops/
└── anomaly_detection/
    ├── pipeline_metrics.csv
    └── models/
        ├── anomaly_model.pkl
        └── anomaly_model_metadata.json
```

The framework action restores from this branch at start and persists updates back to this branch after trusted runs.

## 8. Branch Protection

Keep `security-scan` as a required check in branch protection/rulesets when enforcing preventive gating on pull requests.
