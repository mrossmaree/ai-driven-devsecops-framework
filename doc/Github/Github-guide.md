# GitHub Setup Guide for Consuming Repositories

This guide explains how to configure a consuming repository to run the AI-Driven DevSecOps Framework.

## 1. Prerequisites

Before starting, confirm that:

- the repository contains C or C++ source files
- GitHub Actions is enabled
- the framework repository is accessible
- you have administrator access to repository Actions and branch settings
- the default branch is `main`

The workflow template assumes the framework is referenced as:

```yaml
uses: mrossmaree/ai-driven-devsecops-framework@main
```

Update the owner, repository, or reference if required.

## 2. Enable GitHub Actions

In the consuming repository, go to:

```text
Settings
→ Actions
→ General
```

Under **Actions permissions**, allow the actions used by the workflow, including:

```text
actions/checkout
mrossmaree/ai-driven-devsecops-framework
```

For an organisation repository, organisation-level Actions policies may also need to allow the framework action.

## 3. Configure Workflow Permissions

ML3 needs permission to write its state to `devsecops-state`.

Go to:

```text
Settings
→ Actions
→ General
→ Workflow permissions
```

Select:

```text
Read and write permissions
```

Click **Save**.

The workflow must also contain:

```yaml
permissions:
  contents: write
```

The option **Allow GitHub Actions to create and approve pull requests** is not required.

If read and write permissions cannot be selected, check whether an organisation or enterprise policy is forcing the workflow token to read-only access.

## 4. Add the Workflow

Copy the framework template:

```text
doc/Github/template/run-ai-devsecops-security-scan.yml
```

Create this file in the consuming repository:

```text
.github/workflows/security.yml
```

A minimal example is:

```yaml
name: AI DevSecOps Security Scan

on:
  pull_request:
    paths:
      - "**/*.c"
      - "**/*.cc"
      - "**/*.cpp"
      - "**/*.cxx"
      - "**/*.h"
      - "**/*.hpp"

  push:
    branches:
      - main
    paths:
      - "**/*.c"
      - "**/*.cc"
      - "**/*.cpp"
      - "**/*.cxx"
      - "**/*.h"
      - "**/*.hpp"

  workflow_dispatch:

permissions:
  contents: write

concurrency:
  group: ml3-state-${{ github.repository }}
  cancel-in-progress: false

jobs:
  security-scan:
    name: security-scan
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref || github.ref_name }}
          fetch-depth: 0

      - name: Run AI DevSecOps Framework
        uses: mrossmaree/ai-driven-devsecops-framework@main
        with:
          ml3-minimum-history: "30"
          ml3-retraining-interval: "20"
          ml3-contamination: "0.10"
          ml3-state-branch: "devsecops-state"
```

Retain any additional inputs from the official framework template.

## 5. Configure the `main` Branch

After the workflow has run successfully at least once, configure branch protection or a ruleset for `main`.

Go to either:

```text
Settings
→ Rules
→ Rulesets
```

or:

```text
Settings
→ Branches
→ Branch protection rules
```

Recommended settings:

- require a pull request before merging
- require status checks to pass
- select the `security-scan` check
- require branches to be up to date before merging
- block force pushes
- block branch deletion

The `security-scan` check may appear only after the workflow has completed successfully in the repository.

Keep the job name stable:

```yaml
jobs:
  security-scan:
    name: security-scan
```

## 6. Configure the `devsecops-state` Branch

ML3 stores state in:

```text
devsecops-state
```

The first trusted push to `main` may create this branch automatically.

Do not apply the same protection settings used for `main`.

The state branch should not require:

- a pull request before updates
- the `security-scan` status check
- manual approval for every push
- signed commits unless workflow signing is configured

If a ruleset applies to all branches, exclude `devsecops-state` from rules that prevent GitHub Actions from creating or updating the branch.

A suitable state-branch rule may:

- block force pushes
- block deletion
- allow normal GitHub Actions updates
- avoid pull-request and required-check requirements

## 7. Validate the First Run

Commit or merge a qualifying C or C++ change into `main`.

Open:

```text
Actions
→ AI DevSecOps Security Scan
```

Confirm that the workflow runs:

1. checkout
2. ML1
3. ML2
4. ML3 state restoration
5. ML3 metrics collection
6. ML3 orchestration
7. ML3 state persistence
8. Security Decision Engine
9. report upload

For the first trusted run, the expected ML3 result is:

```text
Status: NOT_AVAILABLE
Reason: INSUFFICIENT_HISTORY
```

Then check the repository branch selector.

The following branch should exist:

```text
devsecops-state
```

It should contain:

```text
.devsecops/anomaly_detection/pipeline_metrics.csv
```

After the first run:

- the history file should contain one trusted record
- no model should exist before the minimum history is reached
- ML3 state files should not appear on `main`

## 8. Validate Pull-Request Behaviour

Create a feature branch with a qualifying C or C++ change and open a pull request.

Expected behaviour:

- the security workflow runs
- ML3 may restore existing state
- ML3 does not append a history row
- ML3 does not train or retrain
- ML3 does not update `devsecops-state`

The latest commit on `devsecops-state` should remain unchanged after the pull-request run.

After merging the pull request, the resulting push to `main` may add one trusted history record.

## 9. Troubleshooting

### The workflow cannot use the framework action

Check:

- GitHub Actions is enabled
- the workflow uses the correct framework repository and reference
- repository or organisation policy allows the framework action
- private framework access is configured when applicable

### `devsecops-state` is not created

Check:

- the event was a `push` to `main`
- the changed files match the C/C++ path filters
- the workflow contains `permissions: contents: write`
- repository workflow permissions are set to read and write
- no ruleset blocks branch creation or updates
- the ML3 persistence step did not fail

### State push is rejected

Check the Actions log for messages such as:

```text
403 Resource not accessible by integration
remote rejected
protected branch update failed
repository rule violation
```

Then review:

- workflow token permissions
- state-branch rules
- organisation rulesets
- signed-commit requirements
- branch creation and update restrictions

### `security-scan` remains pending

The workflow uses C/C++ path filters. A pull request without matching files may skip the workflow.

If `security-scan` is a required check for every pull request, review whether path filtering is suitable for the repository's merge policy.

### ML3 remains `NOT_AVAILABLE`

This is expected while fewer than 30 trusted records are available.

The initial model is trained at record 30. Detection begins from record 31.

### History does not increase after a pull request

This is expected. Pull-request runs are read-only.

History increases only after a valid qualifying push to `main`.

## 10. Setup Checklist

Before testing, confirm:

- [ ] GitHub Actions is enabled.
- [ ] The framework action is allowed.
- [ ] `.github/workflows/security.yml` exists.
- [ ] The workflow references the correct framework repository.
- [ ] Pull-request and `main` push triggers are configured.
- [ ] C/C++ path filters match the project.
- [ ] `permissions: contents: write` is declared.
- [ ] Workflow permissions are set to read and write.
- [ ] Checkout uses `fetch-depth: 0`.
- [ ] Concurrency is configured.
- [ ] No ruleset blocks `devsecops-state`.
- [ ] `main` branch protection is configured.
- [ ] The `security-scan` check is selected after its first successful run.
- [ ] The first trusted main run creates one ML3 history record.
- [ ] A pull-request run does not modify ML3 state.
