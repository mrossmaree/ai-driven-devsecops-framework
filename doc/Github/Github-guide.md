# GitHub Setup Guide for Consuming Repositories

This guide explains how to run the framework safely in GitHub Actions with clear pull-request, direct-main-push, and manual-dispatch behavior.

## 1. Use the Workflow Template

Template in this repository:

- [doc/Github/template/run-ai-devsecops-security-scan.yml](doc/Github/template/run-ai-devsecops-security-scan.yml)

In your consuming repository, create:

- `.github/workflows/security.yml`

Copy the template content into that file.

## 2. Trigger Policy in the Template

The default template is intentionally scoped to avoid duplicate feature-branch push runs.

```yaml
on:
  push:
    branches:
      - main
    paths:
      - '**/*.c'
      - '**/*.cpp'
      - '**/*.cc'
      - '**/*.cxx'
      - '**/*.h'
      - '**/*.hpp'

  pull_request:
    branches:
      - main
    paths:
      - '**/*.c'
      - '**/*.cpp'
      - '**/*.cc'
      - '**/*.cxx'
      - '**/*.h'
      - '**/*.hpp'

  workflow_dispatch:
```

### Trigger Table

| User action | Automatic run? | Event |
|---|---|---|
| Push C/C++ change directly to `main` | Yes | `push` |
| Push documentation-only change to `main` | No | path filter blocks |
| Open PR to `main` with C/C++ changes | Yes | `pull_request` |
| Push new C/C++ commit to branch with open PR to `main` | Yes | `pull_request` (`synchronize`) |
| Push to feature branch without open PR | No | none |
| Start manually from Actions | Yes | `workflow_dispatch` |

Notes:

- `push.branches: main` applies to direct pushes into `main` only.
- `pull_request.branches: main` matches the PR base/target branch, not the source branch name.
- A feature-branch update with an open PR to `main` triggers via PR synchronization.
- A feature-branch update without an open PR does not trigger this default workflow.

## 3. Composite Action Responsibility

- [action.yml](action.yml) defines a **composite action** and runtime steps.
- [action.yml](action.yml) does **not** define workflow start events.
- Event triggers belong to the consuming repository workflow (`on:` block).
- GitHub event context (`github.*`) is passed into the composite action at runtime by Actions.

## 4. Checkout Configuration

Template checkout:

```yaml
- uses: actions/checkout@v4
  with:
    ref: ${{ github.head_ref || github.ref_name }}
    fetch-depth: 0
```

This is preserved intentionally because it provides the needed branch/ref behavior:

- `pull_request`: checks out PR head branch (`github.head_ref`).
- `push`: checks out pushed branch (`github.ref_name`, `main` in default template).
- `workflow_dispatch`: checks out selected branch/ref (`github.ref_name`).

`fetch-depth: 0` is strongly recommended for ML1 diff reliability.

## 5. ML1 Event and Diff Behavior

ML1 receives runtime context from the composite action:

- `pull_request`: base and head SHAs are passed from PR context.
- `push`: predictor uses implemented fallback comparison when explicit base/head are not provided.
- `workflow_dispatch`: also uses implemented fallback behavior when explicit base/head are absent.

Operational requirement:

- Keep `fetch-depth: 0` for reliable diff resolution and changed-function analysis.

## 6. Branch Protection and Gate Semantics

- Pull-request scans run before merge and are preventive.
- Direct pushes to `main` are reactive and run after integration.
- `BLOCK` fails the workflow.
- Merge prevention on PR depends on branch protection requiring the workflow check.
- `BLOCK` does not auto-revert direct pushes.
- `REVIEW` does not block merges by itself unless repository policy explicitly treats it as blocking.

## 7. ML3 Persistence and Default Template

Current persistence step in [action.yml](action.yml):

- event is `push`
- branch is not `main`
- `ml3-persist-state` is `true`

With the default template (pushes only to `main` plus PR and manual runs), that persistence condition is not reached automatically.

Implication for the frozen framework:

- `ml3-persist-state` remains `false` by default.
- No automatic ML3 state write-back occurs under the default template.
- Enabling persistence requires an intentional non-main push workflow or a separate state-management design.
- PR safety is preserved because no state commit/push occurs on `pull_request` runs.

## 8. Required Status Check

If your job name is `security-scan`, configure branch protection to require that exact check name.
