# GitHub Integration Overview

This repository provides a reusable composite action for AI-assisted DevSecOps checks in C/C++ workflows.

## Composite Action vs Workflow Triggers

- [action.yml](action.yml) is a composite action definition.
- It defines runtime steps, not workflow start events.
- Event triggers must be defined in the consuming repository workflow.
- GitHub event context is injected at runtime into action steps.

## Default Trigger Model

The default template in [doc/Github/template/run-ai-devsecops-security-scan.yml](doc/Github/template/run-ai-devsecops-security-scan.yml) is designed for three execution paths:

1. Pull request to `main` (preventive).
2. Direct push to `main` (reactive).
3. Manual `workflow_dispatch` run.

### Trigger Table

| User action | Automatic run? | Event |
|---|---|---|
| Push C/C++ change directly to `main` | Yes | `push` |
| Push documentation-only change to `main` | No | path filter blocks |
| Open PR to `main` with C/C++ changes | Yes | `pull_request` |
| Push new C/C++ commit to branch with open PR to `main` | Yes | `pull_request` (`synchronize`) |
| Push to feature branch without PR | No | none |
| Manual run from Actions | Yes | `workflow_dispatch` |

## Security Gate Behavior

- `BLOCK` fails the workflow.
- On PRs, merge prevention requires branch protection with required checks enabled.
- On direct pushes to `main`, failed workflow does not auto-revert the commit.
- `REVIEW` is advisory by default and is only merge-blocking if repository policy enforces it.

## Checkout and ML1 Diff Reliability

Recommended checkout in consuming workflow:

```yaml
- uses: actions/checkout@v4
  with:
    ref: ${{ github.head_ref || github.ref_name }}
    fetch-depth: 0
```

This supports:

- PR head checkout for `pull_request` events.
- `main` checkout for direct main pushes.
- selected branch/ref checkout for `workflow_dispatch`.

`fetch-depth: 0` is strongly recommended for reliable ML1 diff resolution.

## ML1 Event Behavior in Runtime

- PR runs pass pull-request base/head SHAs into ML1.
- Push/manual runs use implemented fallback diff behavior when explicit base/head are absent.

## ML3 Persistence with Default Template

The persistence condition in [action.yml](action.yml) requires:

- `github.event_name == 'push'`
- `github.ref_name != 'main'`
- `inputs.ml3-persist-state == 'true'`

Under the default template (automatic pushes only on `main`), that condition is not normally reached.

Therefore:

- default behavior is no automatic ML3 state write-back;
- persistence requires an intentional non-main push workflow design;
- PR runs remain safe from state commits.
