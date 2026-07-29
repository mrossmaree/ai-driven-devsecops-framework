# GitHub Integration Overview

This repository provides a reusable composite action for AI-assisted DevSecOps checks in C/C++ workflows.

## Composite Action vs Workflow Triggers

* The [composite action](../../action.yml) defines the framework's runtime steps.
* It does not define workflow start events.
* Event triggers must be defined in the consuming repository workflow.
* GitHub event context is injected into the action steps at runtime.

## Default Trigger Model

The default [workflow template](template/run-ai-devsecops-security-scan.yml) supports three execution paths:

1. Pull request to `main` — preventive.
2. Direct push to `main` — reactive.
3. Manual `workflow_dispatch` run.

### Trigger Table

| User action                                            | Automatic run? | Event                          |
| ------------------------------------------------------ | -------------- | ------------------------------ |
| Push C/C++ change directly to `main`                   | Yes            | `push`                         |
| Push documentation-only change to `main`               | No             | Path filter blocks the run     |
| Open PR to `main` with C/C++ changes                   | Yes            | `pull_request`                 |
| Push new C/C++ commit to branch with open PR to `main` | Yes            | `pull_request` (`synchronize`) |
| Push to feature branch without PR                      | No             | None                           |
| Manual run from Actions                                | Yes            | `workflow_dispatch`            |

## Security Gate Behavior

* `BLOCK` fails the `security-scan` workflow check.
* On PRs, merge prevention requires branch protection or a ruleset that requires the `security-scan` check.
* On direct pushes to `main`, a failed workflow does not automatically revert the commit.
* `REVIEW` is advisory by default and does not block merging.

## Checkout and ML1 Diff Reliability

Recommended checkout configuration in the consuming workflow:

```yaml
- uses: actions/checkout@v4
  with:
    ref: ${{ github.head_ref || github.ref_name }}
    fetch-depth: 0
```

This supports:

* PR head checkout for `pull_request` events;
* `main` checkout for direct pushes to `main`;
* selected branch or ref checkout for `workflow_dispatch`.

`fetch-depth: 0` is strongly recommended for reliable ML1 diff resolution.

## ML1 Event Behavior at Runtime

* Pull-request runs pass the PR base and head SHAs into ML1.
* Push and manual runs use the implemented fallback diff behaviour when explicit base and head SHAs are unavailable.

## ML3 Persistence with the Default Template

The persistence condition in the [composite action](../../action.yml) requires:

* `github.event_name == 'push'`;
* `github.ref_name != 'main'`;
* `inputs.ml3-persist-state == 'true'`.

Under the default template, automatic `push` runs are limited to `main`. Therefore, the non-main push persistence condition is not reached automatically.

As a result:

* the default behaviour performs no automatic ML3 state write-back;
* persistence requires an intentionally designed non-main push workflow;
* pull-request runs remain protected from state commits.

## Workflow Permissions

The default template follows least privilege by using read-only repository access:

```yaml
permissions:
  contents: read
```

A separately designed ML3 persistence workflow that commits and pushes state must use:

```yaml
permissions:
  contents: write
```
