# GitHub Setup Guide for Consuming Repositories

This guide explains how to configure a consuming repository to run the AI-Driven DevSecOps Framework through GitHub Actions.

The default setup supports:

* preventive scanning of pull requests targeting `main`;
* reactive scanning of direct pushes to `main`;
* manually triggered scans;
* branch protection using the framework's security status check.

## 1. Prepare the Consuming Repository

Create or select a GitHub repository containing the C/C++ project that will be analysed by the framework.

The consuming repository should contain the source code to be scanned and a GitHub Actions workflow that references the published framework repository.

## 2. Use the Workflow Template

The workflow template is available in this framework repository:

* [workflow template](template/run-ai-devsecops-security-scan.yml)

In the consuming repository, create:

```text
.github/workflows/security.yml
```

Copy the complete run-ai-devsecops-security-scan.yml template into .github/workflows/security.yml. The example below highlights the key sections that should remain unchanged.

The workflow must reference the published framework repository:

```yaml
- name: Run AI DevSecOps Framework
  uses: <framework-owner>/ai-driven-devsecops-framework@main
```

Replace `<framework-owner>` with the GitHub account or organisation that owns the framework repository.

For this published framework, the reference is:

```yaml
- name: Run AI DevSecOps Framework
  uses: mrossmaree/ai-driven-devsecops-framework@main
```

The general workflow structure should include:

```yaml
name: AI DevSecOps Security Scan

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

permissions:
  contents: read

jobs:
  security-scan:
    runs-on: ubuntu-latest

    steps:
      - name: Check out consuming repository
        uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref || github.ref_name }}
          fetch-depth: 0

      - name: Run AI DevSecOps Framework
        uses: mrossmaree/ai-driven-devsecops-framework@main
```

Retain the complete input configuration included in the provided workflow template.

## 3. Trigger Policy

The default workflow is intentionally scoped to prevent duplicate scans for ordinary feature-branch pushes.

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

| User action                                                     | Automatic run? | GitHub event                             |
| --------------------------------------------------------------- | -------------: | ---------------------------------------- |
| Push a C/C++ change directly to `main`                          |            Yes | `push`                                   |
| Push only documentation changes to `main`                       |             No | Blocked by path filters                  |
| Open a pull request to `main` containing C/C++ changes          |            Yes | `pull_request`                           |
| Push another C/C++ commit to a branch with an open PR to `main` |            Yes | `pull_request` with `synchronize` action |
| Push to a feature branch without an open PR                     |             No | None                                     |
| Start the workflow manually from the Actions tab                |            Yes | `workflow_dispatch`                      |

Important behaviour:

* `push.branches: main` applies to pushes made directly to `main`.
* `pull_request.branches: main` refers to the PR base or target branch.
* It does not refer to the source feature-branch name.
* Updating a feature branch with an open PR to `main` triggers the workflow through PR synchronisation.
* Updating a feature branch without an open PR does not trigger the default workflow.
* Path filters prevent the workflow from running when a change contains no supported C/C++ source or header files.

## 4. Composite Action Responsibility

The framework is implemented as a composite GitHub Action.

* The [composite action](../../action.yml) defines the framework's runtime steps.
* The composite action does not determine when a workflow starts.
* Workflow events are configured in the consuming repository's `security.yml` file.
* GitHub Actions passes the `github.*` event context into the composite action during execution.

The responsibilities are separated as follows:

| Component                     | Responsibility                                       |
| ----------------------------- | ---------------------------------------------------- |
| Consuming repository workflow | Events, checkout, permissions and job configuration  |
| Framework composite action    | ML1, ML2, ML3 and Security Decision Engine execution |

## 5. Checkout Configuration

The workflow template uses:

```yaml
- name: Checkout target project
  uses: actions/checkout@v4
  with:
    ref: ${{ github.head_ref || github.ref_name }}
    fetch-depth: 0
```

This configuration provides the required behaviour for each supported event:

* `pull_request`: checks out the PR source branch using `github.head_ref`;
* `push`: checks out the pushed branch using `github.ref_name`;
* `workflow_dispatch`: checks out the branch or ref selected when the workflow is started manually.

The following option should be retained:

```yaml
fetch-depth: 0
```

It provides the full Git history needed for reliable ML1 diff resolution and changed-function analysis.

## 6. GitHub Event Context

GitHub Actions provides different event information depending on whether the workflow is triggered by a pull request, direct push, or manual execution.

The AI-Driven DevSecOps Framework receives this event context through the composite action during execution. ML1 (Commit Risk Prediction) uses the GitHub event information to determine the appropriate Git comparison for analysing changed functions.

### Pull request

For a pull-request run:

- the PR base SHA is obtained from the GitHub pull-request context;
- the PR head SHA is obtained from the GitHub pull-request context;
- ML1 analyses the changes between the PR base and head commits.

### Push

For a direct push:

- explicit PR base and head SHAs are not available;
- ML1 uses its implemented fallback comparison.

### Manual dispatch

For a manually triggered workflow:

- explicit PR base and head SHAs are normally unavailable;
- ML1 uses its implemented fallback comparison.

For all supported events, retain:

```yaml
fetch-depth: 0
```

## 7. Enable GitHub Actions

GitHub Actions is normally enabled when a repository is created, but the repository settings should be verified before running the framework.

Open:

```text
Repository
→ Settings
→ Actions
→ General
```

### Actions permissions

Under **Actions permissions**, select:

```text
Allow all actions and reusable workflows
```

This setting allows the workflow to use both:

- `actions/checkout@v4`
- `mrossmaree/ai-driven-devsecops-framework@main`

Do not select **Disable actions**.

If **Allow mrossmaree actions and reusable workflows** is selected, GitHub-owned actions such as `actions/checkout@v4` may not be available unless they are explicitly allowed.

Leave **Require actions to be pinned to a full-length commit SHA** disabled. The provided workflow template uses version references (`@v4` and `@main`) rather than commit SHAs.

After adding `.github/workflows/security.yml`, open the repository's **Actions** tab and verify that the **Run AI DevSecOps Security Scan** workflow appears.

## 8. Workflow Permissions

The workflow follows the principle of least privilege and only requires read access to the repository.

The workflow declares:

```yaml
permissions:
  contents: read
```

This permission is sufficient for:

- checking out the consuming repository;
- reading the source code;
- executing ML1, ML2 and ML3;
- generating framework reports;
- producing the final security decision;
- uploading workflow artefacts when configured.

The workflow does not require write permission under the default configuration.

The repository's default workflow permissions can be verified by opening:

```text
Repository
→ Settings
→ Actions
→ General
→ Workflow permissions
```

Select:

```text
Read repository contents and packages permissions
```

The repository does not need **Read and write permissions** because the default workflow does not modify or commit files.

Leave **Allow GitHub Actions to create and approve pull requests** disabled because the framework does not create or approve pull requests.

### Alternate ML3 Persistence Design

A separately designed ML3 persistence workflow that commits and pushes state would require:

```yaml
permissions:
  contents: write
```

and the repository default workflow permission would need to allow write access.

Write permission should not be enabled unless repository write-back has been intentionally implemented and reviewed.

## 9. Branch Protection and Gate Semantics

The framework produces three final decisions:

* `PASS`
* `REVIEW`
* `BLOCK`

Their default GitHub behaviour is:

| Decision | Workflow result                         | Default merge effect                    |
| -------- | --------------------------------------- | --------------------------------------- |
| `PASS`   | Successful                              | Required check passes                   |
| `REVIEW` | Successful with advisory review outcome | Does not block automatically            |
| `BLOCK`  | Failed                                  | Blocks merge when the check is required |

Pull-request scanning is preventive because it runs before code is merged.

Direct-main-push scanning is reactive because it runs after the change has already entered `main`.

Important limitations:

* A `BLOCK` decision fails the workflow.
* A `BLOCK` decision prevents a PR merge only when the workflow check is required by branch protection.
* A `BLOCK` result does not automatically revert a direct push to `main`.
* A `REVIEW` decision remains advisory under the default implementation.

## 10. Run the Workflow Once

Before configuring the workflow as a required status check, run it at least once.

This allows GitHub to register the workflow job's check name.

A first run can be created by:

1. creating a feature branch;
2. making a small C/C++ change;
3. pushing the branch;
4. opening a pull request targeting `main`.

For example:

```bash
git checkout -b test/framework-validation
```

After making a C/C++ change, run:

```bash
git add .
git commit -m "Test AI DevSecOps workflow"
git push -u origin test/framework-validation
```

Open a pull request from:

```text
test/framework-validation
```

into:

```text
main
```

Confirm that the workflow starts and that the following job appears:

```text
security-scan
```

If `security-scan` has never run, GitHub may not display it when selecting required status checks.

## 11. Protect the Main Branch

Configure branch protection after the workflow has run at least once.

Depending on the GitHub interface available for the repository, use either a branch protection rule or a repository ruleset.

### Option A: Branch Protection Rule

Open:

```text
Repository
→ Settings
→ Branches
→ Add branch protection rule
```

Set the branch name pattern to:

```text
main
```

Enable:

* **Require a pull request before merging**
* **Require status checks to pass before merging**
* **Require branches to be up to date before merging**

Under required status checks, select:

```text
security-scan
```

Save the branch protection rule.

### Option B: Repository Ruleset

Open:

```text
Repository
→ Settings
→ Rules
→ Rulesets
→ New ruleset
→ New branch ruleset
```

Configure:

* ruleset name: `Protect main`;
* enforcement status: `Active`;
* target branch: `main`.

Enable rules that:

* require a pull request before merging;
* require status checks to pass;
* require the `security-scan` status check;
* require the branch to be up to date before merging when strict checking is intended.

Save the ruleset.

Only one of these approaches is required. Avoid creating overlapping rules unless their combined behaviour is understood.

## 12. Required Status Check

The workflow job is named:

```yaml
jobs:
  security-scan:
```

The required check should therefore appear as:

```text
security-scan
```

Configure branch protection or the ruleset to require that exact check.

Job names should remain clear and unique. Avoid assigning the same job name to unrelated workflows because this may make required-check configuration ambiguous.

After configuration:

* `PASS` allows the required check to pass;
* `REVIEW` remains advisory under the default implementation;
* `BLOCK` fails `security-scan` and prevents the pull request from being merged.

## 13. ML3 Persistence and the Default Template

The current ML3 persistence condition in the [composite action](../../action.yml) requires:

* the event to be `push`;
* the branch not to be `main`;
* `ml3-persist-state` to be `true`.

The default consuming workflow automatically runs push events only for `main`.

Therefore, the persistence condition is not reached automatically under the default workflow.

Implications:

* `ml3-persist-state` remains `false` by default;
* ML3 anomaly detection still runs;
* no automatic Git-based ML3 state write-back occurs;
* pull-request runs do not commit or push state;
* enabling persistence requires a deliberately designed non-main push workflow or another state-management approach;
* a persistence workflow that pushes repository changes requires `contents: write`.

This behaviour preserves pull-request safety and avoids unplanned repository modifications.

## 14. Validate the GitHub Integration

After completing the setup, validate the following scenarios.

### Scenario 1: Pull-Request Scan

1. Create a feature branch.
2. Add or modify a supported C/C++ file.
3. Push the branch.
4. Open a pull request targeting `main`.

Expected result:

* the workflow starts automatically;
* ML1, ML2, ML3 and the Security Decision Engine run;
* the `security-scan` check appears on the pull request.

### Scenario 2: Pull-Request Synchronisation

1. Keep the pull request open.
2. Push another C/C++ commit to the same feature branch.

Expected result:

* the workflow runs again;
* the event is a `pull_request` synchronisation;
* the latest commit receives a new `security-scan` result.

### Scenario 3: Feature Branch Without a Pull Request

1. Create another feature branch.
2. Push a C/C++ change without opening a pull request.

Expected result:

* the default workflow does not start automatically.

This is intentional.

### Scenario 4: Direct Push to `main`

Push a C/C++ change directly to `main` only when repository policy allows it.

Expected result:

* the workflow starts using the `push` event;
* the scan is reactive because the change is already in `main`;
* a `BLOCK` result fails the workflow but does not automatically revert the push.

When branch protection requires pull requests, ordinary direct pushes to `main` should be prevented.

### Scenario 5: Manual Execution

Open:

```text
Repository
→ Actions
→ AI DevSecOps Security Scan
→ Run workflow
```

Select the required branch and start the workflow.

Expected result:

* the workflow runs using `workflow_dispatch`;
* ML1 uses its implemented fallback comparison when PR SHAs are unavailable.

### Scenario 6: Branch Protection

Create a pull request expected to produce a `BLOCK` decision.

Expected result:

* `security-scan` fails;
* GitHub reports that a required check has failed;
* the pull request cannot be merged while the check remains unsuccessful.
