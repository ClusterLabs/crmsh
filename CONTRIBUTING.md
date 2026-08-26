# Contributing to crmsh

First off, thank you for considering contributing to `crmsh`!

This document outlines the guidelines and best practices for setting up your development environment, writing code, formatting commit messages, and submitting pull requests.

## Development Setup

### Data Manifest and Git Hooks

`data-manifest` contains a list of all shared data files to install.

Whenever a file that is to be installed to `/usr/share/crmsh` is added,
for example a cluster script or crmsh template, the `data-manifest`
file needs to be regenerated, by running `./update-data-manifest.sh`.

`crmsh` includes a `pre-commit` hook to automatically update the `data-manifest` before each commit. To install and configure this hook, run:

```shell
cp contrib/git-hook-pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

---

## Code Style & Conventions

We aim for code that is clean, readable, and highly maintainable. Please adhere to the following conventions:

* **Python Version:** `crmsh` targets Python 3.11 or newer.
* **PEP 8:** Adhere to general Python PEP 8 guidelines.
* **Line Width:** We target a maximum line width of **120 characters**.
* **Import Style:**
  * Place all imports at the very beginning of the file; **never** use local imports within functions/classes.
  * Prefer importing entire modules over specific classes or members (e.g., use `from . import utils` rather than `from .utils import get_stdout`).

---

## Commit Message Guidelines

Because our commit messages are automatically parsed to generate changelogs, structural clarity is critical.

### Commit Format

Each commit message consists of a **header**, a **body**, and an optional **footer**. The header has a special format that includes a **type**, a **scope**, a **subject**, and an optional reference **tag**:

```text
<type>(<scope>): <subject> (<tag>)

<body>

<footer>
```

* **`<tag>`**: Used to reference bug trackers or issue management. It is appended in parentheses at the end of the subject line and can be:
  * A GitHub issue, e.g., `(#123)`
  * A bugzilla number, e.g., `(bsc#1234567)`
  * A jira ticket, e.g., `(jsc#PED-12345)`
  * Multiple tags can be separated by commas, e.g., `(bsc#1234567, #123)`

### Commit Types

* **feat**: A new feature (corresponds to a minor release)
* **fix**: A bug fix (corresponds to a patch release)
* **docs**: Documentation only changes
* **style**: Changes that do not affect the meaning of the code (white-space, formatting, missing semi-colons, etc.)
* **refactor**: A code change that neither fixes a bug nor adds a feature
* **perf**: A code change that improves performance
* **test**: Adding missing tests or correcting existing tests
* **build**: Changes that affect the build system or external dependencies
* **ci**: Changes to CI configuration files and scripts
* **chore**: Other changes that don't modify src or test files

## Testing

### Unit Tests

`test/unittests` are unit tests that test small pieces of
code or functionality. To run these tests, use `tox`.

1. Install `tox`:
   ```shell
   pip install tox
   ```
2. Run the tests from the root directory of the repository:
   ```shell
   tox
   ```

### Functional Tests

* `test/testcases` are larger integration tests which require
  a Pacemaker installation on the machine where the tests are to
  run.
* `test/features` are integration tests that verify cluster-level behavior inside containerized environments.

To run these tests:

```shell
./test/run-functional-tests [OPTIONS] | [TESTCASE INDEX]
```

## OpenSUSE Build Service Integration

Our pull request workflow is tightly integrated with the [openSUSE Build Service](https://build.opensuse.org/):
* As soon as your pull request is merged, a new RPM package is automatically built on the [network:ha-clustering:Unstable](https://build.opensuse.org/project/show/network:ha-clustering:Unstable) repository.
* A `submit request` is then automatically created to the *crmsh* package maintainers at [network:ha-clustering:Factory](https://build.opensuse.org/project/show/network:ha-clustering:Factory).
