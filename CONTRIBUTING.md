# Contributing

Open an issue before substantial work. For bug reports, give the expected and actual results, minimal reproduction, platform, Python version, and sanitized logs. For features, explain motivation, proposed behavior, and compatibility impact. Never include real keys, tokens, or sensitive data.

Create a topic branch from `main` and submit a focused pull request linked to the issue. Describe changes, risks, and how to reproduce testing. Changes to cryptographic verification should include both passing and failing test vectors, and should not disable verification checks merely to satisfy tests. At least one owner reviews changes prior to merge.

## Coding standards

Use Python 3.10+; preserve clear type annotations, straightforward control flow and explicit exceptions. Ruff enforces imports/style and formats source (88-character lines). Mypy and Bandit should report no unaddressed issues. Avoid unnecessary dependencies and pin updates through Poetry's lockfile.

## Before opening a PR

```sh
poetry install
poetry run pre-commit install
poetry run ruff check .
poetry run ruff format --check .
poetry run mypy main.py merkle_proof.py util.py
poetry run bandit -r main.py merkle_proof.py util.py
poetry run pytest --cov=main --cov=merkle_proof --cov=util --cov-report=term-missing --cov-fail-under=75
```

New behavior or bug fixes require pytest tests. CI should pass with at least 75% aggregate coverage before merge. Keep PRs scoped, ensure no secrets are present, and respond to review comments. Prefer squash/rebase merges to preserve linear history.
