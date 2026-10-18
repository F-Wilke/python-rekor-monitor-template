# TruffleHog pre-commit verification (safe demonstration)

The pre-commit hook scans the **staged patch** for the proposed commit. It invokes
`trufflehog filesystem --no-update --no-verification --fail --json` on a
temporary patch file. `--no-verification` keeps scanning fully offline, but may
report unverified matches; it does not make synthetic strings equivalent to
real, validated provider credentials.

Install TruffleHog and run `poetry install` and
`poetry run pre-commit install`. To demonstrate the hook without creating
a leaked commit, use a temporary throwaway branch and a *synthetic* recognized
credential test vector obtained from TruffleHog's upstream test fixtures.
Do not use real AWS credentials. Write the vector into `leak-demo.txt`
(which must not be ignored), run:

```sh
git add leak-demo.txt
poetry run pre-commit run trufflehog-commit
```

Capture the failing output, then remove the staged sample via
`git restore --staged leak-demo.txt` and delete `leak-demo.txt`.
Never force a commit past a failing security hook.

GitHub branch protection is repository configuration, not versioned content:
in **Settings → Rules → Rulesets** create an active ruleset targeting
`refs/heads/main`, require pull requests before merging, block force pushes
and deletion, and require linear history. Take a screenshot of the active
rule. Ensure your repository plan/permissions support enforcement.

For the coverage screenshot, run:

```sh
poetry run pytest --cov=main --cov=merkle_proof --cov=util --cov-report=term-missing --cov-fail-under=75
```

Capture the terminal output after a successful run. Reports must be genuine
run outputs, not reconstructed examples.
