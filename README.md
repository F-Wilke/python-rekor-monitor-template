# Python Rekor Monitor Template

Python command-line verifier for [Sigstore Rekor](https://docs.sigstore.dev/logging/overview/). It fetches Rekor transparency-log checkpoints, verifies Merkle inclusion proofs and artifact ECDSA signatures, and verifies consistency between checkpoints.

## Requirements and installation

Python 3.10+ and [Poetry](https://python-poetry.org/docs/#installation). Clone this repository, then run:

```sh
poetry install
poetry run python main.py --help
```

Use a known artifact and its Rekor log index to check inclusion and signature:

```sh
poetry run python main.py --checkpoint
poetry run python main.py --inclusion 123456 --artifact ./artifact.json
poetry run python main.py --consistency --tree-id TREE_ID --tree-size OLD_SIZE --root-hash OLD_HEX_ROOT
```

Replace the placeholders with real, trusted Rekor values. Rekor queries require internet access. Proof checks and certificate parsing do not replace independently validating signer identity, certificate trust, or checkpoint authenticity; do not interpret a matching signature alone as supply-chain authorization.

## Development

```sh
poetry install
poetry run ruff check .
poetry run ruff format --check .
poetry run mypy main.py merkle_proof.py util.py
poetry run bandit -r main.py merkle_proof.py util.py
poetry run pytest --cov=main --cov=merkle_proof --cov=util --cov-report=term-missing --cov-fail-under=75
poetry run pre-commit install
```

The project uses Ruff for linting/formatting, mypy for static types, Bandit for SAST, pytest for tests, and TruffleHog for pre-commit secret scanning. To install TruffleHog, follow https://github.com/trufflesecurity/trufflehog#installation and verify `trufflehog --version`. The hook scans only the proposed new commit's changes, not the whole filesystem. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

Do not commit genuine credentials, even for testing; use intentionally synthetic test strings.
