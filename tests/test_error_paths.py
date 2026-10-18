"""Additional error-path and CLI tests without live network calls."""
import sys

import pytest

import main


class Response:
    def __init__(self, value):
        self.value = value

    def raise_for_status(self):
        pass

    def json(self):
        return self.value


def test_log_non_mapping_entry(monkeypatch):
    monkeypatch.setattr(main.requests, "get", lambda *a, **kw: Response({"x": None}))
    with pytest.raises(ValueError):
        main.get_log_entry(0)


def test_get_proof_wrong_type():
    with pytest.raises(ValueError):
        main.get_verification_proof(1, entry={"verification": {"inclusionProof": []}})


def test_proof_index_rejects_negative():
    with pytest.raises(ValueError):
        main.get_verification_proof(-1, entry={})


def test_consistency_bad_type():
    with pytest.raises(ValueError):
        main.consistency(None)


@pytest.mark.parametrize("value", [
    {"treeID": "abc", "treeSize": 1, "rootHash": "aa"},
    {"treeID": "1", "treeSize": 0, "rootHash": "aa"},
    {"treeID": "1", "treeSize": 1, "rootHash": 2},
])
def test_consistency_bad_checkpoint(value):
    with pytest.raises(ValueError):
        main.consistency(value)


def test_consistency_missing_hashes(monkeypatch):
    monkeypatch.setattr(main, "get_latest_checkpoint", lambda debug=False: {"treeID": "1", "treeSize": 4, "rootHash": "aa"})
    monkeypatch.setattr(main.requests, "get", lambda *a, **kw: Response({}))
    with pytest.raises(ValueError):
        main.consistency({"treeID": "1", "treeSize": 2, "rootHash": "bb"})


def test_inclusion_negative_index():
    with pytest.raises(ValueError):
        main.inclusion(-1, "artifact")


def test_inclusion_bad_proof(monkeypatch):
    import base64
    import json
    body = base64.b64encode(json.dumps({"spec": {"signature": {
        "content": base64.b64encode(b"sig").decode(),
        "publicKey": {"content": base64.b64encode(b"cert").decode()}
    }}}).encode()).decode()
    monkeypatch.setattr(main, "get_log_entry", lambda *args: {
        "body": body,
        "verification": {"inclusionProof": {"logIndex": 0, "treeSize": 1, "hashes": [4], "rootHash": "aa"}}
    })
    monkeypatch.setattr(main, "extract_public_key", lambda cert: b"key")
    monkeypatch.setattr(main, "verify_artifact_signature", lambda *args: True)
    with pytest.raises(ValueError):
        main.inclusion(0, "file")


def test_cli_checkpoint(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["main.py", "--checkpoint"])
    monkeypatch.setattr(main, "get_latest_checkpoint", lambda debug=False: {"treeSize": 1})
    main.main()
    assert '"treeSize": 1' in capsys.readouterr().out


@pytest.mark.parametrize("args,expected", [
    (["--consistency"], "tree id"),
    (["--consistency", "--tree-id", "1"], "tree size"),
    (["--consistency", "--tree-id", "1", "--tree-size", "2"], "root hash"),
])
def test_cli_missing_options(monkeypatch, capsys, args, expected):
    monkeypatch.setattr(sys, "argv", ["main.py", *args])
    main.main()
    assert expected in capsys.readouterr().out


def test_cli_consistency(monkeypatch):
    monkeypatch.setattr(sys, "argv", [
        "main.py", "--consistency", "--tree-id", "1", "--tree-size", "2",
        "--root-hash", "aa", "--debug",
    ])
    received = []
    monkeypatch.setattr(main, "consistency", lambda checkpoint, debug=False: received.append((checkpoint, debug)))
    main.main()
    assert received == [({"treeID": "1", "treeSize": 2, "rootHash": "aa"}, True)]


def test_cli_inclusion(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["main.py", "--inclusion", "5", "--artifact", "file"])
    received = []
    monkeypatch.setattr(main, "inclusion", lambda *args: received.append(args))
    main.main()
    assert received == [(5, "file", False)]
