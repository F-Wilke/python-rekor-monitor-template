"""Offline tests: no requests to the live Rekor service."""
import base64
import hashlib
import json

import pytest
import requests
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

import main
from merkle_proof import (
    DefaultHasher, RootMismatchError, chain_border_right, chain_inner,
    chain_inner_right, compute_leaf_hash, decomp_incl_proof, inner_proof_size,
    root_from_inclusion_proof, verify_consistency, verify_inclusion,
    verify_match,
)
from util import verify_artifact_signature


class FakeResponse:
    def __init__(self, value):
        self.value = value

    def raise_for_status(self):
        pass

    def json(self):
        return self.value


def test_leaf_hash_domain_separation():
    data = b"hello"
    assert DefaultHasher.hash_leaf(data) == hashlib.sha256(b"\\x00" + data).digest()
    assert DefaultHasher.hash_children(b"a", b"b") == hashlib.sha256(b"\\x01ab").digest()


def test_empty_root():
    assert DefaultHasher.empty_root() == hashlib.sha256(b"").digest()
    assert DefaultHasher.size() == 32


def test_compute_leaf_hash():
    assert compute_leaf_hash(base64.b64encode(b"abc")) == DefaultHasher.hash_leaf(b"abc").hex()


@pytest.mark.parametrize("index,size,expected", [(0, 1, (0, 0)), (0, 2, (1, 0)), (1, 2, (0, 1))])
def test_decompose(index, size, expected):
    assert decomp_incl_proof(index, size) == expected


def test_inner_proof_size():
    assert inner_proof_size(0, 1) == 0
    assert inner_proof_size(0, 2) == 1


def test_chain_inner():
    a, b = DefaultHasher.hash_leaf(b"a"), DefaultHasher.hash_leaf(b"b")
    assert chain_inner(DefaultHasher, a, [b], 0) == DefaultHasher.hash_children(a, b)
    assert chain_inner(DefaultHasher, b, [a], 1) == DefaultHasher.hash_children(a, b)


def test_chain_inner_right():
    a, b = DefaultHasher.hash_leaf(b"a"), DefaultHasher.hash_leaf(b"b")
    assert chain_inner_right(DefaultHasher, b, [a], 1) == DefaultHasher.hash_children(a, b)
    assert chain_inner_right(DefaultHasher, a, [b], 0) == a


def test_chain_border_right():
    a, b = DefaultHasher.hash_leaf(b"a"), DefaultHasher.hash_leaf(b"b")
    assert chain_border_right(DefaultHasher, a, [b]) == DefaultHasher.hash_children(a, b)


def test_root_mismatch():
    with pytest.raises(RootMismatchError):
        verify_match(b"a", b"b")


def test_root_match():
    verify_match(b"a", b"a")


def test_inclusion_one_leaf():
    leaf = DefaultHasher.hash_leaf(b"hello")
    assert root_from_inclusion_proof(DefaultHasher, 0, 1, leaf, []) == leaf
    verify_inclusion(DefaultHasher, 0, 1, leaf.hex(), [], leaf.hex())


def test_inclusion_two_leaves():
    a, b = DefaultHasher.hash_leaf(b"a"), DefaultHasher.hash_leaf(b"b")
    root = DefaultHasher.hash_children(a, b).hex()
    verify_inclusion(DefaultHasher, 0, 2, a.hex(), [b.hex()], root, True)
    verify_inclusion(DefaultHasher, 1, 2, b.hex(), [a.hex()], root)


def test_invalid_inclusion_index():
    with pytest.raises(ValueError):
        root_from_inclusion_proof(DefaultHasher, 1, 1, b"x" * 32, [])


def test_invalid_inclusion_size():
    with pytest.raises(ValueError):
        root_from_inclusion_proof(DefaultHasher, 0, 1, b"x", [])


def test_invalid_proof_count():
    with pytest.raises(ValueError):
        root_from_inclusion_proof(DefaultHasher, 0, 2, b"x" * 32, [])


def test_consistency_equal():
    digest = DefaultHasher.hash_leaf(b"a").hex()
    verify_consistency(DefaultHasher, 1, 1, [], digest, digest)


def test_consistency_equal_wrong_root():
    with pytest.raises(RootMismatchError):
        verify_consistency(DefaultHasher, 1, 1, [], "00" * 32, "11" * 32)


def test_consistency_invalid_sizes():
    with pytest.raises(ValueError):
        verify_consistency(DefaultHasher, 2, 1, [], "00" * 32, "00" * 32)


def test_consistency_empty_tree():
    verify_consistency(DefaultHasher, 0, 1, [], "00" * 32, "11" * 32)


def test_consistency_missing_proof():
    with pytest.raises(ValueError):
        verify_consistency(DefaultHasher, 1, 2, [], "00" * 32, "11" * 32)


def test_consistency_two_leaves():
    a, b = DefaultHasher.hash_leaf(b"a"), DefaultHasher.hash_leaf(b"b")
    verify_consistency(DefaultHasher, 1, 2, [b.hex()], a.hex(), DefaultHasher.hash_children(a, b).hex())


@pytest.mark.parametrize("index", [-1, "0", 1.2])
def test_log_entry_rejects_bad_index(index):
    with pytest.raises(ValueError):
        main.get_log_entry(index)


def test_get_log_entry(monkeypatch):
    monkeypatch.setattr(main.requests, "get", lambda *a, **kw: FakeResponse({"id": {"logIndex": 3, "body": "abc"}}))
    assert main.get_log_entry(3, True)["body"] == "abc"


def test_get_log_entry_mismatch(monkeypatch):
    monkeypatch.setattr(main.requests, "get", lambda *a, **kw: FakeResponse({"id": {"logIndex": 4}}))
    with pytest.raises(ValueError):
        main.get_log_entry(3)


def test_get_log_entry_bad_shape(monkeypatch):
    monkeypatch.setattr(main.requests, "get", lambda *a, **kw: FakeResponse({}))
    with pytest.raises(ValueError):
        main.get_log_entry(3)


def test_get_verification_proof():
    assert main.get_verification_proof(2, entry={"verification": {"inclusionProof": {"treeSize": 1}}}) == {"treeSize": 1}


def test_get_verification_proof_missing():
    with pytest.raises(ValueError):
        main.get_verification_proof(2, entry={})


def test_checkpoint(monkeypatch):
    value = {"treeID": "1", "treeSize": 2, "rootHash": "aa"}
    monkeypatch.setattr(main.requests, "get", lambda *a, **kw: FakeResponse(value))
    assert main.get_latest_checkpoint(True) == value


def test_incomplete_checkpoint(monkeypatch):
    monkeypatch.setattr(main.requests, "get", lambda *a, **kw: FakeResponse({"treeID": 1}))
    with pytest.raises(ValueError):
        main.get_latest_checkpoint()


def test_consistency_invalid_previous():
    with pytest.raises(ValueError):
        main.consistency({})


def test_consistency_tree_mismatch(monkeypatch):
    monkeypatch.setattr(main, "get_latest_checkpoint", lambda debug=False: {"treeID": "2", "treeSize": 5, "rootHash": "aa"})
    with pytest.raises(ValueError):
        main.consistency({"treeID": "1", "treeSize": 2, "rootHash": "aa"})


def test_consistency_not_older(monkeypatch):
    monkeypatch.setattr(main, "get_latest_checkpoint", lambda debug=False: {"treeID": "1", "treeSize": 2, "rootHash": "aa"})
    with pytest.raises(ValueError):
        main.consistency({"treeID": "1", "treeSize": 2, "rootHash": "aa"})


def test_consistency_success(monkeypatch):
    checkpoint = {"treeID": "1", "treeSize": 3, "rootHash": "aa"}
    monkeypatch.setattr(main, "get_latest_checkpoint", lambda debug=False: checkpoint)
    monkeypatch.setattr(main.requests, "get", lambda *a, **kw: FakeResponse({"hashes": [], "rootHash": "aa"}))
    calls = []
    monkeypatch.setattr(main, "verify_consistency", lambda *args: calls.append(args))
    assert main.consistency({"treeID": "1", "treeSize": 2, "rootHash": "bb"}, True)
    assert len(calls) == 1


def test_consistency_invalid_proof(monkeypatch):
    monkeypatch.setattr(main, "get_latest_checkpoint", lambda debug=False: {"treeID": "1", "treeSize": 3, "rootHash": "aa"})
    monkeypatch.setattr(main.requests, "get", lambda *a, **kw: FakeResponse({"hashes": ["bad", 4], "rootHash": "aa"}))
    with pytest.raises(ValueError):
        main.consistency({"treeID": "1", "treeSize": 2, "rootHash": "bb"})


def test_inclusion_requires_artifact():
    with pytest.raises(ValueError):
        main.inclusion(1, "")


def test_inclusion_valid_proof(monkeypatch):
    body = base64.b64encode(json.dumps({"spec": {"signature": {
        "content": base64.b64encode(b"signature").decode(),
        "publicKey": {"content": base64.b64encode(b"certificate").decode()}
    }}}).encode()).decode()
    leaf = compute_leaf_hash(body)
    entry = {"body": body, "verification": {"inclusionProof": {
        "logIndex": 0, "treeSize": 1, "hashes": [], "rootHash": leaf
    }}}
    monkeypatch.setattr(main, "get_log_entry", lambda *a: entry)
    monkeypatch.setattr(main, "extract_public_key", lambda cert: b"key")
    monkeypatch.setattr(main, "verify_artifact_signature", lambda *a: True)
    assert main.inclusion(0, "artifact", True) is True


def test_inclusion_bad_body(monkeypatch):
    monkeypatch.setattr(main, "get_log_entry", lambda *a: {"body": "not base64"})
    with pytest.raises(ValueError):
        main.inclusion(0, "artifact")


def test_signatures(tmp_path):
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    path = tmp_path / "artifact"
    path.write_bytes(b"sample")
    signature = private_key.sign(b"sample", ec.ECDSA(hashes.SHA256()))
    assert verify_artifact_signature(signature, public_key, str(path))
    path.write_bytes(b"tampered")
    assert verify_artifact_signature(signature, public_key, str(path)) is False
