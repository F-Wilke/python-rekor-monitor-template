"""X.509 key extraction and ECDSA signature verification."""

from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key


def extract_public_key(cert: bytes) -> bytes:
    """Extract a PEM-encoded public key from a PEM certificate."""
    certificate = x509.load_pem_x509_certificate(cert)
    return certificate.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def verify_artifact_signature(
    signature: bytes, public_key: bytes, artifact_filename: str
) -> bool:
    """Verify an ECDSA/SHA-256 signature and return whether it is valid.

    A malformed or unsupported public key is an error rather than a failed
    signature, which prevents unsupported algorithms being silently accepted.
    """
    key = load_pem_public_key(public_key)
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError("Expected an elliptic-curve public key")

    data = Path(artifact_filename).read_bytes()
    try:
        key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True
