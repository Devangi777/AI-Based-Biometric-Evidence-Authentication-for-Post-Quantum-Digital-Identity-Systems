"""Classical (pre-quantum) baseline: RSA-3072 key exchange (RSA-OAEP) and
ECDSA-P256 signatures, via the `cryptography` library.

Exists solely to produce the PQC-vs-classical overhead comparison required
by spec Section 8 (evaluation/benchmark.py imports this alongside
crypto/kem.py and crypto/signature.py). Not used in the actual verification
pipeline - ML-KEM/ML-DSA are.
"""
from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

RSA_KEY_SIZE = 3072
_RSA_PUBLIC_EXPONENT = 65537


def rsa_generate_keypair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    private_key = rsa.generate_private_key(public_exponent=_RSA_PUBLIC_EXPONENT, key_size=RSA_KEY_SIZE)
    return private_key, private_key.public_key()


def _oaep_padding() -> padding.OAEP:
    return padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def rsa_encrypt(public_key: rsa.RSAPublicKey, plaintext: bytes) -> bytes:
    """Encrypt a short shared-secret/session-key payload (RSA-OAEP), the
    classical analogue of ML-KEM encapsulation."""
    return public_key.encrypt(plaintext, _oaep_padding())


def rsa_decrypt(private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    return private_key.decrypt(ciphertext, _oaep_padding())


def ecdsa_generate_keypair() -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


def ecdsa_sign(private_key: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    return private_key.sign(message, ec.ECDSA(hashes.SHA256()))


def ecdsa_verify(public_key: ec.EllipticCurvePublicKey, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def public_key_size_bytes(public_key) -> int:
    """DER-encoded SubjectPublicKeyInfo size, for payload-size comparisons."""
    return len(
        public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
