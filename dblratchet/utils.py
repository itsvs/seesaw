import hmac, hashlib

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

ENCODING = serialization.Encoding.Raw
PRIV_FORMAT = serialization.PrivateFormat.Raw
PUB_FORMAT = serialization.PublicFormat.Raw
ENCRYPTION = serialization.NoEncryption


def public_bytes(key: X25519PublicKey) -> bytes:
    return key.public_bytes(encoding=ENCODING, format=PUB_FORMAT)


def private_bytes(key: X25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=ENCODING, format=PRIV_FORMAT, encryption_algorithm=ENCRYPTION()
    )


def bstr(data: bytes) -> str:
    return data.decode("utf-8")


def strb(data: str) -> bytes:
    return data.encode("utf-8")


def kdf(salt: bytes, input: bytes) -> tuple[bytes, bytes]:
    complete = HKDF(
        algorithm=hashes.SHA512(), length=64, salt=salt, info=b"kdf_info"
    ).derive(input)
    return complete[:32], complete[32:]


def mac(key: bytes) -> tuple[bytes, bytes]:
    out1 = hmac.new(key, b"1", hashlib.sha512)
    out2 = hmac.new(key, b"2", hashlib.sha512)

    return strb(out1.hexdigest()), strb(out2.hexdigest())
