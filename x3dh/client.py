import hashlib
import os
import sys
import requests
from base64 import b64encode, b64decode

from flask import Flask, abort, request

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from xeddsa import XEd25519

ENCODING = serialization.Encoding.Raw
PRIV_FORMAT = serialization.PrivateFormat.Raw
PUB_FORMAT = serialization.PublicFormat.Raw
ENCRYPTION = serialization.NoEncryption

F = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF .to_bytes(
    32, "big"
)
SERVER = "http://localhost:5000"

app = Flask(__name__)
username = "unset"
port = "5001"

bundle = {}
shared_keys = {}


@app.route("/")
def index():
    return f"Hello, {username}!"


@app.route("/perform_handshake", methods=["POST"])
def perform_handshake():
    data = request.json
    person = data["send_to"]

    print(f"Performing handshake with {person}.")

    prekey_bundle = requests.get(f"{SERVER}/get_prekey_bundle/{person}").json()
    identity = X25519PublicKey.from_public_bytes(strb(prekey_bundle["identity"]))
    spk = X25519PublicKey.from_public_bytes(strb(prekey_bundle["spk"]))
    signature = strb(prekey_bundle["signature"])

    if not verify(identity, spk, signature):
        print("SIGNED PREKEY VERIFICATION FAILED. ABORTING.")
        abort(403)

    self_id = bundle["identity"]

    opk_index = prekey_bundle["opk_index"]
    opk = X25519PublicKey.from_public_bytes(strb(prekey_bundle["opk"]))

    ephemeral = X25519PrivateKey.generate()
    dh1 = self_id.exchange(spk)
    dh2 = ephemeral.exchange(identity)
    dh3 = ephemeral.exchange(spk)
    dh4 = ephemeral.exchange(opk)

    dh = dh1 + dh2 + dh3 + dh4

    shared_key = HKDF(
        algorithm=hashes.SHA512(), length=32, salt=None, info=b"handshake"
    ).derive(F + dh)

    self_id = public_bytes(self_id.public_key())
    ephemeral = public_bytes(ephemeral.public_key())

    del dh1, dh2, dh3, dh4, dh

    ik_a = hash(self_id)
    ik_b = hash(public_bytes(identity))

    associated_data = ik_a + ik_b
    nonce = os.urandom(12)
    message = b"shaking hands"

    aead = ChaCha20Poly1305(shared_key).encrypt(nonce, message, associated_data)

    print("Sending handshake data.")

    success = requests.post(
        f"{SERVER}/perform_handshake",
        json=dict(
            sender_uid=hashlib.sha1(username.encode("utf-8")).hexdigest(),
            send_to=person,
            identity=bstr(self_id),
            ephemeral=bstr(ephemeral),
            index=opk_index,
            nonce=bstr(nonce),
            aead=bstr(aead),
        ),
    ).json()["success"]

    if success:
        print("Handshake successful! Storing shared key.")
        shared_keys[hashlib.sha1(person.encode("utf-8")).hexdigest()] = dict(shared_key=shared_key, associated_data=associated_data)
    else:
        print("Handshake failed!")

    return dict(success=success)


@app.route("/receive_handshake", methods=["POST"])
def receive_handshake():
    data = request.json
    uid = data["sender_uid"]

    print(f"Received a handshake request from UID {uid}!")

    identity = X25519PublicKey.from_public_bytes(strb(data["identity"]))
    ephemeral = X25519PublicKey.from_public_bytes(strb(data["ephemeral"]))
    index = data["index"]
    opk = bundle["opks"].pop(index)
    nonce = strb(data["nonce"])
    aead = strb(data["aead"])

    dh1 = bundle["spk"].exchange(identity)
    dh2 = bundle["identity"].exchange(ephemeral)
    dh3 = bundle["spk"].exchange(ephemeral)
    dh4 = opk.exchange(ephemeral)

    dh = dh1 + dh2 + dh3 + dh4

    shared_key = HKDF(
        algorithm=hashes.SHA512(), length=32, salt=None, info=b"handshake"
    ).derive(F + dh)

    del dh, dh1, dh2, dh3, dh4, opk

    ik_a = hash(public_bytes(identity))
    ik_b = hash(public_bytes(bundle["identity"].public_key()))

    associated_data = ik_a + ik_b
    message = ChaCha20Poly1305(shared_key).decrypt(nonce, aead, associated_data)

    if message != b"shaking hands":
        del shared_key
        print("AEAD CHECK FAILED. ABORTING HANDSHAKE.")
        abort(403)

    print("Validation successful! Storing shared_key.")
    shared_keys[uid] = dict(shared_key=shared_key, associated_data=associated_data)
    return dict(success=True)


@app.route("/all_data")
def all_data():
    return dict(
        username=username,
        port=request.host.split(":")[-1],
        identity=dict(
            public=bstr(public_bytes(bundle["identity"].public_key())),
            private=bstr(private_bytes(bundle["identity"])),
        ),
        spk=dict(
            public=bstr(public_bytes(bundle["spk"].public_key())),
            private=bstr(private_bytes(bundle["spk"])),
        ),
        signature=bstr(bundle["signature"]),
        opks={
            k: dict(
                public=bstr(public_bytes(v.public_key())),
                private=bstr(private_bytes(v)),
            )
            for k, v in bundle["opks"].items()
        },
        connections={
            k: dict(
                sk = bstr(v.get("shared_key")),
                ad = bstr(v.get("associated_data"))
            )
            for k, v in shared_keys.items()
        }
    )


def sign(identity: X25519PrivateKey, spk: X25519PublicKey):
    """Uses the `identity` private key to sign a hashed
    version of the `spk` public key.

    :param identity: the user's identity
    :type identity: X25519PrivateKey
    :param spk: the user's signed prekey
    :type spk: X25519PublicKey

    :return: the byte sequence representing an EdDSA signature
    on the hashed `spk` public key
    :rtype: bytes
    """
    data = hash(public_bytes(spk))
    id_bytes = private_bytes(identity)
    xed = XEd25519(id_bytes, None)
    return xed.sign(data=data)


def verify(identity: X25519PublicKey, spk: X25519PublicKey, signature: bytes):
    """Verifies that the received `data` is an EdDSA signature
    on the hashed `spk` public key using the `identity` key.

    :param identity: the user's identity
    :type identity: X25519PublicKey
    :param spk: the user's signed prekey
    :type spk: X25519PublicKey
    :param data: the received byte sequence
    :type data: bytes

    :return: whether the verificaiton was successful or not
    :rtype: bool
    """
    data = hash(public_bytes(spk))
    id_bytes = public_bytes(identity)
    xed = XEd25519(None, id_bytes)

    try:
        xed.verify(data, signature)
        return True
    except:
        return False


def initialize_bundle():
    identity = X25519PrivateKey.generate()
    spk = X25519PrivateKey.generate()
    signature = sign(identity, spk.public_key())
    opks = {str(i): X25519PrivateKey.generate() for i in range(5)}

    bundle["identity"] = identity
    bundle["spk"] = spk
    bundle["signature"] = signature
    bundle["opks"] = opks

    identity = bstr(public_bytes(identity.public_key()))
    spk = bstr(public_bytes(spk.public_key()))
    signature = bstr(signature)
    opks = {k: bstr(public_bytes(v.public_key())) for k, v in opks.items()}

    requests.post(
        f"{SERVER}/register_user",
        json=dict(
            username=username,
            prekey_bundle=dict(
                identity=identity,
                spk=spk,
                signature=signature,
                opks=opks,
            ),
            port=port,
        ),
    )


def public_bytes(key: X25519PublicKey):
    return key.public_bytes(encoding=ENCODING, format=PUB_FORMAT)


def private_bytes(key: X25519PrivateKey):
    return key.private_bytes(
        encoding=ENCODING, format=PRIV_FORMAT, encryption_algorithm=ENCRYPTION()
    )


def bstr(data: bytes):
    return b64encode(data).decode("utf-8")


def strb(data: str):
    return b64decode(data.encode("utf-8"))


def hash(data: bytes):
    hasher = hashes.Hash(hashes.SHA512())
    hasher.update(data)
    return hasher.finalize()


if __name__ == "__main__":
    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", 0))
    s.listen(1)
    port = s.getsockname()[1]
    s.close()

    username = sys.argv[-1]
    initialize_bundle()
    app.run(port=port)
