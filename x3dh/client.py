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

F = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF.to_bytes(32, 'big')
DATA = ".data"
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
    identity = X25519PublicKey.from_public_bytes(b64decode(prekey_bundle["identity"].encode('utf-8')))
    spk = X25519PublicKey.from_public_bytes(b64decode(prekey_bundle["spk"].encode('utf-8')))
    signature = b64decode(prekey_bundle["signature"].encode('utf-8'))

    if not verify(identity, spk, signature):
        print("SIGNED PREKEY VERIFICATION FAILED. ABORTING.")
        abort(403)

    self_id = bundle["identity"]

    opk_index = prekey_bundle["opk_index"]
    opk = X25519PublicKey.from_public_bytes(b64decode(prekey_bundle["opk"].encode('utf-8')))

    ephemeral = X25519PrivateKey.generate()
    dh1 = self_id.exchange(spk)
    dh2 = ephemeral.exchange(identity)
    dh3 = ephemeral.exchange(spk)
    dh4 = ephemeral.exchange(opk)

    dh = dh1 + dh2 + dh3 + dh4

    shared_key = HKDF(
        algorithm=hashes.SHA512(), length=32, salt=None, info=b"handshake"
    ).derive(F + dh)

    self_id = self_id.public_key().public_bytes(encoding=ENCODING, format=PUB_FORMAT)
    ephemeral = ephemeral.public_key().public_bytes(
        encoding=ENCODING, format=PUB_FORMAT
    )

    del dh1, dh2, dh3, dh4, dh

    ik_a = hashes.Hash(hashes.SHA512())
    ik_a.update(self_id)
    ik_a = ik_a.finalize()

    ik_b = hashes.Hash(hashes.SHA512())
    ik_b.update(identity.public_bytes(encoding=ENCODING, format=PUB_FORMAT))
    ik_b = ik_b.finalize()

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
            identity=b64encode(self_id).decode('utf-8'),
            ephemeral=b64encode(ephemeral).decode('utf-8'),
            index=opk_index,
            nonce=b64encode(nonce).decode('utf-8'),
            aead=b64encode(aead).decode('utf-8'),
        ),
    ).json()["success"]

    if success:
        print("Handshake successful! Storing shared key.")
        shared_keys[hashlib.sha1(person.encode("utf-8")).hexdigest()] = shared_key
    else:
        print("Handshake failed!")

    return dict(success=success)


@app.route("/receive_handshake", methods=["POST"])
def receive_handshake():
    data = request.json
    uid = data["sender_uid"]

    print(f"Received a handshake request from UID {uid}!")

    identity = X25519PublicKey.from_public_bytes(b64decode(data["identity"].encode('utf-8')))
    ephemeral = X25519PublicKey.from_public_bytes(b64decode(data["ephemeral"].encode('utf-8')))
    index = data["index"]
    opk = bundle["opks"].pop(index)
    nonce = b64decode(data["nonce"].encode('utf-8'))
    aead = b64decode(data["aead"].encode('utf-8'))

    dh1 = bundle["spk"].exchange(identity)
    dh2 = bundle["identity"].exchange(ephemeral)
    dh3 = bundle["spk"].exchange(ephemeral)
    dh4 = opk.exchange(ephemeral)

    dh = dh1 + dh2 + dh3 + dh4

    shared_key = HKDF(
        algorithm=hashes.SHA512(), length=32, salt=None, info=b"handshake"
    ).derive(F + dh)

    os.remove(f"{DATA}/{username}/opk{index}")
    del dh, dh1, dh2, dh3, dh4, opk

    ik_a = hashes.Hash(hashes.SHA512())
    ik_a.update(identity.public_bytes(encoding=ENCODING, format=PUB_FORMAT))
    ik_a = ik_a.finalize()

    ik_b = hashes.Hash(hashes.SHA512())
    ik_b.update(bundle["identity"].public_key().public_bytes(encoding=ENCODING, format=PUB_FORMAT))
    ik_b = ik_b.finalize()

    associated_data = ik_a + ik_b
    message = ChaCha20Poly1305(shared_key).decrypt(nonce, aead, associated_data)

    if message != b"shaking hands":
        del shared_key
        print("AEAD CHECK FAILED. ABORTING HANDSHAKE.")
        abort(403)

    print("Validation successful! Storing shared_key.")
    shared_keys[uid] = dict(shared_key=shared_key)
    return dict(success=True)


@app.route("/all_data")
def all_data():
    return dict(
        username=username,
        port=request.host.split(":")[-1],
        identity=dict(
            public=b64encode(bundle['identity'].public_key().public_bytes(encoding=ENCODING, format=PUB_FORMAT)).decode('utf-8'),
            private=b64encode(bundle['identity'].private_bytes(encoding=ENCODING, format=PRIV_FORMAT, encryption_algorithm=ENCRYPTION())).decode('utf-8'),
        ),
        spk=dict(
            public=b64encode(bundle['spk'].public_key().public_bytes(encoding=ENCODING, format=PUB_FORMAT)).decode('utf-8'),
            private=b64encode(bundle['spk'].private_bytes(encoding=ENCODING, format=PRIV_FORMAT, encryption_algorithm=ENCRYPTION())).decode('utf-8'),
        ),
        signature=b64encode(bundle['signature']).decode('utf-8'),
        opks={
            k: dict(
                public=b64encode(v.public_key().public_bytes(encoding=ENCODING, format=PUB_FORMAT)).decode('utf-8'),
                private=b64encode(v.private_bytes(encoding=ENCODING, format=PRIV_FORMAT, encryption_algorithm=ENCRYPTION())).decode('utf-8'),
            )
            for k, v in bundle['opks'].items()
        }
    )


def sign(identity: X25519PrivateKey, spk: X25519PrivateKey):
    """Uses the `identity` private key to sign a hashed
    version of the `spk` public key.

    :param identity: the user's identity
    :type identity: X25519PrivateKey
    :param spk: the user's signed prekey
    :type spk: X25519PrivateKey

    :return: the byte sequence representing an EdDSA signature
    on the hashed `spk` public key
    :rtype: bytes
    """
    digest = hashes.Hash(hashes.SHA512())
    digest.update(spk.public_key().public_bytes(encoding=ENCODING, format=PUB_FORMAT))
    data = digest.finalize()

    id_bytes = identity.private_bytes(
        encoding=ENCODING, format=PRIV_FORMAT, encryption_algorithm=ENCRYPTION()
    )

    xed = XEd25519(id_bytes, None)
    return xed.sign(data = data)


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
    digest = hashes.Hash(hashes.SHA512())
    digest.update(spk.public_bytes(encoding=ENCODING, format=PUB_FORMAT))
    data = digest.finalize()

    id_bytes = identity.public_bytes(encoding=ENCODING, format=PUB_FORMAT)
    xed = XEd25519(None, id_bytes)

    try:
        xed.verify(data, signature)
        return True
    except:
        return False


def initialize_bundle():
    dir = f"{DATA}/{username}"
    if not os.path.exists(dir):
        os.mkdir(dir)

    identity = X25519PrivateKey.generate()
    with open(f"{dir}/ik", "wb") as f:
        f.write(
            identity.private_bytes(
                encoding=ENCODING, format=PRIV_FORMAT, encryption_algorithm=ENCRYPTION()
            )
        )

    spk = X25519PrivateKey.generate()
    with open(f"{dir}/spk", "wb") as f:
        f.write(
            spk.private_bytes(
                encoding=ENCODING, format=PRIV_FORMAT, encryption_algorithm=ENCRYPTION()
            )
        )

    signature = sign(identity, spk)

    opks = {}
    for i in range(5):
        opk = X25519PrivateKey.generate()
        with open(f"{dir}/opk{i}", "wb") as f:
            f.write(
                opk.private_bytes(
                    encoding=ENCODING,
                    format=PRIV_FORMAT,
                    encryption_algorithm=ENCRYPTION(),
                )
            )
        opks[str(i)] = opk

    bundle["identity"] = identity
    bundle["spk"] = spk
    bundle["signature"] = signature
    bundle["opks"] = opks

    identity = (
        identity
        .public_key()
        .public_bytes(encoding=ENCODING, format=PUB_FORMAT)
    )
    spk = spk.public_key().public_bytes(encoding=ENCODING, format=PUB_FORMAT)
    signature = signature
    opks = {
        k: b64encode(v.public_key().public_bytes(encoding=ENCODING, format=PUB_FORMAT)).decode('utf-8')
        for k, v in opks.items()
    }
    port = request.host.split(":")[-1]

    requests.post(
        f"{SERVER}/register_user",
        json=dict(
            username=username,
            prekey_bundle=dict(
                identity=b64encode(identity).decode('utf-8'),
                spk=b64encode(spk).decode('utf-8'),
                signature=b64encode(signature).decode('utf-8'),
                opks=opks,  
            ),
            port=port,
        ),
    )


if __name__ == "__main__":
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("",0))
    s.listen(1)
    port = s.getsockname()[1]
    s.close()

    username = sys.argv[-1]
    initialize_bundle()
    app.run(port=port)
