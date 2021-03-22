from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from base64 import b64decode
from flask import Flask, request

from models import User
from utils import strb


class App:
    def __init__(self):
        self.app = Flask(__name__)
        self.user = None


app = App()


@app.app.route("/initialize", methods=["POST"])
def init():
    data = request.json
    sk = b64decode(strb(data.get("sk")))
    ad = b64decode(strb(data.get("ad")))
    priv = (
        X25519PrivateKey.from_private_bytes(b64decode(strb(data.get("priv"))))
        if "priv" in data
        else None
    )
    pub = (
        X25519PublicKey.from_public_bytes(b64decode(strb(data.get("pub"))))
        if "pub" in data
        else None
    )

    app.user = User(sk, ad, priv, pub)
    return dict(success=True)


@app.app.route("/send_msg", methods=["POST"])
def send():
    data = request.json
    return app.user.send(data.get("body"))


@app.app.route("/receive_msg")
def receive():
    return app.user.receive(request.json)


if __name__ == "__main__":
    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", 0))
    s.listen(1)
    port = s.getsockname()[1]
    s.close()

    app.app.run(port=port)
