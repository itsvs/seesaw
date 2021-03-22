import hmac, hashlib

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from base64 import b64encode, b64decode
from typing import TypedDict

from utils import public_bytes, bstr, strb, kdf, mac

MAX_SKIP = 250


def encrypt(key: bytes, plain: str, ad: bytes) -> str:
    zeroes = 0x00 .to_bytes(80, "big")
    hkdf = HKDF(
        algorithm=hashes.SHA512(), length=80, salt=zeroes, info=b"msg_info"
    ).derive(key)

    padder = padding.PKCS7(256).padder()
    padded = padder.update(strb(plain)) + padder.finalize()

    enc, auth, iv = hkdf[:32], hkdf[32:64], hkdf[64:]
    aes = Cipher(algorithms.AES(enc), modes.CBC(iv)).encryptor()
    aes = aes.update(padded) + aes.finalize()

    mac = hmac.new(auth, ad + aes, hashlib.sha512).hexdigest()
    return bstr(b64encode(aes)) + mac


def decrypt(key: bytes, cipher: str, ad: bytes) -> str:
    zeroes = 0x00 .to_bytes(80, "big")
    hkdf = HKDF(
        algorithm=hashes.SHA512(), length=80, salt=zeroes, info=b"msg_info"
    ).derive(key)

    enc, auth, iv = hkdf[:32], hkdf[32:64], hkdf[64:]
    decryptor = Cipher(algorithms.AES(enc), modes.CBC(iv)).decryptor()

    aes, mac = b64decode(strb(cipher[:-128])), cipher[-128:]
    test = hmac.new(auth, ad + aes, hashlib.sha512).hexdigest()

    assert mac == test, "Unexpected HMAC in received message"

    padded = decryptor.update(aes) + decryptor.finalize()

    unpadder = padding.PKCS7(256).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()

    return bstr(plaintext)


def header(key: X25519PrivateKey, prev_n: int, n_send: int):
    return dict(
        dh=bstr(b64encode(public_bytes(key.public_key()))),
        pn=prev_n,
        n=n_send,
    )


def skip(state, until: int):
    if state["nr"] + MAX_SKIP < until:
        raise Exception("Too many skipped messages.")
    if state["ckr"]:
        while state["nr"] < until:
            state["ckr"], mk = mac(state["ckr"])
            state["skipped"][public_bytes(state["dhr"]), state["nr"]] = mk
            state["nr"] += 1


def update_dh(state, head):
    state["pn"] = state["ns"]
    state["ns"], state["nr"] = 0, 0
    state["dhr"] = head.get("dh")
    state["rk"], state["ckr"] = kdf(state["rk"], state["dhs"].exchange(state["dhr"]))
    state["dhs"] = X25519PrivateKey.generate()
    state["rk"], state["cks"] = kdf(state["rk"], state["dhs"].exchange(state["dhr"]))


class State(TypedDict, total=False):
    dhs: X25519PrivateKey
    dhr: X25519PublicKey
    cks: bytes
    ckr: bytes
    rk: bytes
    ns: int
    nr: int
    pn: int
    skipped: dict
    ad: bytes


class User:
    def __init__(
        self, sk: bytes, ad: bytes, priv: X25519PrivateKey, pub: X25519PublicKey
    ):
        self.state: State = {}
        if priv and not pub:
            self._do_recipient_init(sk, priv)
        else:
            self._do_sender_init(sk, pub)

        self.state["ns"], self.state["nr"], self.state["pn"] = 0, 0, 0
        self.state["skipped"] = {}
        self.state["ad"] = ad

    def _do_recipient_init(self, sk: bytes, priv: X25519PrivateKey):
        self.state["dhs"] = priv
        self.state["dhr"], self.state["cks"], self.state["ckr"] = None, None, None
        self.state["rk"] = sk

    def _do_sender_init(self, sk: bytes, pub: X25519PublicKey):
        self.state["dhs"] = X25519PrivateKey.generate()
        self.state["dhr"] = pub
        self.state["rk"], self.state["cks"] = kdf(
            sk, self.state["dhs"].exchange(self.state["dhr"])
        )
        self.state["ckr"] = None

    def send(self, text: str):
        state: State = self.state.copy()
        state["cks"], mk = mac(state["cks"])
        head = header(state["dhs"], state["pn"], state["ns"])
        cipher = encrypt(mk, text, state["ad"])

        self.state = state
        self.state["ns"] += 1

        return dict(body=cipher, **head)

    def receive(self, message):
        head, cipher = message, message.pop("body")
        head["dh"] = X25519PublicKey.from_public_bytes(b64decode(strb(head.get("dh"))))

        if (public_bytes(head.get("dh")), head.get("n")) in self.state["skipped"]:
            mk = self.state["skipped"].pop(
                (public_bytes(head.get("dh")), head.get("n"))
            )
            return decrypt(mk, cipher, self.state["ad"])

        state: State = self.state.copy()
        state["skipped"] = state["skipped"].copy()
        if not state["dhr"] or (
            public_bytes(head.get("dh")) != public_bytes(state["dhr"])
        ):
            skip(state, head.get("pn"))
            update_dh(state, head)
        skip(state, head.get("n"))

        state["ckr"], mk = mac(state["ckr"])
        plaintext = decrypt(mk, cipher, state["ad"])

        self.state = state
        self.state["nr"] += 1
        return plaintext
