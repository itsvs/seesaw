from nacl.bindings import randombytes, crypto_scalarmult_base, crypto_hash_sha512
from nacl.signing import VerifyKey

from .ref10 import (
    FieldElementBytes,
    fe_frombytes,
    fe_tobytes,
    fe_1,
    fe_add,
    fe_sub,
    fe_mul,
    fe_invert,

    ge_p3_tobytes,
    ScalarBytes,
    ge_scalarmult_base,

    ScalarReduceBytes,
    sc_reduce,
    sc_muladd,

    sc_neg,
    sc_cmov
)

class XEd25519:
    """
    The base class for all XEdDSA implementations.
    Do not use this class directly, use subclasses for specific key types instead.

    The :mod:`xeddsa.implementations` module ships such subclasses.
    """
    def __init__(self, private_key = None, public_key = None):
        """
        Create an XEdDSA object from Montgomery key material, to encrypt AND sign data using just one
        Montgomery key pair.

        Args:
            mont_priv: The Montgomery private key.
            mont_pub: The Montgomery public key.

        If both ``mont_priv`` and ``mont_pub`` are :obj:`None`, a new key pair is generated.
        """
        if private_key and not public_key:
            public_key = crypto_scalarmult_base(private_key)

        self.private_key = private_key
        self.public_key = public_key

    def get_ed25519(self):
        """
        Args:
            mont_priv: The Montgomery private key.

        Returns:
            The Twisted Edwards private and public key derived from the Montgomery private key.
        """
        ed_priv = ScalarBytes.wrap(self.private_key)

        # get the twisted edwards public key, including the sign bit
        ed_pub = bytes(ge_p3_tobytes(ge_scalarmult_base(ed_priv)))

        # save the sign bit for later
        sign_bit = bool((ed_pub[31] >> 7) & 1)

        # force the sign bit to zero
        ed_pub_mut = bytearray(ed_pub)
        ed_pub_mut[31] &= 0x7F
        ed_pub = bytes(ed_pub_mut)

        # prepare the negated private key
        ed_priv_neg = sc_neg(ed_priv)

        # get the correct private key based on the sign stored above
        ed_priv = sc_cmov(ed_priv, ed_priv_neg, sign_bit)
        return bytes(ed_priv), bytes(ed_pub)

    def get_ed_public(self):
        """
        Args:
            mont_pub: The Montgomery public key.

        Returns:
            The Twisted Edwards public key derived from the Montgomery public key.
        """
        # Read the public key as a field element
        public_fe = fe_frombytes(FieldElementBytes.wrap(self.public_key))

        # Convert the Montgomery public key to a twisted Edwards public key
        one = fe_1()

        # Calculate the parameters (u - 1) and (u + 1)
        public_minus_one = fe_sub(public_fe, one)
        public_plus_one  = fe_add(public_fe, one)

        # Prepare inv(u + 1)
        public_plus_one = fe_invert(public_plus_one)

        # Calculate y = (u - 1) * inv(u + 1) (mod p)
        ed_pub = fe_mul(public_minus_one, public_plus_one)
        return bytes(fe_tobytes(ed_pub))

    def sign(self, data: bytes, nonce = None):
        """
        Sign data using the Montgomery private key stored in this XEdDSA instance.

        Args:
            data: The data to sign.
            nonce: The nonce to use while signing. If omitted or set to :obj:`None`, a nonce is generated.

        Returns:
            The signature of the data, not including the data itself.

        Raises:
            MissingKeyException: If the Montgomery private key is not available.
        """

        if not self.private_key:
            raise Exception("Cannot sign without a private key.")

        if nonce is None:
            nonce = randombytes(64)

        ed_priv, ed_pub = self.get_ed25519()
        # Aliases for consistency with the specification
        M = data
        Z = nonce

        # A, a = calculate_key_pair(k)
        A = ed_pub
        a = ed_priv

        # r = hash_1(a || M || Z) (mod q)

        # If the hash has an index as above, that means, we are supposed to calculate:
        #     hash(2 ^ b - 1 - i || X)
        #
        # If b = 256 (which is the case for 25519 XEdDSA), then 2 ^ b - 1 = [ 0xFF ] * 32
        # Now, subtracting i from the result can be done by subtracting i from the first
        # byte (assuming i <= 0xFF).
        padding_mut = bytearray(b"\xFF" * 32)
        padding_mut[0] -= 1
        padding = bytes(padding_mut)
        r = crypto_hash_sha512(padding + ed_priv + data + nonce)
        r_sc = sc_reduce(ScalarReduceBytes.wrap(r))

        # R = rB
        R = bytes(ge_p3_tobytes(ge_scalarmult_base(r_sc)))

        # h = hash(R || A || M) (mod q)
        h = crypto_hash_sha512(R + ed_pub + data)
        h_sc = sc_reduce(ScalarReduceBytes.wrap(h))

        # s = r + ha (mod q)
        s = bytes(sc_muladd(h_sc, ScalarBytes.wrap(ed_priv), r_sc))

        return R + s

    def verify(self, data: bytes, signature) -> bool:
        """
        Verify a signature using the Montgomery public key stored in this XEdDSA instance.

        Args:
            data: The data.
            signature: The signature.

        Returns:
            Whether the signature is valid.
        """
        ed_pub = self.get_ed_public()

        # Get the sign bit from the signature.
        # This part of the signature is usually unused, but the XEdDSA implementation of libsignal uses the
        # bit to store information about the sign of the public key. Before verification, this sign bit has to
        # be removed from the signature and restored on the public key, which should have a sign bit of 0 at
        # this point.
        sign_bit = (signature[63] >> 7) & 1

        # Set the sign bit to zero in the signature.
        signature_mut = bytearray(signature)
        signature_mut[63] &= 0x7F
        signature = bytes(signature_mut)

        # Restore the sign bit on the verification key, which should have 0 as its current sign bit.
        ed_pub_mut = bytearray(ed_pub)
        ed_pub_mut[31] |= sign_bit << 7
        ed_pub = bytes(ed_pub_mut)

        # From this point on, the signature should be a valid EdDSA signature and thus be verifyable by
        # libsodium or other libraries that implement Ed25519 signatures.
        return VerifyKey(ed_pub).verify(data, signature)
