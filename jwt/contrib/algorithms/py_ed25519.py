"""
Implementation of Ed25519 using ``cryptography`` (as of Version 2.6 released in February 2019)
"""

import cryptography.exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
    load_ssh_public_key,
)

from jwt.algorithms import Algorithm
from jwt.compat import string_types, text_type


class Ed25519Algorithm(Algorithm):
    """
    Performs signing and verification operations using Ed25519

    This class requires ``cryptography>=2.6`` to be installed.
    """

    def __init__(self, **kwargs):
        pass

    def prepare_key(self, key):

        if isinstance(key, (Ed25519PrivateKey, Ed25519PublicKey)):
            return key

        if isinstance(key, string_types):
            if isinstance(key, text_type):
                key = key.encode("utf-8")
            str_key = key.decode("utf-8")

            if "-----BEGIN PUBLIC" in str_key:
                return load_pem_public_key(key, backend=default_backend())
            if "-----BEGIN PRIVATE" in str_key:
                return load_pem_private_key(
                    key, password=None, backend=default_backend()
                )
            if str_key[0:4] == "ssh-":
                return load_ssh_public_key(key, backend=default_backend())

        raise TypeError("Expecting a PEM-formatted or OpenSSH key.")

    def sign(self, msg, key):
        """
        Sign a message ``msg`` using the Ed25519 private key ``key``
        :param str|bytes msg: Message to sign
        :param Ed25519PrivateKey key: A :class:`.Ed25519PrivateKey` instance
        :return bytes signature: The signature, as bytes
        """
        msg = bytes(msg, "utf-8") if type(msg) is not bytes else msg
        return key.sign(msg)

    def verify(self, msg, key, sig):
        """
        Verify a given ``msg`` against a signature ``sig`` using the Ed25519 key ``key``

        :param str|bytes sig: Ed25519 signature to check ``msg`` against
        :param str|bytes msg: Message to sign
        :param Ed25519PrivateKey|Ed25519PublicKey key: A private or public Ed25519 key instance
        :return bool verified: True if signature is valid, False if not.
        """
        try:
            msg = bytes(msg, "utf-8") if type(msg) is not bytes else msg
            sig = bytes(sig, "utf-8") if type(sig) is not bytes else sig

            if isinstance(key, Ed25519PrivateKey):
                key = key.public_key()
            key.verify(sig, msg)
            return True  # If no exception was raised, the signature is valid.
        except cryptography.exceptions.InvalidSignature:
            return False
