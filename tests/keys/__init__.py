import json
import os

from jwt.utils import base64url_decode

BASE_PATH = os.path.dirname(os.path.abspath(__file__))


def decode_value(val):
    decoded = base64url_decode(val)
    return int.from_bytes(decoded, byteorder="big")


def load_hmac_key():
    with open(os.path.join(BASE_PATH, "jwk_hmac.json")) as infile:
        keyobj = json.load(infile)

    return base64url_decode(keyobj["k"])


try:
    from cryptography.hazmat.primitives.asymmetric import ec

    from jwt.algorithms import RSAAlgorithm

    has_crypto = True
except ImportError:
    has_crypto = False

if has_crypto:

    def load_rsa_key():
        with open(os.path.join(BASE_PATH, "jwk_rsa_key.json")) as infile:
            return RSAAlgorithm.from_jwk(infile.read())

    def load_rsa_pub_key():
        with open(os.path.join(BASE_PATH, "jwk_rsa_pub.json")) as infile:
            return RSAAlgorithm.from_jwk(infile.read())

    def load_ec_key():
        with open(os.path.join(BASE_PATH, "jwk_ec_key.json")) as infile:
            keyobj = json.load(infile)

        return ec.EllipticCurvePrivateNumbers(
            private_value=decode_value(keyobj["d"]),
            public_numbers=load_ec_pub_key_p_521().public_numbers(),
        )

    def load_ec_pub_key_p_521():
        with open(os.path.join(BASE_PATH, "jwk_ec_pub_P-521.json")) as infile:
            keyobj = json.load(infile)

        return ec.EllipticCurvePublicNumbers(
            x=decode_value(keyobj["x"]),
            y=decode_value(keyobj["y"]),
            curve=ec.SECP521R1(),
        ).public_key()
