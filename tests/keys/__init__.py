import json
import os

from jwt.algorithms import has_crypto
from jwt.utils import base64url_decode

try:
    from cryptography.hazmat.primitives.asymmetric import ec
except ModuleNotFoundError:
    pass

if has_crypto:
    from jwt.algorithms import RSAAlgorithm

BASE_PATH = os.path.dirname(os.path.abspath(__file__))


def decode_value(val):
    decoded = base64url_decode(val)
    return int.from_bytes(decoded, byteorder="big")


def load_hmac_key():
    with open(os.path.join(BASE_PATH, "jwk_hmac.json")) as infile:
        keyobj = json.load(infile)

    return base64url_decode(keyobj["k"])


def load_rsa_pub_key():
    with open(os.path.join(BASE_PATH, "jwk_rsa_pub.json")) as infile:
        return RSAAlgorithm.from_jwk(infile.read())


def load_ec_pub_key_p_521():
    with open(os.path.join(BASE_PATH, "jwk_ec_pub_P-521.json")) as infile:
        keyobj = json.load(infile)

    return ec.EllipticCurvePublicNumbers(
        x=decode_value(keyobj["x"]),
        y=decode_value(keyobj["y"]),
        curve=ec.SECP521R1(),
    ).public_key()
