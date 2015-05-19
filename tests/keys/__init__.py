import json
import os

from jwt.utils import base64url_decode

from tests.utils import ensure_bytes, int_from_bytes

BASE_PATH = os.path.dirname(os.path.abspath(__file__))


def decode_value(val):
    decoded = base64url_decode(ensure_bytes(val))
    return int_from_bytes(decoded, 'big')


def load_hmac_key():
    with open(os.path.join(BASE_PATH, 'jwk_hmac.json'), 'r') as infile:
        keyobj = json.load(infile)

    return base64url_decode(ensure_bytes(keyobj['k']))

try:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.backends import default_backend

    has_crypto = True
except ImportError:
    has_crypto = False

if has_crypto:
    def load_rsa_key():
        with open(os.path.join(BASE_PATH, 'jwk_rsa_key.json'), 'r') as infile:
            keyobj = json.load(infile)

        return rsa.RSAPrivateNumbers(
            p=decode_value(keyobj['p']),
            q=decode_value(keyobj['q']),
            d=decode_value(keyobj['d']),
            dmp1=decode_value(keyobj['dp']),
            dmq1=decode_value(keyobj['dq']),
            iqmp=decode_value(keyobj['qi']),
            public_numbers=load_rsa_pub_key().public_numbers()
        ).private_key(default_backend())

    def load_rsa_pub_key():
        with open(os.path.join(BASE_PATH, 'jwk_rsa_pub.json'), 'r') as infile:
            keyobj = json.load(infile)

        return rsa.RSAPublicNumbers(
            n=decode_value(keyobj['n']),
            e=decode_value(keyobj['e'])
        ).public_key(default_backend())

    def load_ec_key():
        with open(os.path.join(BASE_PATH, 'jwk_ec_key.json'), 'r') as infile:
            keyobj = json.load(infile)

        return ec.EllipticCurvePrivateNumbers(
            private_value=decode_value(keyobj['d']),
            public_numbers=load_ec_pub_key().public_numbers()
        )

    def load_ec_pub_key():
        with open(os.path.join(BASE_PATH, 'jwk_ec_pub.json'), 'r') as infile:
            keyobj = json.load(infile)

        return ec.EllipticCurvePublicNumbers(
            x=decode_value(keyobj['x']),
            y=decode_value(keyobj['y']),
            curve=ec.SECP521R1()
        ).public_key(default_backend())
