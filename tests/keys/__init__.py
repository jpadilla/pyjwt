import json
import os
from typing import Union

from jwt.algorithms import has_crypto, AllowedRSAKeys
from jwt.utils import base64url_decode

BASE_PATH = os.path.dirname(os.path.abspath(__file__))


def decode_value(val: Union[str, bytes]) -> int:
    decoded = base64url_decode(val)
    return int.from_bytes(decoded, byteorder="big")


def load_hmac_key() -> bytes:
    with open(os.path.join(BASE_PATH, "jwk_hmac.json")) as infile:
        keyobj = json.load(infile)

    return base64url_decode(keyobj["k"])


if has_crypto:
    from cryptography.hazmat.primitives.asymmetric import ec
    from jwt.algorithms import RSAAlgorithm

    def load_rsa_pub_key() -> AllowedRSAKeys:
        with open(os.path.join(BASE_PATH, "jwk_rsa_pub.json")) as infile:
            return RSAAlgorithm.from_jwk(infile.read())

    def load_ec_pub_key_p_521() -> ec.EllipticCurvePublicKey:
        with open(os.path.join(BASE_PATH, "jwk_ec_pub_P-521.json")) as infile:
            keyobj = json.load(infile)

        return ec.EllipticCurvePublicNumbers(
            x=decode_value(keyobj["x"]),
            y=decode_value(keyobj["y"]),
            curve=ec.SECP521R1(),
        ).public_key()
else:
    import sys

    if sys.version_info >= (3, 11):
        from typing import Never
    else:
        from typing_extensions import Never

    def load_rsa_pub_key() -> AllowedRSAKeys:
        raise RuntimeError("cryptography is not available")

    def load_ec_pub_key_p_521() -> Never:  # type: ignore[misc]
        raise RuntimeError("cryptography is not available")
