from __future__ import annotations

from typing import Any, Literal, cast, get_args, overload

from ..exceptions import InvalidKeyError
from ..types import JWKDict
from ..utils import base64url_decode, base64url_encode, force_bytes
from ._helpers import finalize_jwk, parse_jwk_input
from ._types import AllowedOKPKeys
from .base import Algorithm

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed448 import (
    Ed448PrivateKey,
    Ed448PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
    load_ssh_public_key,
)

_OKP_CRV_TO_CLASS = {
    "Ed25519": (Ed25519PrivateKey, Ed25519PublicKey),
    "Ed448": (Ed448PrivateKey, Ed448PublicKey),
}


class OKPAlgorithm(Algorithm):
    """
    Performs signing and verification operations using EdDSA

    This class requires ``cryptography>=2.6`` to be installed.
    """

    _crypto_key_types = cast(tuple[type[AllowedOKPKeys], ...], get_args(AllowedOKPKeys))

    def __init__(self, **kwargs: Any) -> None:
        pass

    def prepare_key(self, key: AllowedOKPKeys | str | bytes) -> AllowedOKPKeys:
        if not isinstance(key, (str, bytes)):
            self.check_crypto_key_type(key)
            return cast(AllowedOKPKeys, key)

        key_str = key.decode("utf-8") if isinstance(key, bytes) else key
        key_bytes = key.encode("utf-8") if isinstance(key, str) else key

        if "-----BEGIN PUBLIC" in key_str:
            loaded_key = load_pem_public_key(key_bytes)
        elif "-----BEGIN PRIVATE" in key_str:
            loaded_key = load_pem_private_key(key_bytes, password=None)
        elif key_str[0:4] == "ssh-":
            loaded_key = load_ssh_public_key(key_bytes)
        else:
            raise InvalidKeyError("Not a public or private key")

        # Explicit check the key to prevent confusing errors from cryptography
        self.check_crypto_key_type(loaded_key)
        return cast(AllowedOKPKeys, loaded_key)

    def sign(self, msg: str | bytes, key: Ed25519PrivateKey | Ed448PrivateKey) -> bytes:
        msg_bytes = msg.encode("utf-8") if isinstance(msg, str) else msg
        return key.sign(msg_bytes)

    def verify(self, msg: str | bytes, key: AllowedOKPKeys, sig: str | bytes) -> bool:
        try:
            msg_bytes = msg.encode("utf-8") if isinstance(msg, str) else msg
            sig_bytes = sig.encode("utf-8") if isinstance(sig, str) else sig

            public_key = (
                key.public_key()
                if isinstance(key, (Ed25519PrivateKey, Ed448PrivateKey))
                else key
            )
            public_key.verify(sig_bytes, msg_bytes)
            return True
        except InvalidSignature:
            return False

    @overload
    @staticmethod
    def to_jwk(key: AllowedOKPKeys, as_dict: Literal[True]) -> JWKDict: ...
    @overload
    @staticmethod
    def to_jwk(key: AllowedOKPKeys, as_dict: Literal[False] = False) -> str: ...

    @staticmethod
    def to_jwk(key: AllowedOKPKeys, as_dict: bool = False) -> JWKDict | str:
        if isinstance(key, (Ed25519PublicKey, Ed448PublicKey)):
            x = key.public_bytes(
                encoding=Encoding.Raw,
                format=PublicFormat.Raw,
            )
            crv = "Ed25519" if isinstance(key, Ed25519PublicKey) else "Ed448"

            obj: dict[str, Any] = {
                "x": base64url_encode(force_bytes(x)).decode(),
                "kty": "OKP",
                "crv": crv,
            }
            return finalize_jwk(obj, as_dict)

        if isinstance(key, (Ed25519PrivateKey, Ed448PrivateKey)):
            d = key.private_bytes(
                encoding=Encoding.Raw,
                format=PrivateFormat.Raw,
                encryption_algorithm=NoEncryption(),
            )
            x = key.public_key().public_bytes(
                encoding=Encoding.Raw,
                format=PublicFormat.Raw,
            )
            crv = "Ed25519" if isinstance(key, Ed25519PrivateKey) else "Ed448"

            obj = {
                "x": base64url_encode(force_bytes(x)).decode(),
                "d": base64url_encode(force_bytes(d)).decode(),
                "kty": "OKP",
                "crv": crv,
            }
            return finalize_jwk(obj, as_dict)

        raise InvalidKeyError("Not a public or private key")

    @staticmethod
    def from_jwk(jwk: str | JWKDict) -> AllowedOKPKeys:
        obj = parse_jwk_input(jwk)

        if obj.get("kty") != "OKP":
            raise InvalidKeyError("Not an Octet Key Pair")

        curve_name = obj.get("crv")
        if curve_name not in _OKP_CRV_TO_CLASS:
            raise InvalidKeyError(f"Invalid curve: {curve_name}")

        priv_cls, pub_cls = _OKP_CRV_TO_CLASS[curve_name]

        if "x" not in obj:
            raise InvalidKeyError('OKP should have "x" parameter')

        x = base64url_decode(obj.get("x"))

        try:
            if "d" not in obj:
                return pub_cls.from_public_bytes(x)
            d = base64url_decode(obj.get("d"))
            return priv_cls.from_private_bytes(d)
        except ValueError as err:
            raise InvalidKeyError("Invalid key parameter") from err
