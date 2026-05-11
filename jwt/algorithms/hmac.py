from __future__ import annotations

import hashlib
import hmac
from typing import ClassVar, Literal, overload

from ..exceptions import InvalidKeyError
from ..types import HashlibHash, JWKDict
from ..utils import base64url_decode, force_bytes, is_pem_format, is_ssh_key
from ._helpers import finalize_jwk, parse_jwk_input
from .base import Algorithm


class HMACAlgorithm(Algorithm):
    SHA256: ClassVar[HashlibHash] = hashlib.sha256
    SHA384: ClassVar[HashlibHash] = hashlib.sha384
    SHA512: ClassVar[HashlibHash] = hashlib.sha512

    def __init__(self, hash_alg: HashlibHash) -> None:
        self.hash_alg = hash_alg

    def prepare_key(self, key: str | bytes) -> bytes:
        key_bytes = force_bytes(key)
        if is_pem_format(key_bytes) or is_ssh_key(key_bytes):
            raise InvalidKeyError(
                "The specified key is an asymmetric key or x509 certificate "
                "and should not be used as an HMAC secret."
            )
        return key_bytes

    @overload
    @staticmethod
    def to_jwk(key_obj: str | bytes, as_dict: Literal[True]) -> JWKDict: ...
    @overload
    @staticmethod
    def to_jwk(key_obj: str | bytes, as_dict: Literal[False] = False) -> str: ...

    @staticmethod
    def to_jwk(key_obj: str | bytes, as_dict: bool = False) -> JWKDict | str:
        from ..utils import base64url_encode
        obj = {
            "k": base64url_encode(force_bytes(key_obj)).decode(),
            "kty": "oct",
        }
        return finalize_jwk(obj, as_dict)

    @staticmethod
    def from_jwk(jwk: str | JWKDict) -> bytes:
        obj = parse_jwk_input(jwk)
        if obj.get("kty") != "oct":
            raise InvalidKeyError("Not an HMAC key")
        return base64url_decode(obj["k"])

    def check_key_length(self, key: bytes) -> str | None:
        min_length = self.hash_alg().digest_size
        if len(key) < min_length:
            return (
                f"The HMAC key is {len(key)} bytes long, which is below "
                f"the minimum recommended length of {min_length} bytes for "
                f"{self.hash_alg().name.upper()}. See RFC 7518 Section 3.2."
            )
        return None

    def sign(self, msg: bytes, key: bytes) -> bytes:
        return hmac.new(key, msg, self.hash_alg).digest()

    def verify(self, msg: bytes, key: bytes, sig: bytes) -> bool:
        return hmac.compare_digest(sig, self.sign(msg, key))