from __future__ import annotations

from typing import Any, ClassVar, Literal, cast, overload

from ..exceptions import InvalidKeyError
from ..types import JWKDict
from ..utils import (
    force_bytes,
    from_base64url_uint,
    to_base64url_uint,
)
from ._helpers import finalize_jwk, parse_jwk_input
from ._types import AllowedRSAKeys
from .base import Algorithm

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPrivateNumbers,
    RSAPublicKey,
    RSAPublicNumbers,
    rsa_crt_dmp1,
    rsa_crt_dmq1,
    rsa_crt_iqmp,
    rsa_recover_prime_factors,
)
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
    load_ssh_public_key,
)


class RSAAlgorithm(Algorithm):
    SHA256: ClassVar[type[hashes.HashAlgorithm]] = hashes.SHA256
    SHA384: ClassVar[type[hashes.HashAlgorithm]] = hashes.SHA384
    SHA512: ClassVar[type[hashes.HashAlgorithm]] = hashes.SHA512

    _crypto_key_types: ClassVar[tuple[type[RSAPrivateKey], type[RSAPublicKey]]] = (
        RSAPrivateKey,
        RSAPublicKey,
    )
    _MIN_KEY_SIZE: ClassVar[int] = 2048

    def __init__(self, hash_alg: type[hashes.HashAlgorithm]) -> None:
        self.hash_alg = hash_alg

    def check_key_length(self, key: AllowedRSAKeys) -> str | None:
        if key.key_size < self._MIN_KEY_SIZE:
            return (
                f"The RSA key is {key.key_size} bits long, which is below "
                f"the minimum recommended size of {self._MIN_KEY_SIZE} bits. "
                f"See NIST SP 800-131A."
            )
        return None

    def prepare_key(self, key: AllowedRSAKeys | str | bytes) -> AllowedRSAKeys:
        if isinstance(key, self._crypto_key_types):
            return key

        if not isinstance(key, (bytes, str)):
            raise TypeError("Expecting a PEM-formatted key.")

        key_bytes = force_bytes(key)

        try:
            if key_bytes.startswith(b"ssh-rsa"):
                public_key = load_ssh_public_key(key_bytes)
                self.check_crypto_key_type(public_key)
                return cast(RSAPublicKey, public_key)
            else:
                private_key = load_pem_private_key(key_bytes, password=None)
                self.check_crypto_key_type(private_key)
                return cast(RSAPrivateKey, private_key)
        except ValueError:
            try:
                public_key = load_pem_public_key(key_bytes)
                self.check_crypto_key_type(public_key)
                return cast(RSAPublicKey, public_key)
            except (ValueError, UnsupportedAlgorithm):
                raise InvalidKeyError(
                    "Could not parse the provided public key."
                ) from None

    def sign(self, msg: bytes, key: RSAPrivateKey) -> bytes:
        return key.sign(msg, padding.PKCS1v15(), self.hash_alg())

    def verify(self, msg: bytes, key: AllowedRSAKeys, sig: bytes) -> bool:
        try:
            pub = key.public_key() if isinstance(key, RSAPrivateKey) else key
            pub.verify(sig, msg, padding.PKCS1v15(), self.hash_alg())
            return True
        except InvalidSignature:
            return False

    @overload
    @staticmethod
    def to_jwk(key_obj: AllowedRSAKeys, as_dict: Literal[True]) -> JWKDict: ...
    @overload
    @staticmethod
    def to_jwk(key_obj: AllowedRSAKeys, as_dict: Literal[False] = False) -> str: ...

    @staticmethod
    def to_jwk(key_obj: AllowedRSAKeys, as_dict: bool = False) -> JWKDict | str:
        if isinstance(key_obj, RSAPrivateKey):
            numbers = key_obj.private_numbers()
            obj: dict[str, Any] = {
                "kty": "RSA",
                "key_ops": ["sign"],
                "n": to_base64url_uint(numbers.public_numbers.n).decode(),
                "e": to_base64url_uint(numbers.public_numbers.e).decode(),
                "d": to_base64url_uint(numbers.d).decode(),
                "p": to_base64url_uint(numbers.p).decode(),
                "q": to_base64url_uint(numbers.q).decode(),
                "dp": to_base64url_uint(numbers.dmp1).decode(),
                "dq": to_base64url_uint(numbers.dmq1).decode(),
                "qi": to_base64url_uint(numbers.iqmp).decode(),
            }
        elif isinstance(key_obj, RSAPublicKey):
            numbers = key_obj.public_numbers()
            obj = {
                "kty": "RSA",
                "key_ops": ["verify"],
                "n": to_base64url_uint(numbers.n).decode(),
                "e": to_base64url_uint(numbers.e).decode(),
            }
        else:
            raise InvalidKeyError("Not a public or private key")

        return finalize_jwk(obj, as_dict)

    @staticmethod
    def from_jwk(jwk: str | JWKDict) -> AllowedRSAKeys:
        obj = parse_jwk_input(jwk)

        if obj.get("kty") != "RSA":
            raise InvalidKeyError("Not an RSA key") from None

        if "d" in obj and "e" in obj and "n" in obj:
            # Private key
            if "oth" in obj:
                raise InvalidKeyError(
                    "Unsupported RSA private key: > 2 primes not supported"
                )

            other_props = ["p", "q", "dp", "dq", "qi"]
            props_found = [prop in obj for prop in other_props]
            any_props_found = any(props_found)

            if any_props_found and not all(props_found):
                raise InvalidKeyError(
                    "RSA key must include all parameters if any are present besides d"
                ) from None

            public_numbers = RSAPublicNumbers(
                from_base64url_uint(obj["e"]),
                from_base64url_uint(obj["n"]),
            )

            if any_props_found:
                numbers = RSAPrivateNumbers(
                    d=from_base64url_uint(obj["d"]),
                    p=from_base64url_uint(obj["p"]),
                    q=from_base64url_uint(obj["q"]),
                    dmp1=from_base64url_uint(obj["dp"]),
                    dmq1=from_base64url_uint(obj["dq"]),
                    iqmp=from_base64url_uint(obj["qi"]),
                    public_numbers=public_numbers,
                )
            else:
                d = from_base64url_uint(obj["d"])
                p, q = rsa_recover_prime_factors(public_numbers.n, d, public_numbers.e)
                numbers = RSAPrivateNumbers(
                    d=d,
                    p=p,
                    q=q,
                    dmp1=rsa_crt_dmp1(d, p),
                    dmq1=rsa_crt_dmq1(d, q),
                    iqmp=rsa_crt_iqmp(p, q),
                    public_numbers=public_numbers,
                )

            return numbers.private_key()
        elif "n" in obj and "e" in obj:
            # Public key
            return RSAPublicNumbers(
                from_base64url_uint(obj["e"]),
                from_base64url_uint(obj["n"]),
            ).public_key()
        else:
            raise InvalidKeyError("Not a public or private key")


class RSAPSSAlgorithm(RSAAlgorithm):
    def sign(self, msg: bytes, key: RSAPrivateKey) -> bytes:
        return key.sign(
            msg,
            padding.PSS(
                mgf=padding.MGF1(self.hash_alg()),
                salt_length=self.hash_alg().digest_size,
            ),
            self.hash_alg(),
        )

    def verify(self, msg: bytes, key: AllowedRSAKeys, sig: bytes) -> bool:
        try:
            pub = key.public_key() if isinstance(key, RSAPrivateKey) else key
            pub.verify(
                sig,
                msg,
                padding.PSS(
                    mgf=padding.MGF1(self.hash_alg()),
                    salt_length=self.hash_alg().digest_size,
                ),
                self.hash_alg(),
            )
            return True
        except InvalidSignature:
            return False
