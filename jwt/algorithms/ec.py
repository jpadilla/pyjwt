from __future__ import annotations

from typing import Any, ClassVar, Literal, Union, cast, get_args, overload

from ..exceptions import InvalidKeyError
from ..types import JWKDict
from ..utils import (
    base64url_decode, base64url_encode, der_to_raw_signature,
    force_bytes, raw_to_der_signature, to_base64url_uint,
)
from ._helpers import finalize_jwk, parse_jwk_input
from ._types import AllowedECKeys, AllowedKeys
from .base import Algorithm

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA, SECP256K1, SECP256R1, SECP384R1, SECP521R1,
    EllipticCurve, EllipticCurvePrivateKey, EllipticCurvePrivateNumbers,
    EllipticCurvePublicKey, EllipticCurvePublicNumbers,
)
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, load_pem_public_key, load_ssh_public_key,
)

# ---- Curve Lookup Table (replaces ~40 lines of if/elif) ----

_EC_CRV_TO_CURVE: dict[str, tuple[type[EllipticCurve], int]] = {
    "P-256":     (SECP256R1, 32),
    "P-384":     (SECP384R1, 48),
    "P-521":     (SECP521R1, 66),
    "secp256k1": (SECP256K1, 32),
}

_EC_CURVE_TO_CRV: dict[type[EllipticCurve], str] = {
    SECP256R1: "P-256",
    SECP384R1: "P-384",
    SECP521R1: "P-521",
    SECP256K1: "secp256k1",
}


class ECAlgorithm(Algorithm):
    SHA256: ClassVar[type[hashes.HashAlgorithm]] = hashes.SHA256
    SHA384: ClassVar[type[hashes.HashAlgorithm]] = hashes.SHA384
    SHA512: ClassVar[type[hashes.HashAlgorithm]] = hashes.SHA512

    _crypto_key_types = cast(
        tuple[type[AllowedKeys], ...],
        get_args(Union[EllipticCurvePrivateKey, EllipticCurvePublicKey]),
    )

    def __init__(
        self,
        hash_alg: type[hashes.HashAlgorithm],
        expected_curve: type[EllipticCurve] | None = None,
    ) -> None:
        self.hash_alg = hash_alg
        self.expected_curve = expected_curve

    def _validate_curve(self, key: AllowedECKeys) -> None:
        if self.expected_curve is None:
            return
        if not isinstance(key.curve, self.expected_curve):
            raise InvalidKeyError(
                f"The key's curve '{key.curve.name}' does not match the expected "
                f"curve '{self.expected_curve.name}' for this algorithm"
            )

    def prepare_key(self, key: AllowedECKeys | str | bytes) -> AllowedECKeys:
        if isinstance(key, self._crypto_key_types):
            ec_key = cast(AllowedECKeys, key)
            self._validate_curve(ec_key)
            return ec_key

        if not isinstance(key, (bytes, str)):
            raise TypeError("Expecting a PEM-formatted key.")

        key_bytes = force_bytes(key)
        try:
            if key_bytes.startswith(b"ecdsa-sha2-"):
                public_key = load_ssh_public_key(key_bytes)
            else:
                public_key = load_pem_public_key(key_bytes)
            self.check_crypto_key_type(public_key)
            ec_pub = cast(EllipticCurvePublicKey, public_key)
            self._validate_curve(ec_pub)
            return ec_pub
        except ValueError:
            private_key = load_pem_private_key(key_bytes, password=None)
            self.check_crypto_key_type(private_key)
            ec_priv = cast(EllipticCurvePrivateKey, private_key)
            self._validate_curve(ec_priv)
            return ec_priv

    def sign(self, msg: bytes, key: EllipticCurvePrivateKey) -> bytes:
        der_sig = key.sign(msg, ECDSA(self.hash_alg()))
        return der_to_raw_signature(der_sig, key.curve)

    def verify(self, msg: bytes, key: AllowedECKeys, sig: bytes) -> bool:
        try:
            der_sig = raw_to_der_signature(sig, key.curve)
        except ValueError:
            return False
        try:
            pub = key.public_key() if isinstance(key, EllipticCurvePrivateKey) else key
            pub.verify(der_sig, msg, ECDSA(self.hash_alg()))
            return True
        except InvalidSignature:
            return False

    # ---- to_jwk: uses _EC_CURVE_TO_CRV instead of if/elif ----

    @overload
    @staticmethod
    def to_jwk(key_obj: AllowedECKeys, as_dict: Literal[True]) -> JWKDict: ...
    @overload
    @staticmethod
    def to_jwk(key_obj: AllowedECKeys, as_dict: Literal[False] = False) -> str: ...

    @staticmethod
    def to_jwk(key_obj: AllowedECKeys, as_dict: bool = False) -> JWKDict | str:
        if isinstance(key_obj, EllipticCurvePrivateKey):
            public_numbers = key_obj.public_key().public_numbers()
        elif isinstance(key_obj, EllipticCurvePublicKey):
            public_numbers = key_obj.public_numbers()
        else:
            raise InvalidKeyError("Not a public or private key")

        crv = _EC_CURVE_TO_CRV.get(type(key_obj.curve))
        if crv is None:
            raise InvalidKeyError(f"Invalid curve: {key_obj.curve}")

        obj: dict[str, Any] = {
            "kty": "EC",
            "crv": crv,
            "x": to_base64url_uint(
                public_numbers.x, bit_length=key_obj.curve.key_size
            ).decode(),
            "y": to_base64url_uint(
                public_numbers.y, bit_length=key_obj.curve.key_size
            ).decode(),
        }

        if isinstance(key_obj, EllipticCurvePrivateKey):
            obj["d"] = to_base64url_uint(
                key_obj.private_numbers().private_value,
                bit_length=key_obj.curve.key_size,
            ).decode()

        return finalize_jwk(obj, as_dict)

    # ---- from_jwk: uses _EC_CRV_TO_CURVE instead of if/elif ----

    @staticmethod
    def from_jwk(jwk: str | JWKDict) -> AllowedECKeys:
        obj = parse_jwk_input(jwk)

        if obj.get("kty") != "EC":
            raise InvalidKeyError("Not an Elliptic curve key") from None
        if "x" not in obj or "y" not in obj:
            raise InvalidKeyError("Not an Elliptic curve key") from None

        x = base64url_decode(obj["x"])
        y = base64url_decode(obj["y"])
        curve_name = obj.get("crv")

        if curve_name not in _EC_CRV_TO_CURVE:
            raise InvalidKeyError(f"Invalid curve: {curve_name}")

        curve_cls, expected_len = _EC_CRV_TO_CURVE[curve_name]

        if len(x) != expected_len or len(y) != expected_len:
            raise InvalidKeyError(
                f"Coords should be {expected_len} bytes for curve {curve_name}"
            )

        curve_obj = curve_cls()
        public_numbers = EllipticCurvePublicNumbers(
            x=int.from_bytes(x, byteorder="big"),
            y=int.from_bytes(y, byteorder="big"),
            curve=curve_obj,
        )

        if "d" not in obj:
            return public_numbers.public_key()

        d = base64url_decode(obj["d"])
        if len(d) != expected_len:
            raise InvalidKeyError(
                f"D should be {expected_len} bytes for curve {curve_name}"
            )

        return EllipticCurvePrivateNumbers(
            int.from_bytes(d, byteorder="big"), public_numbers
        ).private_key()
