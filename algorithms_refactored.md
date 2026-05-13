# Algorithms Refactoring — Suggested Code

Refactors the 999-line `algorithms.py` into a subpackage + extracts duplicated helpers.

---

## New File Structure

```
jwt/
  algorithms/
    __init__.py      # Re-exports for backward compat
    _types.py        # TypeAlias definitions
    _helpers.py      # Shared JWK parse/serialize helpers
    base.py          # Algorithm ABC, NoneAlgorithm
    hmac.py          # HMACAlgorithm
    rsa.py           # RSAAlgorithm, RSAPSSAlgorithm
    ec.py            # ECAlgorithm
    okp.py           # OKPAlgorithm
```

---

## `algorithms/_helpers.py`

Extracted from 4 identical copy-pasted blocks across `from_jwk()` and `to_jwk()`.

```python
from __future__ import annotations

import json
from typing import Any

from ..exceptions import InvalidKeyError
from ..types import JWKDict


def parse_jwk_input(jwk: str | JWKDict) -> JWKDict:
    """Common JWK deserialization used by all from_jwk() methods."""
    try:
        if isinstance(jwk, str):
            return json.loads(jwk)
        elif isinstance(jwk, dict):
            return jwk
        raise ValueError
    except ValueError:
        raise InvalidKeyError("Key is not valid JSON") from None


def finalize_jwk(obj: dict[str, Any], as_dict: bool) -> JWKDict | str:
    """Common JWK serialization used by all to_jwk() methods."""
    if as_dict:
        return obj
    return json.dumps(obj)
```

---

## `algorithms/_types.py`

```python
from __future__ import annotations

import os
import sys
from typing import TYPE_CHECKING, Union

try:
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurvePrivateKey,
        EllipticCurvePublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.ed448 import (
        Ed448PrivateKey,
        Ed448PublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.rsa import (
        RSAPrivateKey,
        RSAPublicKey,
    )

    if sys.version_info >= (3, 10):
        from typing import TypeAlias
    else:
        from typing_extensions import TypeAlias

    AllowedRSAKeys: TypeAlias = Union[RSAPrivateKey, RSAPublicKey]
    AllowedECKeys: TypeAlias = Union[EllipticCurvePrivateKey, EllipticCurvePublicKey]
    AllowedOKPKeys: TypeAlias = Union[
        Ed25519PrivateKey, Ed25519PublicKey, Ed448PrivateKey, Ed448PublicKey
    ]
    AllowedKeys: TypeAlias = Union[AllowedRSAKeys, AllowedECKeys, AllowedOKPKeys]
    AllowedPrivateKeys: TypeAlias = Union[
        RSAPrivateKey, EllipticCurvePrivateKey, Ed25519PrivateKey, Ed448PrivateKey
    ]
    AllowedPublicKeys: TypeAlias = Union[
        RSAPublicKey, EllipticCurvePublicKey, Ed25519PublicKey, Ed448PublicKey
    ]

    if TYPE_CHECKING or bool(os.getenv("SPHINX_BUILD", "")):
        from cryptography.hazmat.primitives.asymmetric.types import (
            PrivateKeyTypes,
            PublicKeyTypes,
        )

    has_crypto = True
except ModuleNotFoundError:
    if sys.version_info >= (3, 11):
        from typing import Never
    else:
        from typing_extensions import Never

    AllowedRSAKeys = Never  # type: ignore[misc]
    AllowedECKeys = Never  # type: ignore[misc]
    AllowedOKPKeys = Never  # type: ignore[misc]
    AllowedKeys = Never  # type: ignore[misc]
    AllowedPrivateKeys = Never  # type: ignore[misc]
    AllowedPublicKeys = Never  # type: ignore[misc]
    has_crypto = False

requires_cryptography = {
    "RS256",
    "RS384",
    "RS512",
    "ES256",
    "ES256K",
    "ES384",
    "ES521",
    "ES512",
    "PS256",
    "PS384",
    "PS512",
    "EdDSA",
}
```

---

## `algorithms/base.py`

```python
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Literal, NoReturn, overload

from ..exceptions import InvalidKeyError
from ..types import JWKDict
from ._types import AllowedKeys, has_crypto

if has_crypto:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.types import (
        PrivateKeyTypes,
        PublicKeyTypes,
    )


class Algorithm(ABC):
    """The interface for an algorithm used to sign and verify tokens."""

    _crypto_key_types: tuple[type[AllowedKeys], ...] | None = None

    def compute_hash_digest(self, bytestr: bytes) -> bytes:
        hash_alg = getattr(self, "hash_alg", None)
        if hash_alg is None:
            raise NotImplementedError

        if (
            has_crypto
            and isinstance(hash_alg, type)
            and issubclass(hash_alg, hashes.HashAlgorithm)
        ):
            digest = hashes.Hash(hash_alg(), backend=default_backend())
            digest.update(bytestr)
            return bytes(digest.finalize())
        else:
            return bytes(hash_alg(bytestr).digest())

    def check_crypto_key_type(self, key: PublicKeyTypes | PrivateKeyTypes) -> None:
        if not has_crypto or self._crypto_key_types is None:
            raise ValueError(
                "This method requires the cryptography library, "
                "and should only be used by cryptography-based algorithms."
            )
        if not isinstance(key, self._crypto_key_types):
            valid_classes = (cls.__name__ for cls in self._crypto_key_types)
            raise InvalidKeyError(
                f"Expected one of {valid_classes}, got: {key.__class__.__name__}. "
                f"Invalid Key type for {self.__class__.__name__}"
            )

    @abstractmethod
    def prepare_key(self, key: Any) -> Any: ...

    @abstractmethod
    def sign(self, msg: bytes, key: Any) -> bytes: ...

    @abstractmethod
    def verify(self, msg: bytes, key: Any, sig: bytes) -> bool: ...

    @overload
    @staticmethod
    @abstractmethod
    def to_jwk(key_obj: Any, as_dict: Literal[True]) -> JWKDict: ...
    @overload
    @staticmethod
    @abstractmethod
    def to_jwk(key_obj: Any, as_dict: Literal[False] = False) -> str: ...
    @staticmethod
    @abstractmethod
    def to_jwk(key_obj: Any, as_dict: bool = False) -> JWKDict | str: ...

    @staticmethod
    @abstractmethod
    def from_jwk(jwk: str | JWKDict) -> Any: ...

    def check_key_length(self, key: Any) -> str | None:
        return None


class NoneAlgorithm(Algorithm):
    """Placeholder for use when no signing or verification is required."""

    def prepare_key(self, key: str | None) -> None:
        if key == "":
            key = None
        if key is not None:
            raise InvalidKeyError('When alg = "none", key value must be None.')
        return key

    def sign(self, msg: bytes, key: None) -> bytes:
        return b""

    def verify(self, msg: bytes, key: None, sig: bytes) -> bool:
        return False

    @staticmethod
    def to_jwk(key_obj: Any, as_dict: bool = False) -> NoReturn:
        raise NotImplementedError()

    @staticmethod
    def from_jwk(jwk: str | JWKDict) -> NoReturn:
        raise NotImplementedError()
```

---

## `algorithms/hmac.py`

```python
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
```

---

## `algorithms/ec.py` — with curve lookup table

Key refactoring: the `if/elif` chains become a dictionary lookup.

```python
from __future__ import annotations

from typing import Any, ClassVar, Literal, Union, cast, get_args, overload

from ..exceptions import InvalidKeyError
from ..types import JWKDict
from ..utils import (
    base64url_decode,
    base64url_encode,
    der_to_raw_signature,
    force_bytes,
    raw_to_der_signature,
    to_base64url_uint,
)
from ._helpers import finalize_jwk, parse_jwk_input
from ._types import AllowedECKeys, AllowedKeys
from .base import Algorithm

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    SECP256K1,
    SECP256R1,
    SECP384R1,
    SECP521R1,
    EllipticCurve,
    EllipticCurvePrivateKey,
    EllipticCurvePrivateNumbers,
    EllipticCurvePublicKey,
    EllipticCurvePublicNumbers,
)
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
    load_ssh_public_key,
)

# ---- Curve Lookup Table (replaces ~40 lines of if/elif) ----

_EC_CRV_TO_CURVE: dict[str, tuple[type[EllipticCurve], int]] = {
    "P-256": (SECP256R1, 32),
    "P-384": (SECP384R1, 48),
    "P-521": (SECP521R1, 66),
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
```

---

## `algorithms/__init__.py`

Backward-compatible re-exports so `from jwt.algorithms import X` still works.

```python
from __future__ import annotations

from ._types import (
    AllowedECKeys,
    AllowedKeys,
    AllowedOKPKeys,
    AllowedPrivateKeys,
    AllowedPublicKeys,
    AllowedRSAKeys,
    has_crypto,
    requires_cryptography,
)
from .base import Algorithm, NoneAlgorithm
from .hmac import HMACAlgorithm

if has_crypto:
    from .ec import ECAlgorithm
    from .okp import OKPAlgorithm
    from .rsa import RSAAlgorithm, RSAPSSAlgorithm

from .ec import _EC_CRV_TO_CURVE  # noqa: for use by api_jwk if needed


def get_default_algorithms() -> dict[str, Algorithm]:
    default_algorithms: dict[str, Algorithm] = {
        "none": NoneAlgorithm(),
        "HS256": HMACAlgorithm(HMACAlgorithm.SHA256),
        "HS384": HMACAlgorithm(HMACAlgorithm.SHA384),
        "HS512": HMACAlgorithm(HMACAlgorithm.SHA512),
    }

    if has_crypto:
        from cryptography.hazmat.primitives.asymmetric.ec import (
            SECP256K1,
            SECP256R1,
            SECP384R1,
            SECP521R1,
        )

        default_algorithms.update(
            {
                "RS256": RSAAlgorithm(RSAAlgorithm.SHA256),
                "RS384": RSAAlgorithm(RSAAlgorithm.SHA384),
                "RS512": RSAAlgorithm(RSAAlgorithm.SHA512),
                "ES256": ECAlgorithm(ECAlgorithm.SHA256, SECP256R1),
                "ES256K": ECAlgorithm(ECAlgorithm.SHA256, SECP256K1),
                "ES384": ECAlgorithm(ECAlgorithm.SHA384, SECP384R1),
                "ES521": ECAlgorithm(ECAlgorithm.SHA512, SECP521R1),
                "ES512": ECAlgorithm(ECAlgorithm.SHA512, SECP521R1),
                "PS256": RSAPSSAlgorithm(RSAPSSAlgorithm.SHA256),
                "PS384": RSAPSSAlgorithm(RSAPSSAlgorithm.SHA384),
                "PS512": RSAPSSAlgorithm(RSAPSSAlgorithm.SHA512),
                "EdDSA": OKPAlgorithm(),
            }
        )

    return default_algorithms


__all__ = [
    "Algorithm",
    "NoneAlgorithm",
    "HMACAlgorithm",
    "RSAAlgorithm",
    "RSAPSSAlgorithm",
    "ECAlgorithm",
    "OKPAlgorithm",
    "AllowedRSAKeys",
    "AllowedECKeys",
    "AllowedOKPKeys",
    "AllowedKeys",
    "AllowedPrivateKeys",
    "AllowedPublicKeys",
    "has_crypto",
    "requires_cryptography",
    "get_default_algorithms",
]
```

---

## Key Changes Summary

| What Changed | Before | After |
|---|---|---|
| File count | 1 file (999 lines) | 7 files (~140 lines avg) |
| JWK parse boilerplate | Copy-pasted 4× | `parse_jwk_input()` helper |
| JWK serialize boilerplate | Copy-pasted 4× | `finalize_jwk()` helper |
| EC curve mapping | ~40 lines of `if/elif` | 2 dict lookups |
| `if has_crypto:` nesting | 600 lines indented | Module-level imports |
| Imports from other modules | `from .algorithms import X` | Still works (re-exports) |

> [!NOTE]
> `rsa.py` and `okp.py` follow the same pattern as `hmac.py` and `ec.py` — use `parse_jwk_input()` / `finalize_jwk()` and remove the `if has_crypto:` wrapper since they're only imported conditionally in `__init__.py`.
