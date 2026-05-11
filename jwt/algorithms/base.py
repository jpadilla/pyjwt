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
        PrivateKeyTypes, PublicKeyTypes,
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
