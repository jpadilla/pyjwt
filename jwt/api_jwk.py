from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Iterator
from typing import Any

from .utils import base64url_encode

from .algorithms import get_default_algorithms, has_crypto, requires_cryptography
from .exceptions import (
    InvalidKeyError,
    MissingCryptographyError,
    PyJWKError,
    PyJWKSetError,
    PyJWTError,
)
from .types import JWKDict


class PyJWK:
    def __init__(self, jwk_data: JWKDict, algorithm: str | None = None) -> None:
        """A class that represents a `JSON Web Key <https://www.rfc-editor.org/rfc/rfc7517>`_.

        :param jwk_data: The decoded JWK data.
        :type jwk_data: dict[str, typing.Any]
        :param algorithm: The key algorithm. If not specified, the key's ``alg`` will be used.
        :type algorithm: str or None
        :raises InvalidKeyError: If the key type (``kty``) is not found or unsupported, or if the curve (``crv``) is not found or unsupported.
        :raises MissingCryptographyError: If the algorithm requires ``cryptography`` to be installed and it is not available.
        :raises PyJWKError: If unable to find an algorithm for the key.
        """
        self._jwk_data = jwk_data

        kty = self._jwk_data.get("kty", None)
        if not kty:
            raise InvalidKeyError(f"kty is not found: {self._jwk_data}")

        if not algorithm and isinstance(self._jwk_data, dict):
            algorithm = self._jwk_data.get("alg", None)

        if not algorithm:
            # Determine alg with kty (and crv).
            crv = self._jwk_data.get("crv", None)
            if kty == "EC":
                if crv == "P-256" or not crv:
                    algorithm = "ES256"
                elif crv == "P-384":
                    algorithm = "ES384"
                elif crv == "P-521":
                    algorithm = "ES512"
                elif crv == "secp256k1":
                    algorithm = "ES256K"
                else:
                    raise InvalidKeyError(f"Unsupported crv: {crv}")
            elif kty == "RSA":
                algorithm = "RS256"
            elif kty == "oct":
                algorithm = "HS256"
            elif kty == "OKP":
                if not crv:
                    raise InvalidKeyError(f"crv is not found: {self._jwk_data}")
                if crv == "Ed25519":
                    algorithm = "EdDSA"
                else:
                    raise InvalidKeyError(f"Unsupported crv: {crv}")
            else:
                raise InvalidKeyError(f"Unsupported kty: {kty}")

        if not has_crypto and algorithm in requires_cryptography:
            raise MissingCryptographyError(
                f"{algorithm} requires 'cryptography' to be installed."
            )

        self.algorithm_name = algorithm

        try:
            self.Algorithm = get_default_algorithms()[algorithm]
        except KeyError:
            raise PyJWKError(
                f"Unable to find an algorithm for key: {self._jwk_data}",
            ) from None

        try:
            self.key = self.Algorithm.from_jwk(self._jwk_data)
        except (TypeError, ValueError) as error:
            raise InvalidKeyError(
                f"Unable to construct key from JWK: {error}"
            ) from error

    @staticmethod
    def from_dict(obj: JWKDict, algorithm: str | None = None) -> PyJWK:
        """Creates a :class:`PyJWK` object from a JSON-like dictionary.

        :param obj: The JWK data, as a dictionary
        :type obj: dict[str, typing.Any]
        :param algorithm: The key algorithm. If not specified, the key's ``alg`` will be used.
        :type algorithm: str or None
        :rtype: PyJWK
        """
        return PyJWK(obj, algorithm)

    @staticmethod
    def from_json(data: str, algorithm: str | None = None) -> PyJWK:
        """Create a :class:`PyJWK` object from a JSON string.
        Implicitly calls :meth:`PyJWK.from_dict()`.

        :param str data: The JWK data, as a JSON string.
        :param algorithm:  The key algorithm.  If not specific, the key's ``alg`` will be used.
        :type algorithm: str or None

        :rtype: PyJWK
        """
        obj = json.loads(data)
        return PyJWK.from_dict(obj, algorithm)

    @property
    def key_type(self) -> str | None:
        """The `kty` property from the JWK.

        :rtype: str or None
        """
        return self._jwk_data.get("kty", None)

    @property
    def key_id(self) -> str | None:
        """The `kid` property from the JWK.

        :rtype: str or None
        """
        return self._jwk_data.get("kid", None)

    @property
    def public_key_use(self) -> str | None:
        """The `use` property from the JWK.

        :rtype: str or None
        """
        return self._jwk_data.get("use", None)

    # The members required for a thumbprint, per key type, as defined by
    # RFC 7638, Section 3.2. All other members are excluded.
    _THUMBPRINT_REQUIRED_MEMBERS: dict[str, tuple[str, ...]] = {
        "EC": ("crv", "kty", "x", "y"),
        "OKP": ("crv", "kty", "x"),
        "RSA": ("e", "kty", "n"),
        "oct": ("k", "kty"),
    }

    def thumbprint(self, hash_algorithm: str = "SHA-256") -> str:
        """Compute the JWK thumbprint of this key, as defined by
        `RFC 7638 <https://www.rfc-editor.org/rfc/rfc7638.html>`_.

        Only the members required for the key's ``kty`` are included, in
        lexicographic order, so members such as ``kid``, ``alg`` and
        ``use`` do not affect the result. The JSON representation is
        hashed and the digest is Base64URL-encoded without padding.

        :param hash_algorithm: The hash function to use, for example
            ``"SHA-256"`` (the default), ``"SHA-384"`` or ``"SHA-512"``.
        :type hash_algorithm: str
        :rtype: str
        :raises InvalidKeyError: If the key type is unsupported or a
            member required for the thumbprint is missing.
        :raises ValueError: If ``hash_algorithm`` is not a known hash
            function.
        """
        kty = self.key_type
        try:
            required_members = self._THUMBPRINT_REQUIRED_MEMBERS[kty]  # type: ignore[index]
        except KeyError:
            raise InvalidKeyError(f"Unsupported kty for thumbprint: {kty}") from None

        missing_members = [
            member for member in required_members if member not in self._jwk_data
        ]
        if missing_members:
            raise InvalidKeyError(
                "Unable to compute thumbprint, missing required "
                f"member(s): {', '.join(missing_members)}"
            )

        try:
            hash_function = hashlib.new(hash_algorithm.replace("-", "").lower())
        except ValueError:
            raise ValueError(f"Unsupported hash algorithm: {hash_algorithm}") from None

        thumbprint_json = json.dumps(
            {member: self._jwk_data[member] for member in required_members},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        hash_function.update(thumbprint_json)
        return base64url_encode(hash_function.digest()).decode("ascii")


class PyJWKSet:
    def __init__(self, keys: list[JWKDict]) -> None:
        self.keys: list[PyJWK] = []

        if not keys:
            raise PyJWKSetError("The JWK Set did not contain any keys")

        if not isinstance(keys, list):
            raise PyJWKSetError("Invalid JWK Set value")

        for key in keys:
            if not isinstance(key, dict):
                # skip members that aren't JWK objects
                continue
            try:
                self.keys.append(PyJWK(key))
            except PyJWTError as error:
                if isinstance(error, MissingCryptographyError):
                    raise error
                # skip unusable keys
                continue

        if len(self.keys) == 0:
            raise PyJWKSetError(
                "The JWK Set did not contain any usable keys. Perhaps 'cryptography' is not installed?"
            )

    @staticmethod
    def from_dict(obj: dict[str, Any]) -> PyJWKSet:
        keys = obj.get("keys", [])
        return PyJWKSet(keys)

    @staticmethod
    def from_json(data: str) -> PyJWKSet:
        obj = json.loads(data)
        return PyJWKSet.from_dict(obj)

    def __getitem__(self, kid: str) -> PyJWK:
        for key in self.keys:
            if key.key_id == kid:
                return key
        raise KeyError(f"keyset has no key for kid: {kid}")

    def __iter__(self) -> Iterator[PyJWK]:
        return iter(self.keys)


class PyJWTSetWithTimestamp:
    def __init__(self, jwk_set: PyJWKSet):
        self.jwk_set = jwk_set
        self.timestamp = time.monotonic()

    def get_jwk_set(self) -> PyJWKSet:
        return self.jwk_set

    def get_timestamp(self) -> float:
        return self.timestamp
