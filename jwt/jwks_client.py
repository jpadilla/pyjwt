import json
import urllib.request
from functools import lru_cache
from typing import Any, List

from .api_jwk import PyJWK, PyJWKSet
from .api_jwt import decode_complete as decode_token
from .exceptions import PyJWKClientError, PyJWKSetError


class PyJWKClient:
    def __init__(self, uri: str, cache_keys: bool = True, max_cached_keys: int = 16):
        self.uri = uri
        if cache_keys:
            # Cache signing keys
            # Ignore mypy (https://github.com/python/mypy/issues/2427)
            self.get_signing_key = lru_cache(maxsize=max_cached_keys)(self.get_signing_key)  # type: ignore

    def fetch_data(self) -> Any:
        with urllib.request.urlopen(self.uri) as response:
            return json.load(response)

    def get_jwk_set(self) -> PyJWKSet:
        data = self.fetch_data()
        return PyJWKSet.from_dict(data)

    def get_signing_keys(self) -> List[PyJWK]:
        jwk_set = self.get_jwk_set()
        try:
            return jwk_set.get_signing_keys()
        except PyJWKSetError as e:
            assert str(e) == "The JWK Set did not contain any signing keys"
            raise PyJWKClientError("The JWKS endpoint did not contain any signing keys")

    def get_signing_key(self, kid: str) -> PyJWK:
        jwk_set = self.get_jwk_set()
        try:
            return jwk_set.get_signing_key(kid)
        except PyJWKSetError as e:
            assert str(e).startswith("Unable to find a signing key that matches:")
            raise PyJWKClientError(
                f'Unable to find a signing key that matches: "{kid}"'
            )

    def get_signing_key_from_jwt(self, token: str) -> PyJWK:
        unverified = decode_token(token, options={"verify_signature": False})
        header = unverified["header"]
        return self.get_signing_key(header.get("kid"))
