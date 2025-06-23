from __future__ import annotations

import json
import time
import urllib.request
from ssl import SSLContext
from typing import Any, Dict, List, Optional
from urllib.error import URLError

from .api_jwk import PyJWK, PyJWKSet
from .api_jwt import decode_complete as decode_token
from .exceptions import PyJWKClientConnectionError, PyJWKClientError
from .jwk_set_cache import JWKSetCache


class PyJWKClient:
    def __init__(
        self,
        uri: str,
        cache_keys: bool = False,
        max_cached_keys: int = 16,
        cache_jwk_set: bool = True,
        lifespan: float = 300,
        headers: Optional[Dict[str, Any]] = None,
        timeout: float = 30,
        ssl_context: Optional[SSLContext] = None,
    ):
        if headers is None:
            headers = {}
        self.uri = uri
        self.jwk_set_cache: Optional[JWKSetCache] = None
        self.headers = headers
        self.timeout = timeout
        self.ssl_context = ssl_context

        if cache_jwk_set:
            # Init jwt set cache with default or given lifespan.
            # Default lifespan is 300 seconds (5 minutes).
            if lifespan <= 0:
                raise PyJWKClientError(
                    f'Lifespan must be greater than 0, the input is "{lifespan}"'
                )
            self.jwk_set_cache = JWKSetCache(lifespan)
        else:
            self.jwk_set_cache = None

        # Replace lru_cache with TTL-aware individual key cache
        # Use the same TTL as JWKSetCache for consistency
        if cache_keys:
            self._key_cache_enabled = True
            self._key_cache: Dict[str, tuple[PyJWK, float]] = {}  # kid -> (key, timestamp)
            self._max_cached_keys = max_cached_keys
            self._key_cache_ttl = lifespan  # Use same TTL as JWKSetCache
        else:
            self._key_cache_enabled = False

    def fetch_data(self) -> Any:
        jwk_set: Any = None
        try:
            r = urllib.request.Request(url=self.uri, headers=self.headers)
            with urllib.request.urlopen(
                r, timeout=self.timeout, context=self.ssl_context
            ) as response:
                jwk_set = json.load(response)
        except (URLError, TimeoutError) as e:
            raise PyJWKClientConnectionError(
                f'Fail to fetch data from the url, err: "{e}"'
            ) from e
        else:
            return jwk_set
        finally:
            if self.jwk_set_cache is not None:
                self.jwk_set_cache.put(jwk_set)

    def get_jwk_set(self, refresh: bool = False) -> PyJWKSet:
        data = None
        if self.jwk_set_cache is not None and not refresh:
            data = self.jwk_set_cache.get()

        if data is None:
            data = self.fetch_data()

        if not isinstance(data, dict):
            raise PyJWKClientError("The JWKS endpoint did not return a JSON object")

        return PyJWKSet.from_dict(data)

    def get_signing_keys(self, refresh: bool = False) -> List[PyJWK]:
        jwk_set = self.get_jwk_set(refresh)
        signing_keys = [
            jwk_set_key
            for jwk_set_key in jwk_set.keys
            if jwk_set_key.public_key_use in ["sig", None] and jwk_set_key.key_id
        ]

        if not signing_keys:
            raise PyJWKClientError("The JWKS endpoint did not contain any signing keys")

        return signing_keys

    def _get_cached_key(self, kid: str) -> Optional[PyJWK]:
        """Get a cached key if it exists and hasn't expired."""
        if not self._key_cache_enabled or kid not in self._key_cache:
            return None

        key, timestamp = self._key_cache[kid]

        # Check and remove if expired (use same logic as JWKSetCache)
        if time.monotonic() - timestamp > self._key_cache_ttl:
            del self._key_cache[kid]
            return None

        return key

    def _cache_key(self, kid: str, key: PyJWK) -> None:
        """Cache a key with current timestamp."""
        if not self._key_cache_enabled:
            return

        # Evict oldest if at capacity
        if len(self._key_cache) >= self._max_cached_keys and kid not in self._key_cache:
            # Simple eviction: remove oldest timestamp
            oldest_kid = min(self._key_cache.keys(),
                           key=lambda k: self._key_cache[k][1])
            del self._key_cache[oldest_kid]

        self._key_cache[kid] = (key, time.monotonic())

    def get_signing_key(self, kid: str) -> PyJWK:
        # Check TTL-aware cache first
        cached_key = self._get_cached_key(kid)
        if cached_key is not None:
            return cached_key

        signing_keys = self.get_signing_keys()
        signing_key = self.match_kid(signing_keys, kid)

        if not signing_key:
            signing_keys = self.get_signing_keys(refresh=True)
            signing_key = self.match_kid(signing_keys, kid)

            if not signing_key:
                raise PyJWKClientError(
                    f'Unable to find a signing key that matches: "{kid}"'
                )

        # Cache the key with TTL (not lru)
        self._cache_key(kid, signing_key)
        return signing_key

    def get_signing_key_from_jwt(self, token: str | bytes) -> PyJWK:
        unverified = decode_token(token, options={"verify_signature": False})
        header = unverified["header"]
        return self.get_signing_key(header.get("kid"))

    @staticmethod
    def match_kid(signing_keys: List[PyJWK], kid: str) -> Optional[PyJWK]:
        signing_key = None

        for key in signing_keys:
            if key.key_id == kid:
                signing_key = key
                break

        return signing_key
