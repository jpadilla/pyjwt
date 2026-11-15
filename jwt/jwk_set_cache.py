import time
from typing import Any, Optional, Union

from .api_jwk import PyJWKSet, PyJWTSetWithTimestamp
from .exceptions import PyJWKSetError


class JWKSetCache:
    def __init__(self, lifespan: float) -> None:
        self.jwk_set_with_timestamp: Optional[PyJWTSetWithTimestamp] = None
        self.lifespan = lifespan

    def put(self, jwk_set: Optional[Union[PyJWKSet, dict[str, Any]]]) -> None:
        """Cache *jwk_set*, or clear the cache when it is ``None``.

        Accepts either an already-parsed ``PyJWKSet`` or the raw JWKS
        payload it is parsed from, and always stores it parsed so that
        reads never have to parse the keys again.

        :raises PyJWKSetError: If *jwk_set* is neither a ``PyJWKSet`` nor a
            JWKS payload containing usable keys.
        """
        if jwk_set is None:
            # clear cache
            self.jwk_set_with_timestamp = None
            return

        if not isinstance(jwk_set, PyJWKSet):
            if not isinstance(jwk_set, dict):
                raise PyJWKSetError("Invalid JWK Set value")
            jwk_set = PyJWKSet.from_dict(jwk_set)

        self.jwk_set_with_timestamp = PyJWTSetWithTimestamp(jwk_set)

    def get(self, max_stale: float = 0) -> Optional[PyJWKSet]:
        """Return the cached ``PyJWKSet`` if it is not expired.

        Can return keys that are up to *max_stale* seconds
        past expiration. Returns ``None`` if the cache is empty
        or expired past *max_stale* tolerance.
        """
        if self.jwk_set_with_timestamp is None or self.is_expired(max_stale):
            return None

        return self.jwk_set_with_timestamp.get_jwk_set()

    def is_expired(self, max_stale: float = 0) -> bool:
        """Return whether the currently cached ``PyJWKSet`` is expired.

        Returns ``True`` if the cached ``PyJWKSet`` is more than
        *max_stale* seconds past its lifetime. Returns ``False``
        otherwise. Always returns ``False`` for a lifespan of ``-1``.
        """
        return (
            self.jwk_set_with_timestamp is not None
            and self.lifespan > -1
            and time.monotonic()
            > self.jwk_set_with_timestamp.get_timestamp() + self.lifespan + max_stale
        )
