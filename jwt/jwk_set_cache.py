from typing import Optional
from datetime import datetime, timezone

from .api_jwk import PyJWKSet, PyJWTSetWithTimestamp


class JWKSetCache:
    def __init__(self, lifespan: int):
        self.jwk_set_with_timestamp = None
        self.lifespan = lifespan

    def put(self, jwk_set: PyJWKSet):
        if jwk_set is not None:
            self.jwk_set_with_timestamp = PyJWTSetWithTimestamp(jwk_set)
        else:
            # clear cache
            self.jwk_set_with_timestamp = None

    def get(self) -> Optional:
        if self.jwk_set_with_timestamp is None or self.is_expired():
            return None

        return self.jwk_set_with_timestamp.get_jwk_set()

    def is_expired(self) -> bool:
        return self.jwk_set_with_timestamp is not None \
               and self.lifespan > -1 \
               and datetime.now(timezone.utc) > self.jwk_set_with_timestamp.get_timestamp() + self.lifespan

