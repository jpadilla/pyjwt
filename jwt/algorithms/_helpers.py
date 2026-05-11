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
