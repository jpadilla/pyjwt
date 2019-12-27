# -*- coding: utf-8 -*-
# flake8: noqa

"""
JSON Web Token implementation

Minimum implementation based on this spec:
https://self-issued.info/docs/draft-jones-json-web-token-01.html
"""


__title__ = "pyjwt"
__version__ = "2.0.0.dev"
__author__ = "José Padilla"
__license__ = "MIT"
__copyright__ = "Copyright 2015-2020 José Padilla"


from .api_jws import PyJWS
from .api_jwt import (
    PyJWT,
    decode,
    encode,
    get_unverified_header,
    register_algorithm,
    unregister_algorithm,
)
from .exceptions import (
    DecodeError,
    ExpiredSignature,
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAlgorithmError,
    InvalidAudience,
    InvalidAudienceError,
    InvalidIssuedAtError,
    InvalidIssuer,
    InvalidIssuerError,
    InvalidSignatureError,
    InvalidTokenError,
    MissingRequiredClaimError,
    PyJWKClientError,
    PyJWKError,
    PyJWKSetError,
    PyJWTError,
)
from .jwks_client import PyJWKClient
