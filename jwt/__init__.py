# -*- coding: utf-8 -*-
# flake8: noqa

"""
JSON Web Token implementation

Minimum implementation based on this spec:
https://self-issued.info/docs/draft-jones-json-web-token-01.html
"""


__title__ = "pyjwt"
__version__ = "1.7.1"
__author__ = "José Padilla"
__license__ = "MIT"
__copyright__ = "Copyright 2015-2018 José Padilla"


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
    PyJWTError,
)
