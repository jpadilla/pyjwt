# flake8: noqa

"""
JSON Web Token implementation

Minimum implementation based on this spec:
http://self-issued.info/docs/draft-jones-json-web-token-01.html
"""


from .__about__ import (
    __title__, __description__, __url__, __version__, __author__,
    __email__, __license__, __copyright__, __description__
)


from .api import encode, decode, register_algorithm
from .exceptions import (
    InvalidTokenError, DecodeError, ExpiredSignatureError,
    InvalidAudienceError, InvalidIssuerError
)
