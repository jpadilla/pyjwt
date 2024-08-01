from typing import Any, Callable, Dict, List, NotRequired, TypedDict

JWKDict = Dict[str, Any]

HashlibHash = Callable[..., Any]


# TODO: Make fields mandatory in PyJWT3
# See: https://peps.python.org/pep-0589/#inheritance
class JwtOptionsEncode(TypedDict):
    verify_signature: NotRequired[bool]
    verify_exp: NotRequired[bool]
    verify_nbf: NotRequired[bool]
    verify_iat: NotRequired[bool]
    verify_aud: NotRequired[bool]
    verify_iss: NotRequired[bool]
    require: NotRequired[List[str]]


class JwsOptions(TypedDict):
    verify_signature: NotRequired[bool]
