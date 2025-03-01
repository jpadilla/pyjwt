from typing import Any, Callable, Dict, TypedDict

JWKDict = Dict[str, Any]

HashlibHash = Callable[..., Any]


class SigOptions(TypedDict):
    verify_signature: bool


class Options(TypedDict, total=False):
    verify_signature: bool
    require: list[str]
    strict_aud: bool
    verify_aud: bool
    verify_exp: bool
    verify_iat: bool
    verify_iss: bool
    verify_jti: bool
    verify_nbf: bool
    verify_sub: bool


# The only difference between Options and FullOptions is that FullOptions
# required _every_ value to be there; Options doesn't require any
class FullOptions(TypedDict):
    verify_signature: bool
    require: list[str]
    strict_aud: bool
    verify_aud: bool
    verify_exp: bool
    verify_iat: bool
    verify_iss: bool
    verify_jti: bool
    verify_nbf: bool
    verify_sub: bool
