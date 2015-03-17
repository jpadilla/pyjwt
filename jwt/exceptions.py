class InvalidTokenError(Exception):
    pass


class DecodeError(InvalidTokenError):
    pass


class ExpiredSignatureError(InvalidTokenError):
    pass


class InvalidAudienceError(InvalidTokenError):
    pass


class InvalidIssuerError(InvalidTokenError):
    pass


class InvalidAlgorithmError(Exception):
    pass


# Compatibility aliases (deprecated)
ExpiredSignature = ExpiredSignatureError
InvalidAudience = InvalidAudienceError
InvalidIssuer = InvalidIssuerError
