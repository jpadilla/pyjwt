class PyJwtError(Exception):
    """
    Base class for all exceptions
    """
    pass


class InvalidTokenError(PyJwtError):
    pass


class DecodeError(InvalidTokenError):
    pass


class InvalidSignatureError(DecodeError):
    pass


class ExpiredSignatureError(InvalidTokenError):
    pass


class InvalidAudienceError(InvalidTokenError):
    pass


class InvalidIssuerError(InvalidTokenError):
    pass


class InvalidIssuedAtError(InvalidTokenError):
    pass


class ImmatureSignatureError(InvalidTokenError):
    pass


class InvalidKeyError(PyJwtError):
    pass


class InvalidAlgorithmError(InvalidTokenError):
    pass


class MissingRequiredClaimError(InvalidTokenError):
    def __init__(self, claim):
        self.claim = claim

    def __str__(self):
        return 'Token is missing the "%s" claim' % self.claim


# Compatibility aliases (deprecated)
ExpiredSignature = ExpiredSignatureError
InvalidAudience = InvalidAudienceError
InvalidIssuer = InvalidIssuerError
