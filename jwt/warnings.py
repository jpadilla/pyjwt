class RemovedInPyjwt3Warning(DeprecationWarning):
    pass


class WeakKeyWarning(UserWarning):
    """
    Warning for when a cryptographically weak key is used for HMAC algorithms.
    This warning indicates that the key length is below the recommended minimum
    according to NIST SP 800-107.
    """
    pass
