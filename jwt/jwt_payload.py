"""
= JWTPayload

A JWTPayload is the result of PyJWT.decode()

It
- is a dict (namely, the decoded payload)
- has signing_input, header, and signature as attributes
- exposes JWTPayload.compute_hash_digest(<string>)
  which selects a hash algo (and implementation) based on the header and uses
  it to compute a message digest


== Design Decision: Why JWTPayload?

This implementation path was chosen to handle a desire to support additional
verification of JWTs without changing the API of pyjwt to v2.0

Because JWTPayload inherits from dict, it behaves the same as the raw dict
objects that PyJWT.decode() used to return (prior to this addition). Unless you
check `type(PyJWT.decode()) is dict`, you likely won't see any change.

It exposes the information previously hidden by PyJWT.decode to allow complex
verification methods to be added to pyjwt client code (rather than baked into
pyjwt itself).

It also allows carefully selected methods (like compute_hash_digest) to be
exposed which are derived from these data.
"""
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend

    has_crypto = True
except ImportError:
    has_crypto = False


class JWTPayload(dict):
    """
    A decoded JWT payload.
    When treated directly as a dict, represents the JWT Payload (which is
    typically what clients want).

    :ivar signing_input: The signing input as a bytestring
    :ivar header: The JWT header as a **dict**
    :ivar signature: The JWT signature as a string
    """

    def __init__(
        self,
        jwt_api,
        payload,
        signing_input,
        header,
        signature,
        *args,
        **kwargs
    ):
        super(JWTPayload, self).__init__(payload, *args, **kwargs)
        self.signing_input = signing_input
        self.header = header
        self.signature = signature

        self._jwt_api = jwt_api

    def compute_hash_digest(self, bytestr):
        """
        Given a bytestring, compute a hash digest of the bytestring and
        return it, using the algorithm specified by the JWT header.

        When `cryptography` is present, it will be used.

        This method is necessary in order to support computation of the OIDC
        at_hash claim.
        """
        algorithm = self.header.get("alg")
        alg_obj = self._jwt_api.get_algo_by_name(algorithm)
        hash_alg = alg_obj.hash_alg

        if has_crypto and (
            isinstance(hash_alg, type)
            and issubclass(hash_alg, hashes.HashAlgorithm)
        ):
            digest = hashes.Hash(hash_alg(), backend=default_backend())
            digest.update(bytestr)
            return digest.finalize()
        else:
            return hash_alg(bytestr).digest()
