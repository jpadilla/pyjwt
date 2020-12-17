API Reference
=============

.. module:: jwt

.. function:: encode(payload, key, algorithm="HS256", headers=None, json_encoder=None)

    Encode the ``payload`` as JSON Web Token.

    :param dict payload: JWT claims, e.g. ``dict(iss=..., aud=..., sub=...)``
    :param str key: a key suitable for the chosen algorithm:

        * for **asymmetric algorithms**: PEM-formatted private key, a multiline string
        * for **symmetric algorithms**: plain string, sufficiently long for security

    :param str algorithm: algorithm to sign the token with, e.g. ``"ES256"``
    :param dict headers: additional JWT header fields, e.g. ``dict(kid="my-key-id")``
    :param json.JSONEncoder json_encoder: custom JSON encoder for ``payload`` and ``headers``
    :rtype: str
    :returns: a JSON Web Token

.. function:: decode(jwt, key="", algorithms=None, options=None, audience=None, issuer=None, leeway=0)

    Verify the ``jwt`` token signature and return the token claims.

    :param str|bytes jwt: the token to be decoded
    :param str key: the key suitable for the allowed algorithm

    :param list algorithms: allowed algorithms, e.g. ``["ES256"]``

        .. note:: It is highly recommended to specify the expected ``algorithms``.

        .. note:: It is insecure to mix symmetric and asymmetric algorithms because they require different kinds of keys.

    :param dict options: extended decoding and validation options

        * ``require_exp=False`` check that ``exp`` (expiration) claim is present
        * ``require_iat=False`` check that ``iat`` (issued at) claim is present
        * ``require_nbf=False`` check that ``nbf`` (not before) claim is present
        * ``verify_aud=False`` check that ``aud`` (audience) claim matches ``audience``
        * ``verify_iat=False`` check that ``iat`` (issued at) claim value is an integer
        * ``verify_exp=False`` check that ``exp`` (expiration) claim value is OK
        * ``verify_iss=False`` check that ``iss`` (issuer) claim matches ``issuer``
        * ``verify_signature=True`` verify the JWT cryptographic signature

    :param iterable audience: optional, the value for ``verify_aud`` check
    :param str issuer: optional, the value for ``verify_iss`` check
    :param int|float leeway: a time margin in seconds for the expiration check
    :rtype: dict
    :returns: the JWT claims

.. note:: TODO: Document PyJWS / PyJWT classes

Exceptions
----------

.. currentmodule:: jwt.exceptions


.. class:: InvalidTokenError

    Base exception when ``decode()`` fails on a token

.. class:: DecodeError

    Raised when a token cannot be decoded because it failed validation

.. class:: InvalidSignatureError

    Raised when a token's signature doesn't match the one provided as part of
    the token.

.. class:: ExpiredSignatureError

    Raised when a token's ``exp`` claim indicates that it has expired

.. class:: InvalidAudienceError

    Raised when a token's ``aud`` claim does not match one of the expected
    audience values

.. class:: InvalidIssuerError

    Raised when a token's ``iss`` claim does not match the expected issuer

.. class:: InvalidIssuedAtError

    Raised when a token's ``iat`` claim is in the future

.. class:: ImmatureSignatureError

    Raised when a token's ``nbf`` claim represents a time in the future

.. class:: InvalidKeyError

    Raised when the specified key is not in the proper format

.. class:: InvalidAlgorithmError

    Raised when the specified algorithm is not recognized by PyJWT

.. class:: MissingRequiredClaimError

    Raised when a claim that is required to be present is not contained
    in the claimset
