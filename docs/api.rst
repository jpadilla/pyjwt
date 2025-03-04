API Reference
=============

.. module:: jwt

.. function:: encode(payload, key, algorithm="HS256", headers=None, json_encoder=None)

    Encode the ``payload`` as JSON Web Token.

    :param dict payload: JWT claims, e.g. ``dict(iss=..., aud=..., sub=...)``
    :param key: a key suitable for the chosen algorithm:

        * for **asymmetric algorithms**: PEM-formatted private key, a multiline string
        * for **symmetric algorithms**: plain string, sufficiently long for security

    :type key: str or bytes or jwt.PyJWK
    :param str algorithm: algorithm to sign the token with, e.g. ``"ES256"``.
        If ``headers`` includes ``alg``, it will be preferred to this parameter.
        If ``key`` is a :class:`jwt.PyJWK` object, by default the key algorithm will be used.
    :param dict headers: additional JWT header fields, e.g. ``dict(kid="my-key-id")``.
    :param json.JSONEncoder json_encoder: custom JSON encoder for ``payload`` and ``headers``
    :rtype: str
    :returns: a JSON Web Token

.. autofunction:: decode(jwt, key="", algorithms=None, options=None, audience=None, issuer=None, leeway=0) -> dict[str, typing.Any]

.. autoclass:: PyJWK
    :class-doc-from: init
    :members:

    .. property:: algorithm_name

        :type: str

        The name of the algorithm used by the key.

    .. property:: Algorithm

        The :py:class:`jwt.algorithms.Algorithm` class associated with the key.

.. module:: jwt.api_jwt

.. autofunction:: decode_complete(jwt, key="", algorithms=None, options=None, audience=None, issuer=None, leeway=0) -> dict[str, typing.Any]



.. note:: TODO: Document PyJWS class
.. module:: jwt.api_jws

.. autoclass:: jwt.api_jws.PyJWS
    :members:

.. module:: jwt.types
    :synopsis: Type validation used in the JWT API
.. autoclass:: jwt.types.SigOptions
    :members:
    :undoc-members:
.. autoclass:: jwt.types.Options
    :members:
    :undoc-members:

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

    Raised when a token's ``iat`` claim is non-numeric

.. class:: ImmatureSignatureError

    Raised when a token's ``nbf`` or ``iat`` claims represent a time in the future

.. class:: InvalidKeyError

    Raised when the specified key is not in the proper format

.. class:: InvalidAlgorithmError

    Raised when the specified algorithm is not recognized by PyJWT

.. class:: MissingRequiredClaimError

    Raised when a claim that is required to be present is not contained
    in the claimset
