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


.. class:: PyJWK

  A class that represents a `JSON Web Key <https://www.rfc-editor.org/rfc/rfc7517>`_.

  .. method:: __init__(self, jwk_data, algorithm=None)

    :param dict data:  The decoded JWK data.
    :param algorithm:  The key algorithm.  If not specific, the key's ``alg`` will be used.
    :type algorithm: str or None

  .. staticmethod:: from_json(data, algorithm=None)

    :param str data: The JWK data, as a JSON string.
    :param algorithm:  The key algorithm.  If not specific, the key's ``alg`` will be used.
    :type algorithm: str or None

    :returntype: jwt.PyJWK

    Create a :class:`jwt.PyJWK` object from a JSON string.

  .. property:: algorithm_name

    :type: str

    The name of the algorithm used by the key.

  .. property:: Algorithm

    The ``Algorithm`` class associated with the key.

  .. property:: key_type

    :type: str or None

    The ``kty`` property from the JWK.

  .. property:: key_id

    :type: str or None

    The ``kid`` property from the JWK.

  .. property:: public_key_use

    :type: str or None

    The ``use`` property from the JWK.

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
