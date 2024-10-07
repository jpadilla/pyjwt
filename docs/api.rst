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

.. function:: decode(jwt, key="", algorithms=None, options=None, audience=None, issuer=None, leeway=0)

    Verify the ``jwt`` token signature and return the token claims.

    :param str jwt: the token to be decoded
    :param key: the key suitable for the allowed algorithm
    :type key: str or bytes or jwt.PyJWK

    :param list algorithms: allowed algorithms, e.g. ``["ES256"]``
        If ``key`` is a :class:`jwt.PyJWK` object, allowed algorithms will default to the key algorithm.

        .. warning::

           Do **not** compute the ``algorithms`` parameter based on
           the ``alg`` from the token itself, or on any other data
           that an attacker may be able to influence, as that might
           expose you to various vulnerabilities (see `RFC 8725 §2.1
           <https://www.rfc-editor.org/rfc/rfc8725.html#section-2.1>`_). Instead,
           either hard-code a fixed value for ``algorithms``, or
           configure it in the same place you configure the
           ``key``. Make sure not to mix symmetric and asymmetric
           algorithms that interpret the ``key`` in different ways
           (e.g. HS\* and RS\*).

    :param dict options: extended decoding and validation options

        * ``verify_signature=True`` verify the JWT cryptographic signature
        * ``require=[]`` list of claims that must be present.
          Example: ``require=["exp", "iat", "nbf"]``.
          **Only verifies that the claims exists**. Does not verify that the claims are valid.
        * ``verify_aud=verify_signature`` check that ``aud`` (audience) claim matches ``audience``
        * ``verify_iss=verify_signature`` check that ``iss`` (issuer) claim matches ``issuer``
        * ``verify_exp=verify_signature`` check that ``exp`` (expiration) claim value is in the future
        * ``verify_iat=verify_signature`` check that ``iat`` (issued at) claim value is an integer
        * ``verify_nbf=verify_signature`` check that ``nbf`` (not before) claim value is in the past
        * ``strict_aud=False`` check that the ``aud`` claim is a single value (not a list), and matches ``audience`` exactly

        .. warning::

            ``exp``, ``iat`` and ``nbf`` will only be verified if present.
            Please pass respective value to ``require`` if you want to make
            sure that they are always present (and therefore always verified
            if ``verify_exp``, ``verify_iat``, and ``verify_nbf`` respectively
            is set to ``True``).

    :param audience: optional, the value for ``verify_aud`` check
    :type audience: Union[str, Iterable]
    :param str issuer: optional, the value for ``verify_iss`` check
    :param float leeway: a time margin in seconds for the expiration check
    :rtype: dict
    :returns: the JWT claims

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

.. function:: decode_complete(jwt, key="", algorithms=None, options=None, audience=None, issuer=None, leeway=0)

    Identical to ``jwt.decode`` except for return value which is a dictionary containing the token header (JOSE Header),
    the token payload (JWT Payload), and token signature (JWT Signature) on the keys "header", "payload",
    and "signature" respectively.

    :param str jwt: the token to be decoded
    :param str key: the key suitable for the allowed algorithm

    :param list algorithms: allowed algorithms, e.g. ``["ES256"]``

        .. warning::

           Do **not** compute the ``algorithms`` parameter based on
           the ``alg`` from the token itself, or on any other data
           that an attacker may be able to influence, as that might
           expose you to various vulnerabilities (see `RFC 8725 §2.1
           <https://www.rfc-editor.org/rfc/rfc8725.html#section-2.1>`_). Instead,
           either hard-code a fixed value for ``algorithms``, or
           configure it in the same place you configure the
           ``key``. Make sure not to mix symmetric and asymmetric
           algorithms that interpret the ``key`` in different ways
           (e.g. HS\* and RS\*).

    :param dict options: extended decoding and validation options

        * ``verify_signature=True`` verify the JWT cryptographic signature
        * ``require=[]`` list of claims that must be present.
          Example: ``require=["exp", "iat", "nbf"]``.
          **Only verifies that the claims exists**. Does not verify that the claims are valid.
        * ``verify_aud=verify_signature`` check that ``aud`` (audience) claim matches ``audience``
        * ``verify_iss=verify_signature`` check that ``iss`` (issuer) claim matches ``issuer``
        * ``verify_exp=verify_signature`` check that ``exp`` (expiration) claim value is in the future
        * ``verify_iat=verify_signature`` check that ``iat`` (issued at) claim value is an integer
        * ``verify_nbf=verify_signature`` check that ``nbf`` (not before) claim value is in the past
        * ``strict_aud=False`` check that the ``aud`` claim is a single value (not a list), and matches ``audience`` exactly

        .. warning::

            ``exp``, ``iat`` and ``nbf`` will only be verified if present.
            Please pass respective value to ``require`` if you want to make
            sure that they are always present (and therefore always verified
            if ``verify_exp``, ``verify_iat``, and ``verify_nbf`` respectively
            is set to ``True``).

    :param Iterable audience: optional, the value for ``verify_aud`` check
    :param str issuer: optional, the value for ``verify_iss`` check
    :param float leeway: a time margin in seconds for the expiration check
    :rtype: dict
    :returns: Decoded JWT with the JOSE Header on the key ``header``, the JWS
     Payload on the key ``payload``, and the JWS Signature on the key ``signature``.

.. note:: TODO: Document PyJWS class

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
