API Reference
=============

.. module:: jwt

TODO: Document PyJWS / PyJWT classes

Exceptions
----------

.. currentmodule:: jwt.exceptions


.. class:: InvalidTokenError

    Base exception when ``decode()`` fails on a token

.. class:: DecodeError

    Raised when a token cannot be decoded because it failed validation

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
