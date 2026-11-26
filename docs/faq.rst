Frequently Asked Questions
==========================

How can I extract a public / private key from a x509 certificate?
-----------------------------------------------------------------

The ``load_pem_x509_certificate()`` function from ``cryptography`` can be used to
extract the public or private keys from a x509 certificate in PEM format.

.. code-block:: python

    from cryptography.x509 import load_pem_x509_certificate

    cert_str = b"-----BEGIN CERTIFICATE-----MIIDETCCAfm..."
    cert_obj = load_pem_x509_certificate(cert_str)
    public_key = cert_obj.public_key()
    private_key = cert_obj.private_key()

How do I migrate from ``python-jose`` to ``PyJWT``?
---------------------------------------------------

Most ``encode()`` and ``decode()`` calls translate directly, with a few key differences:

1. **Passing a JWK dictionary instead of a PEM string**

   ``PyJWT`` does not accept a raw JWK dictionary directly in ``jwt.decode()``.
   Convert the dictionary first with :meth:`jwt.PyJWK.from_dict` (requires ``cryptography`` for asymmetric algorithms such as ``RS256``):

   .. code-block:: python

       import jwt

       signing_key = jwt.PyJWK.from_dict(jwk_dict)
       payload = jwt.decode(token, signing_key, algorithms=["RS256"])

   If you have a full JWKS payload (``{"keys": [...]}``), use :class:`jwt.PyJWKSet` or :class:`jwt.PyJWKClient`.

2. **Reading claims or headers without verifying the signature**

   Replace ``jose.jwt.get_unverified_claims(token)`` with ``jwt.decode()`` and ``verify_signature`` disabled, and use :func:`jwt.get_unverified_header` for headers:

   .. code-block:: python

       import jwt

       header = jwt.get_unverified_header(token)
       claims = jwt.decode(token, options={"verify_signature": False})

   .. warning::

       Do not trust unverified claims for authentication or authorization decisions.

3. **Exception names**

   Replace ``jose.JWTError`` with :class:`jwt.PyJWTError` (base class for all PyJWT errors) or :class:`jwt.InvalidTokenError`.
   ``ExpiredSignatureError`` has the same name in both libraries (:class:`jwt.ExpiredSignatureError`).
