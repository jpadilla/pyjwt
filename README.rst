PyJWT
=====

.. image:: https://github.com/jpadilla/pyjwt/workflows/CI/badge.svg
   :target: https://github.com/jpadilla/pyjwt/actions?query=workflow%3ACI

.. image:: https://img.shields.io/pypi/v/pyjwt.svg
   :target: https://pypi.python.org/pypi/pyjwt

.. image:: https://codecov.io/gh/jpadilla/pyjwt/branch/master/graph/badge.svg
   :target: https://codecov.io/gh/jpadilla/pyjwt

.. image:: https://readthedocs.org/projects/pyjwt/badge/?version=stable
   :target: https://pyjwt.readthedocs.io/en/stable/

A Python implementation of `RFC 7519 <https://tools.ietf.org/html/rfc7519>`_. Original implementation was written by `@progrium <https://github.com/progrium>`_.

Security Notice
---------------

**CVE-2025-45768 Fixed in v2.10.2**: PyJWT now enforces minimum HMAC key lengths according to NIST SP 800-107:

- **HS256**: 32 bytes minimum (256 bits)
- **HS384**: 48 bytes minimum (384 bits)
- **HS512**: 64 bytes minimum (512 bits)

For enhanced security, enable strict validation:

.. code-block:: python

    import jwt

    # Strict mode (recommended for new applications)
    jwt_encoder = jwt.PyJWT(strict_key_validation=True)

    # Weak keys will raise InvalidKeyError
    try:
        jwt_encoder.encode({"data": "test"}, "weak", algorithm="HS256")
    except jwt.InvalidKeyError:
        print("Key too short - use at least 32 bytes for HS256")

Sponsor
-------

.. |auth0-logo| image:: https://github.com/user-attachments/assets/ee98379e-ee76-4bcb-943a-e25c4ea6d174
   :width: 160px

+--------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| |auth0-logo| | If you want to quickly add secure token-based authentication to Python projects, feel free to check Auth0's Python SDK and free plan at `auth0.com/signup <https://auth0.com/signup?utm_source=external_sites&utm_medium=pyjwt&utm_campaign=devn_signup>`_. |
+--------------+-----------------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

Installing
----------

Install with **pip**:

.. code-block:: console

    $ pip install PyJWT


Usage
-----

.. code-block:: pycon

    >>> import jwt
    >>> encoded = jwt.encode({"some": "payload"}, "secret", algorithm="HS256")
    >>> print(encoded)
    eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg
    >>> jwt.decode(encoded, "secret", algorithms=["HS256"])
    {'some': 'payload'}

Documentation
-------------

View the full docs online at https://pyjwt.readthedocs.io/en/stable/


Tests
-----

You can run tests from the project root after cloning with:

.. code-block:: console

    $ tox
