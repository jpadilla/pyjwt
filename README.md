PyJWT
=====
A Python implementation of [JSON Web Token draft 01](http://self-issued.info/docs/draft-jones-json-web-token-01.html).

Installing
----------

    sudo easy_install PyJWT

Usage
-----

    import jwt
    jwt.encode({"some": "payload"}, "secret")

Note the resulting JWT will not be encrypted, but verifiable with a secret key.

    jwt.decode("someJWTstring", "secret")

If the secret is wrong, it will raise a `jwt.DecodeError` telling you as such. You can still get at the payload by setting the verify argument to false.

    jwt.decode("someJWTstring", verify=False)

Algorithms
----------

The JWT spec supports several algorithms for cryptographic signing. This library currently supports:

* HS256	- HMAC using SHA-256 hash algorithm (default)
* HS384	- HMAC using SHA-384 hash algorithm
* HS512 - HMAC using SHA-512 hash algorithm

Change the algorithm with by setting it in encode:

    jwt.encode({"some": "payload"}, "secret", "HS512")

Tests
-----

You can run tests from the project root after installed with:

    python tests/test_jwt.py

License
-------

MIT