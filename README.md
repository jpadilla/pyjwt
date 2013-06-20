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

* HS256 - HMAC using SHA-256 hash algorithm (default)
* HS384 - HMAC using SHA-384 hash algorithm
* HS512 - HMAC using SHA-512 hash algorithm

Change the algorithm with by setting it in encode:

    jwt.encode({"some": "payload"}, "secret", "HS512")

Tests
-----

You can run tests from the project root after installed with:

    python tests/test_jwt.py

Support of reserved claim names
-------------------------------

Json Web Token defines some reserved claim names and defines how they should be used. PyJWT support theses reserved claim names:

 - "exp" (Expiration Time) Claim

Expiration Time Claim
=====================

From JWT RFC:

    The exp (expiration time) claim identifies the expiration time on or after which the JWT MUST NOT be accepted for processing. The processing of the exp claim requires that the current date/time MUST be before the expiration date/time listed in the exp claim. Implementers MAY provide for some small leeway, usually no more than a few minutes, to account for clock skew. Its value MUST be a number containing an IntDate value. Use of this claim is OPTIONAL.

You can pass the expiration time as a timestamp (an int) or as a datetime. Expiration time will be casted into a timestamp. For example:

    jwt.encode({"exp": 1371720939}, "secret")

    jwt.encode({"exp": datetime.utcnow()}, "secret")

Expiration time will be automatically verified in pyjwt.decode and raises a jwt.ExpiredSignature if expiration time is in past:

    import jwt
    try:
        jwt.decode('JWT_STRING', "secret")
    except jwt.ExpiredSignature:
        # Signature has expired

Expiration time will be compared to utc timestamp (as given by timegm(datetime.utcnow().utctimetuple())) so be sure to use utc timestamp or datetime in encoding.

You can turn off expiration time verification with verify_expiration argument.

Pyjwt also support the leeway part of expiration time definition, which means you can validate a expiration time which is in the past but no very far. For example, if you have a jwt payload with a expiration time set to 30 seconds after creation but you know that sometimes you will process it after 30 seconds, you can set a leeway of 10 seconds in order to have some margin:

    import jwt, time
    jwt_payload = jwt.encode({'exp': datetime.utcnow() + datetime.timedelta(seconds=30)}, 'secret')
    time.sleep(32)
    # Jwt payload is now expired
    # But with some leeway, it will be correclt validated
    jwt.decode(jwt_payload, 'secret', leeway=10)


License
-------

MIT
