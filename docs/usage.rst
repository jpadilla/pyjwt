Usage Examples
==============

Encoding & Decoding HS256 Tokens
---------------------------------

.. code-block:: python

    >>import jwt
    >>encoded = jwt.encode({'some': 'payload'}, 'secret', algorithm='HS256')
    >> encoded
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg'
    >> jwt.decode(encoded, 'secret', algorithms=['HS256'])
    {u'some': u'payload'}


Encoding & Decoding RS256 Tokens
---------------------------------

.. code-block:: python

    >> import jwt
    >> from cryptography.hazmat.backends import default_backend
    >> from cryptography.hazmat.primitives import serialization
    >> # openssl genrsa 1024 | tee private_key.pem
    >> private_key_pem = '''
    .. -----BEGIN RSA PRIVATE KEY-----
    .. MIICXgIBAAKBgQDBCeVu627zFZ1JH9/Wi/J/bs6zC3bUFl0ASfE6XHGxyPTAPXgJ
    .. nc7AsnRBxbNA692v1srkZr1X1BwUbzcaMRZwpGi4vO4VwzLldJC/YLFp5z6C66bg
    .. GvRrp5pQhu4ntuHR82yS2X/IBsmMArUug9mO/LyoGthqRBVic/a9l9+INQIDAQAB
    .. AoGBAIekj45waubuwjXW6u+UKRL4ZtAS9y2yhSklzBbpTI7TmX/X8Zg4RkbLXru0
    .. 0u+EjaL4eFskAlpL1mtZdsu1wICvyiFKuvh5WE+OwxBLpju/7AuZ9lCan9HR0X8P
    .. EXASwU8ZFGTbLWPJePeiWl41431EAZtq/cWDSB/RQeoa2mNBAkEA5OKP+uxjSH1o
    .. kCg+YqmlaakQ+2b8fS5J0ZyriVmoOAG0af647rsf4G3x3tXokoLXLn/620DE1HQ5
    .. fCqI7l2xhQJBANfoNwSAqMbrURS2g4X1F6t5kxqPW7QNYrqPiAwGeXrJlG0Y8U5v
    .. Yv73vRlnigdSJzTQOnY0FhniFWuScIdk4vECQG6iTLIfHQZnB+nWagFKuxfNjtXW
    .. O+lOPIRDVG75lWQs/sXVSBKtBIV431a00swuzlA9sEXWks2WuEqaTMHbK/kCQQCG
    .. 3uV3Z5OG5zp4EOcqCAeoM0LERadIW1BAMCcRM/4wyLlySTF8CLKziThUJUyg9B3P
    .. rP/IFRN1SbiNwSWQPmJRAkEAlBTPJeblIe0u/Zj8f4AKaSnKQXBvTwA3OP/FyjHR
    .. 8KaS4wpfYQvYuXZe6EDB6d6AxNxDuYn5T6D/qtVAR/eZWw==
    .. -----END RSA PRIVATE KEY-----
    .. '''
    >> private_key = serialization.load_pem_private_key(
    ..     private_key_pem,
    ..     password=None,
    ..     backend=default_backend())
    >> signed_jwt = jwt.encode({'another': 'payload'}, private_key, algorithm='RS256')
    >> signed_jwt
    'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhbm90aGVyIjoicGF5bG9hZCJ9.oRd6O1uZsyCSWnUoEpoE02Ad-114y-p8uraCCbptrfgJ-8WF4ZMCuFA6Lb1GB-NRZvxlEBA7j0OBX4w3Vi0frh0ClP-6fpSR4cWvsO3HBcO3Ahz2g9VqNvVW5pewJzvmqBzzUyrGOsu7CM-TFtRvXcXL2G716RT6n6eTBQgYUxs'
    >> # cat private_key.pem | openssl rsa -pubout | tee public_key.pem
    .. public_key_pem = '''
    .. -----BEGIN PUBLIC KEY-----
    .. MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBCeVu627zFZ1JH9/Wi/J/bs6z
    .. C3bUFl0ASfE6XHGxyPTAPXgJnc7AsnRBxbNA692v1srkZr1X1BwUbzcaMRZwpGi4
    .. vO4VwzLldJC/YLFp5z6C66bgGvRrp5pQhu4ntuHR82yS2X/IBsmMArUug9mO/Lyo
    .. GthqRBVic/a9l9+INQIDAQAB
    .. -----END PUBLIC KEY-----
    .. '''
    >> public_key = serialization.load_pem_public_key(
    ..     public_key_pem,
    ..     backend=default_backend())
    >> verified_jwt = jwt.decode(
    ..     signed_jwt,
    ..     public_key,
    ..     algorithms=['RS256'])
    >> verified_jwt
    {u'another': u'payload'}


Specifying Additional Headers
---------------------------------

.. code-block:: python

    >>jwt.encode({'some': 'payload'}, 'secret', algorithm='HS256', headers={'kid': '230498151c214b788dd97f22b85410a5'})
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjIzMDQ5ODE1MWMyMTRiNzg4ZGQ5N2YyMmI4NTQxMGE1In0.eyJzb21lIjoicGF5bG9hZCJ9.DogbDGmMHgA_bU05TAB-R6geQ2nMU2BRM-LnYEtefwg'


Reading the Claimset without Validation
-----------------------------------------

If you wish to read the claimset of a JWT without performing validation of the
signature or any of the registered claim names, you can set the ``verify``
parameter to ``False``.

Note: It is generally ill-advised to use this functionality unless you
clearly understand what you are doing. Without digital signature information,
the integrity or authenticity of the claimset cannot be trusted.

.. code-block:: python

    >>jwt.decode(encoded, verify=False)
    {u'some': u'payload'}

Registered Claim Names
----------------------

The JWT specificaftion defines some registered claim names and defines
how they should be used. PyJWT supports these registered claim names:

 - "exp" (Expiration Time) Claim
 - "nbf" (Not Before Time) Claim
 - "iss" (Issuer) Claim
 - "aud" (Audience) Claim
 - "iat" (Issued At) Claim

Expiration Time Claim (exp)
~~~~~~~~~~~~~~~~~~~~~~~~~~~

    The "exp" (expiration time) claim identifies the expiration time on
    or after which the JWT MUST NOT be accepted for processing.  The
    processing of the "exp" claim requires that the current date/time
    MUST be before the expiration date/time listed in the "exp" claim.
    Implementers MAY provide for some small leeway, usually no more than
    a few minutes, to account for clock skew.  Its value MUST be a number
    containing a NumericDate value.  Use of this claim is OPTIONAL.

You can pass the expiration time as a UTC UNIX timestamp (an int) or as a
datetime, which will be converted into an int. For example:

.. code-block:: python

    jwt.encode({'exp': 1371720939}, 'secret')
    jwt.encode({'exp': datetime.utcnow()}, 'secret')

Expiration time is automatically verified in `jwt.decode()` and raises
`jwt.ExpiredSignatureError` if the expiration time is in the past:

.. code-block:: python

    try:
        jwt.decode('JWT_STRING', 'secret')
    except jwt.ExpiredSignatureError:
        # Signature has expired

Expiration time will be compared to the current UTC time (as given by
`timegm(datetime.utcnow().utctimetuple())`), so be sure to use a UTC timestamp
or datetime in encoding.

You can turn off expiration time verification with the `verify_exp` parameter in the options argument.

PyJWT also supports the leeway part of the expiration time definition, which
means you can validate a expiration time which is in the past but not very far.
For example, if you have a JWT payload with a expiration time set to 30 seconds
after creation but you know that sometimes you will process it after 30 seconds,
you can set a leeway of 10 seconds in order to have some margin:

.. code-block:: python

    jwt_payload = jwt.encode({
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=30)
    }, 'secret')

    time.sleep(32)

    # JWT payload is now expired
    # But with some leeway, it will still validate
    jwt.decode(jwt_payload, 'secret', leeway=10)

Instead of specifying the leeway as a number of seconds, a `datetime.timedelta`
instance can be used. The last line in the example above is equivalent to:

.. code-block:: python

    jwt.decode(jwt_payload, 'secret', leeway=datetime.timedelta(seconds=10))

Not Before Time Claim (nbf)
~~~~~~~~~~~~~~~~~~~~~~~~~~~

    The "nbf" (not before) claim identifies the time before which the JWT
    MUST NOT be accepted for processing.  The processing of the "nbf"
    claim requires that the current date/time MUST be after or equal to
    the not-before date/time listed in the "nbf" claim.  Implementers MAY
    provide for some small leeway, usually no more than a few minutes, to
    account for clock skew.  Its value MUST be a number containing a
    NumericDate value.  Use of this claim is OPTIONAL.

The `nbf` claim works similarly to the `exp` claim above.

.. code-block:: python

    jwt.encode({'nbf': 1371720939}, 'secret')
    jwt.encode({'nbf': datetime.utcnow()}, 'secret')

Issuer Claim (iss)
~~~~~~~~~~~~~~~~~~

    The "iss" (issuer) claim identifies the principal that issued the
    JWT.  The processing of this claim is generally application specific.
    The "iss" value is a case-sensitive string containing a StringOrURI
    value.  Use of this claim is OPTIONAL.

.. code-block:: python

    payload = {
        'some': 'payload',
        'iss': 'urn:foo'
    }

    token = jwt.encode(payload, 'secret')
    decoded = jwt.decode(token, 'secret', issuer='urn:foo')

If the issuer claim is incorrect, `jwt.InvalidIssuerError` will be raised.

Audience Claim (aud)
~~~~~~~~~~~~~~~~~~~~

    The "aud" (audience) claim identifies the recipients that the JWT is
    intended for.  Each principal intended to process the JWT MUST
    identify itself with a value in the audience claim.  If the principal
    processing the claim does not identify itself with a value in the
    "aud" claim when this claim is present, then the JWT MUST be
    rejected.  In the general case, the "aud" value is an array of case-
    sensitive strings, each containing a StringOrURI value.  In the
    special case when the JWT has one audience, the "aud" value MAY be a
    single case-sensitive string containing a StringOrURI value.  The
    interpretation of audience values is generally application specific.
    Use of this claim is OPTIONAL.

.. code-block:: python

    payload = {
        'some': 'payload',
        'aud': 'urn:foo'
    }

    token = jwt.encode(payload, 'secret')
    decoded = jwt.decode(token, 'secret', audience='urn:foo')

If the audience claim is incorrect, `jwt.InvalidAudienceError` will be raised.

Issued At Claim (iat)
~~~~~~~~~~~~~~~~~~~~~

    The iat (issued at) claim identifies the time at which the JWT was issued.
    This claim can be used to determine the age of the JWT. Its value MUST be a
    number containing a NumericDate value. Use of this claim is OPTIONAL.

If the `iat` claim is in the future, an `jwt.InvalidIssuedAtError` exception
will be raised.

.. code-block:: python

    jwt.encode({'iat': 1371720939}, 'secret')
    jwt.encode({'iat': datetime.utcnow()}, 'secret')
