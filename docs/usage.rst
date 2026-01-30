Usage Examples
==============

Encoding & Decoding Tokens with HS256
-------------------------------------

.. code-block:: pycon

    >>> import jwt
    >>> key = "secret"
    >>> encoded = jwt.encode({"some": "payload"}, key, algorithm="HS256")
    >>> jwt.decode(encoded, key, algorithms="HS256")
    {'some': 'payload'}

Encoding & Decoding Tokens with RS256 (RSA)
-------------------------------------------

RSA encoding and decoding require the ``cryptography`` module. See :ref:`installation_cryptography`.

.. code-block:: pycon

    >>> import jwt
    >>> private_key = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAwhvqCC+37A+UXgcvDl+7nbVjDI3QErdZBkI1VypVBMkKKWHM\nNLMdHk0bIKL+1aDYTRRsCKBy9ZmSSX1pwQlO/3+gRs/MWG27gdRNtf57uLk1+lQI\n6hBDozuyBR0YayQDIx6VsmpBn3Y8LS13p4pTBvirlsdX+jXrbOEaQphn0OdQo0WD\noOwwsPCNCKoIMbUOtUCowvjesFXlWkwG1zeMzlD1aDDS478PDZdckPjT96ICzqe4\nO1Ok6fRGnor2UTmuPy0f1tI0F7Ol5DHAD6pZbkhB70aTBuWDGLDR0iLenzyQecmD\n4aU19r1XC9AHsVbQzxHrP8FveZGlV/nJOBJwFwIDAQABAoIBAFCVFBA39yvJv/dV\nFiTqe1HahnckvFe4w/2EKO65xTfKWiyZzBOotBLrQbLH1/FJ5+H/82WVboQlMATQ\nSsH3olMRYbFj/NpNG8WnJGfEcQpb4Vu93UGGZP3z/1B+Jq/78E15Gf5KfFm91PeQ\nY5crJpLDU0CyGwTls4ms3aD98kNXuxhCGVbje5lCARizNKfm/+2qsnTYfKnAzN+n\nnm0WCjcHmvGYO8kGHWbFWMWvIlkoZ5YubSX2raNeg+YdMJUHz2ej1ocfW0A8/tmL\nwtFoBSuBe1Z2ykhX4t6mRHp0airhyc+MO0bIlW61vU/cPGPos16PoS7/V08S7ZED\nX64rkyECgYEA4iqeJZqny/PjOcYRuVOHBU9nEbsr2VJIf34/I9hta/mRq8hPxOdD\n/7ES/ZTZynTMnOdKht19Fi73Sf28NYE83y5WjGJV/JNj5uq2mLR7t2R0ZV8uK8tU\n4RR6b2bHBbhVLXZ9gqWtu9bWtsxWOkG1bs0iONgD3k5oZCXp+IWuklECgYEA27bA\n7UW+iBeB/2z4x1p/0wY+whBOtIUiZy6YCAOv/HtqppsUJM+W9GeaiMpPHlwDUWxr\n4xr6GbJSHrspkMtkX5bL9e7+9zBguqG5SiQVIzuues9Jio3ZHG1N2aNrr87+wMiB\nxX6Cyi0x1asmsmIBO7MdP/tSNB2ebr8qM6/6mecCgYBA82ZJfFm1+8uEuvo6E9/R\nyZTbBbq5BaVmX9Y4MB50hM6t26/050mi87J1err1Jofgg5fmlVMn/MLtz92uK/hU\nS9V1KYRyLc3h8gQQZLym1UWMG0KCNzmgDiZ/Oa/sV5y2mrG+xF/ZcwBkrNgSkO5O\n7MBoPLkXrcLTCARiZ9nTkQKBgQCsaBGnnkzOObQWnIny1L7s9j+UxHseCEJguR0v\nXMVh1+5uYc5CvGp1yj5nDGldJ1KrN+rIwMh0FYt+9dq99fwDTi8qAqoridi9Wl4t\nIXc8uH5HfBT3FivBtLucBjJgOIuK90ttj8JNp30tbynkXCcfk4NmS23L21oRCQyy\nlmqNDQKBgQDRvzEB26isJBr7/fwS0QbuIlgzEZ9T3ZkrGTFQNfUJZWcUllYI0ptv\ny7ShHOqyvjsC3LPrKGyEjeufaM5J8EFrqwtx6UB/tkGJ2bmd1YwOWFHvfHgHCZLP\n34ZNURCvxRV9ZojS1zmDRBJrSo7+/K0t28hXbiaTOjJA18XAyyWmGg==\n-----END RSA PRIVATE KEY-----\n"
    >>> public_key = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwhvqCC+37A+UXgcvDl+7\nnbVjDI3QErdZBkI1VypVBMkKKWHMNLMdHk0bIKL+1aDYTRRsCKBy9ZmSSX1pwQlO\n/3+gRs/MWG27gdRNtf57uLk1+lQI6hBDozuyBR0YayQDIx6VsmpBn3Y8LS13p4pT\nBvirlsdX+jXrbOEaQphn0OdQo0WDoOwwsPCNCKoIMbUOtUCowvjesFXlWkwG1zeM\nzlD1aDDS478PDZdckPjT96ICzqe4O1Ok6fRGnor2UTmuPy0f1tI0F7Ol5DHAD6pZ\nbkhB70aTBuWDGLDR0iLenzyQecmD4aU19r1XC9AHsVbQzxHrP8FveZGlV/nJOBJw\nFwIDAQAB\n-----END PUBLIC KEY-----\n"
    >>> encoded = jwt.encode({"some": "payload"}, private_key, algorithm="RS256")
    >>> jwt.decode(encoded, public_key, algorithms=["RS256"])
    {'some': 'payload'}

If your private key needs a passphrase, you need to pass in a ``PrivateKey`` object from ``cryptography``.

.. code-block:: python

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend

    pem_bytes = b"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,C9C8F89EC68D15F26EB9B9695216C6DC\nE3lvX0dYjDxC0DIDitwNj+mEvU48Cqlp9esIeVmfcFmM6KpuQEA4asg/19kldbRq\ntOAYwmMuzz6GNYtX6sQXcStUE3pKMiMaTuP9WXzTc0boSYsGpGoQLtGv3h+0lkPu\nTGaktEhIfplAYlmsS/twr9Jh9QZjEs3dEMwpuF8A/iDZFeIE2thZL0bo38VWorgZ\nTCoOlC7qGtaeDvXXYrMvAUw3lN9A+DvxuPvbGqfqiHVBhxRcQEcR5p65lKP/V0WQ\nDe0AqCx1ghYGnExT7I4GLfr7Ux3F1UcVldPPsNeCTR/5YMOYDw7o5CZZ2TM39T33\nDBwfRhDqKe4bMUQcvcD54S2tfW7tEekm6mx5JwzW11sd0Gprj2uggDTOj3ce2yzM\nzl/dfbyFgh6v4jFeblIgvQ4VPg9nfCaRhatw5KXnfHBvmvdxlQ1Qp5P43ThXjI2a\njaJdm2lu1DLhf1OYGeQ0ytDDPzvhrZrdEJ8jbB3VCn4O/hvCtdsp7jVw2Djxmw2A\niRz2zlZJUlaytbi/DMpEVFwIzpuiDkpJ+ekzAsBbm/rGR/tjCEtHzVuoQNUWI93k\n0FML+Zzb6AkBWYjBXDZtzwJpMdNr8Vvh3krZySbRzQstqL2PYuNoSZ8/1xnnVqTV\nA0pDX7OS856AXQzQ1FRjjk/Jd0k6jGj8d7LzVgMnb8VknKvshlLmZDz8Sqa1coN4\n0Z1VfiT0Hzlk0fkoGtRjhSc3MB6ZLg7vVlY5vb4bRrTX79s/p8Y/OecYnGC6qhTi\n+VyJiMfwXyjFjIWYH8Y3G0QLkvOrTxLAY/3B2TU5wVSD7lfnPKOatMK1W0DHu5jp\nG9PPTzK9ol3v6Pk0prYg1fiApb6CCBUeZBvCIbJCzYrL/yBV/xYlCwAekLNGz9Vj\nNQUoiJqi27fOQi+ZXCrF7gYj8afo/xrg0tf7YqoOty8qfsozXzqwHKn+PcZOcqa5\n5rIqjLOO2f6KO2dxBeZK6zmzg7K/8RjvsNkEuXffec/nwnC10OVoMbE4wyPmNUQi\ndSuZ6xWBqiREjodLL+Ez/N1Qa52kuLSigrrSBTM2e42PWDV1sNW5V2wwlnolXFF6\n2Xp74WaGdnwF4Afrm7AnaBxdmfjk/a+c2uzPkZkpVnxrW3l8afphhKpRoTLzqDPp\nZGc5Fx9UZsmX18B8D1OGbf4aVLUkoqPPHbccCI+wByoAgIoq+y2391fP/Db6fY9A\nR4t2uuP2sNqDfYtzPYikePBXhYlldE1UHJ378g8pTiRHOI9BhuKIOIbVngPUYk4I\nwhYct2K84HjvR3iRnobK0UmmNOqtK0AtUqne+xaj1f3OwMZSvTUe7/jESgw1e1tn\nulKiWnKnmTSZkeTIp6itui2T7ewfNyitPtvnhoH1fBnMyUVACip0SLXp1fwQ7iCc\namPFFKo7p+C7P3l0ItegaMHywOSTBvK39DQTIpF9ml8VCQ+UyPOv/LnSJk1mbJN/\nc2Hdoj5dMa6T7ysIwZGEissJ/MEP+dpRs7VmCjWrHCDHfeAIO0n32g4zbzlNc/OA\nIdCXTvi4xUEn2n3JPt5Ba9qDUevaHSERlLxI+9a4ZaZeg4t+AzY0ur6+RWx+PaXB\n-----END RSA PRIVATE KEY-----\n"
    passphrase = b"abc123"

    private_key = serialization.load_pem_private_key(
        pem_bytes, password=passphrase, backend=default_backend()
    )
    encoded = jwt.encode({"some": "payload"}, private_key, algorithm="RS256")

If you are repeatedly encoding with the same private key, reusing the same
``RSAPrivateKey`` also has performance benefits because it avoids the
CPU-intensive ``RSA_check_key`` primality test.

Encoding & Decoding Tokens with PS256 (RSA)
-------------------------------------------

RSA encoding and decoding require the ``cryptography`` module. See :ref:`installation_cryptography`.

.. code-block:: pycon

    >>> import jwt
    >>> private_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEAuNhCS6bodtd+PvKqNj+tYZYqTNMDkf0rcptgHhecSsMP9Vay\n+6NvJk1tC+IajPaE4yRJVY4jFqEt3A0MJ9sKe5mWDYFmzW/L6VzQvQ+0nrMc1YTE\nDpOf7BQhlW5W0mDj5SwSR50Lxg/acb+SMWq6zmhuAoLRapH17K2RWONA2vr2frox\nJ6N9TGtrQHygDb0p9D6jPnXEe4y+zBuj6o0bCkJgCVNM+CU19xBepj5caetYV28/\n49yl5XPi93n1ATU+7aGAKxuvjudODuHhF/UsZScMFSHeZW367eQldTB2w9uoIIzW\nO46tKimr21zYifMimjwnBQ/PLDqc7HqY0Y/rLQIDAQABAoIBAAdu0CD7/Iu61/LE\nDfV8fgZXOYA5WVgSLCBsVbh1Y+2FsStBFJVrLwRanLCbo6GuJWMqNGC3ryWGebJI\nPAg7lfepEhBHodClAY1yvq9mOvHJa2Fn+KegEWWMMbAxQwCBW5NS6waXhBUE0i3n\ncYOB3TKA9IYuqH52kW22VQqT/imlWEb28pJJT49YfggmOOtAkrKerokO53lAfrJA\ntm8lYvxXnfnuYh7zI835RpZJ1PeaYrMqyAwT+StD9hPKGWGpN1gCJijjcK0aapvq\nMLET/JxMxxcLsINOeLtGhMKawmET3J/esJTumOE2L77MFG83rlCPbsSfLdSAI2WD\nSe3Q2ikCgYEA7JzmVrPh7G/oILLzIfk8GHFACRTtlE5SDEpFq+ARMprfcBXpkl+Q\naWqQ3vuSH7oiAQKlvo3We6XXohCMMDU2DyMaXiQMk73R83fMwbFnFcqFhbzx2zpm\nj/neHIViEi/N69SHPxl+vnUTfeVZptibNGS+ch3Ubawt3wCaWr+IdAcCgYEAx/19\ns5ryq2oTQCD5GfIqW73LAUly5RqENLvKHZ2z+mZ0pp7dc5449aDsHPLXLl1YC3mO\nlZZk+8Jh5yrpHyljiIYwh/1y0WsbungMlH6lG9JigcN8R2Tk9hWT7DQL0fm0dYoQ\njkwr/gJv6PW0piLsR0vsQQpm/F/ucZolVPQIoisCgYA5XXzWznvax/LeYqRhuzxf\nrK1axlEnYKmxwxwLJKLmwvejBB0B2Nt5Q1XmSdXOjWELH6oxfc/fYIDcEOj8ExqN\nJvSQmGrYMvBA9+2TlEAq31Pp7boxbYJKK8k23vu87wwcvgUgPj0lTdsw7bcDpYZT\neI1Xu3WyNUlVxJ6nm8IoZwKBgG6YPjVekKg+htrF4Tt58fa95E+X4JPVsBrBZqou\nFeN5WTTzUZ+odfNPxILVwC2BrTjbRgBvJPUcr6t4zWZQKxzKqHfrrt0kkDb0QHC2\nAHR8ScFc65NHtl5n3F+ZAJhjsGn3qeQnN4TGsEBx8C6XzXY4BDSLnhweqOvlxJNQ\nSJ31AoGAX/UN5xR6PlCgPw5HWfGd7+4sArkjA36DAXvrAgW/6/mxZZzoGA1swYdZ\nq2uGp38UEKkxKTrhR4J6eR5DsLAfl/KQBbNC42vqZwe9YrS4hNQFR14GwlyJhdLx\nKQD/JzHwNQN5+o+hy0lJavTw9NwAAb1ZzTgvq6fPwEG0b9hn0SI=\n-----END RSA PRIVATE KEY-----\n"
    >>> public_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuNhCS6bodtd+PvKqNj+t\nYZYqTNMDkf0rcptgHhecSsMP9Vay+6NvJk1tC+IajPaE4yRJVY4jFqEt3A0MJ9sK\ne5mWDYFmzW/L6VzQvQ+0nrMc1YTEDpOf7BQhlW5W0mDj5SwSR50Lxg/acb+SMWq6\nzmhuAoLRapH17K2RWONA2vr2froxJ6N9TGtrQHygDb0p9D6jPnXEe4y+zBuj6o0b\nCkJgCVNM+CU19xBepj5caetYV28/49yl5XPi93n1ATU+7aGAKxuvjudODuHhF/Us\nZScMFSHeZW367eQldTB2w9uoIIzWO46tKimr21zYifMimjwnBQ/PLDqc7HqY0Y/r\nLQIDAQAB\n-----END PUBLIC KEY-----\n"
    >>> encoded = jwt.encode({"some": "payload"}, private_key, algorithm="PS256")
    >>> jwt.decode(encoded, public_key, algorithms=["PS256"])
    {'some': 'payload'}

Encoding & Decoding Tokens with EdDSA (Ed25519)
-----------------------------------------------

EdDSA encoding and decoding require the ``cryptography`` module. See :ref:`installation_cryptography`.

.. code-block:: pycon

    >>> import jwt
    >>> private_key = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIPtUxyxlhjOWetjIYmc98dmB2GxpeaMPP64qBhZmG13r\n-----END PRIVATE KEY-----\n"
    >>> public_key = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA7p4c1IU6aA65FWn6YZ+Bya5dRbfd4P6d4a6H0u9+gCg=\n-----END PUBLIC KEY-----\n"
    >>> encoded = jwt.encode({"some": "payload"}, private_key, algorithm="EdDSA")
    >>> jwt.decode(encoded, public_key, algorithms=["EdDSA"])
    {'some': 'payload'}

Encoding & Decoding Tokens with ES256 (ECDSA)
---------------------------------------------

ECDSA encoding and decoding require the ``cryptography`` module. See :ref:`installation_cryptography`.

.. code-block:: pycon

    >>> import jwt
    >>> private_key = b"-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIHAhM7P6HG3LgkDvgvfDeaMA6uELj+jEKWsSeOpS/SfYoAoGCCqGSM49\nAwEHoUQDQgAEXHVxB7s5SR7I9cWwry/JkECIRekaCwG3uOLCYbw5gVzn4dRmwMyY\nUJFcQWuFSfECRK+uQOOXD0YSEucBq0p5tA==\n-----END EC PRIVATE KEY-----\n"
    >>> public_key = b"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXHVxB7s5SR7I9cWwry/JkECIReka\nCwG3uOLCYbw5gVzn4dRmwMyYUJFcQWuFSfECRK+uQOOXD0YSEucBq0p5tA==\n-----END PUBLIC KEY-----\n"
    >>> encoded = jwt.encode({"some": "payload"}, private_key, algorithm="ES256")
    >>> jwt.decode(encoded, public_key, algorithms=["ES256"])
    {'some': 'payload'}


Specifying Additional Headers
-----------------------------

.. code-block:: pycon

    >>> jwt.encode(
    ...     {"some": "payload"},
    ...     "secret",
    ...     algorithm="HS256",
    ...     headers={"kid": "230498151c214b788dd97f22b85410a5"},
    ... )
    'eyJhbGciOiJIUzI1NiIsImtpZCI6IjIzMDQ5ODE1MWMyMTRiNzg4ZGQ5N2YyMmI4NTQxMGE1IiwidHlwIjoiSldUIn0.eyJzb21lIjoicGF5bG9hZCJ9.0n16c-shKKnw6gervyk1Dge35tvzbzQ_KCV3H3bgoJ0'


By default the ``typ`` is attaching to the headers. In case when you don't need to pass this header to the token, you have to explicitly null it.

.. code-block:: pycon

    >>> jwt.encode(
    ...     {"some": "payload"},
    ...     "secret",
    ...     algorithm="HS256",
    ...     headers={"typ": None},
    ... )  # doctest: +ELLIPSIS
    'eyJhbGciOiJIUzI1NiJ9.eyJzb21lIjoicGF5bG9hZCJ9...'

Reading the Claimset without Validation
---------------------------------------

If you wish to read the claimset of a JWT without performing validation of the
signature or any of the registered claim names, you can set the
``verify_signature`` option to ``False``.

Note: It is generally ill-advised to use this functionality unless you
clearly understand what you are doing. Without digital signature information,
the integrity or authenticity of the claimset cannot be trusted.

.. code-block:: pycon

    >>> jwt.decode(encoded, options={"verify_signature": False})
    {'some': 'payload'}

Reading Headers without Validation
----------------------------------

Some APIs require you to read a JWT header without validation. For example,
in situations where the token issuer uses multiple keys and you have no
way of knowing in advance which one of the issuer's public keys or shared
secrets to use for validation, the issuer may include an identifier for the
key in the header.

.. code-block:: pycon

    >>> encoded = jwt.encode(
    ...     {"some": "payload"},
    ...     "secret",
    ...     algorithm="HS256",
    ...     headers={"kid": "230498151c214b788dd97f22b85410a5"},
    ... )
    >>> jwt.get_unverified_header(encoded)
    {'alg': 'HS256', 'kid': '230498151c214b788dd97f22b85410a5', 'typ': 'JWT'}

Registered Claim Names
----------------------

The JWT specification defines some registered claim names and defines
how they should be used. PyJWT supports these registered claim names:

 - "exp" (Expiration Time) Claim
 - "nbf" (Not Before Time) Claim
 - "iss" (Issuer) Claim
 - "aud" (Audience) Claim
 - "iat" (Issued At) Claim
 - "sub" (Subject) Claim
 - "jti" (JWT ID) Claim

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

.. code-block:: pycon

    >>> from datetime import datetime, timezone
    >>> token = jwt.encode({"exp": 1371720939}, "secret")
    >>> token = jwt.encode({"exp": datetime.now(tz=timezone.utc)}, "secret")

Expiration time is automatically verified in `jwt.decode()` and raises
`jwt.ExpiredSignatureError` if the expiration time is in the past:

.. code-block:: pycon

    >>> try:
    ...     jwt.decode(token, "secret", algorithms=["HS256"])
    ... except jwt.ExpiredSignatureError:
    ...     print("expired")
    ...
    expired

Expiration time will be compared to the current UTC time (as given by
`timegm(datetime.now(tz=timezone.utc).utctimetuple())`), so be sure to use a UTC timestamp
or datetime in encoding.

You can turn off expiration time verification with the `verify_exp` parameter in the options argument.

PyJWT also supports the leeway part of the expiration time definition, which
means you can validate a expiration time which is in the past but not very far.
For example, if you have a JWT payload with a expiration time set to 30 seconds
after creation but you know that sometimes you will process it after 30 seconds,
you can set a leeway of 5 seconds in order to have some margin:

.. code-block:: pycon

    >>> import time, datetime
    >>> from datetime import timezone
    >>> payload = {
    ...     "exp": datetime.datetime.now(tz=timezone.utc) + datetime.timedelta(seconds=1)
    ... }
    >>> token = jwt.encode(payload, "secret")
    >>> time.sleep(2)
    >>> # JWT payload is now expired
    >>> # But with some leeway, it will still validate
    >>> decoded = jwt.decode(token, "secret", leeway=5, algorithms=["HS256"])

Instead of specifying the leeway as a number of seconds, a `datetime.timedelta`
instance can be used. The last line in the example above is equivalent to:

.. code-block:: pycon

    >>> decoded = jwt.decode(
    ...     token, "secret", leeway=datetime.timedelta(seconds=5), algorithms=["HS256"]
    ... )

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

.. code-block:: pycon

    >>> token = jwt.encode({"nbf": 1371720939}, "secret")
    >>> token = jwt.encode({"nbf": datetime.datetime.now(tz=timezone.utc)}, "secret")

The `nbf` claim also supports the leeway feature similar to the `exp` claim. This
allows you to validate a “not before” time that is slightly in the future. Using
leeway with the nbf claim can be particularly helpful in scenarios where clock
synchronization between the token issuer and the validator is imprecise.

.. code-block:: pycon

    >>> import time, datetime
    >>> from datetime import timezone
    >>> payload = {
    ...     "nbf": datetime.datetime.now(tz=timezone.utc) - datetime.timedelta(seconds=3)
    ... }
    >>> token = jwt.encode(payload, "secret")
    >>> # JWT payload is not valid yet
    >>> # But with some leeway, it will still validate
    >>> decoded = jwt.decode(token, "secret", leeway=5, algorithms=["HS256"])


Issuer Claim (iss)
~~~~~~~~~~~~~~~~~~

    The "iss" (issuer) claim identifies the principal that issued the
    JWT.  The processing of this claim is generally application specific.
    The "iss" value is a case-sensitive string containing a StringOrURI
    value.  Use of this claim is OPTIONAL.

.. code-block:: pycon

    >>> payload = {"some": "payload", "iss": "urn:foo"}
    >>> token = jwt.encode(payload, "secret")
    >>> try:
    ...     jwt.decode(token, "secret", issuer="urn:invalid", algorithms=["HS256"])
    ... except jwt.InvalidIssuerError:
    ...     print("invalid issuer")
    ...
    invalid issuer

If the issuer claim is incorrect, `jwt.InvalidIssuerError` will be raised.

Audience Claim (aud)
~~~~~~~~~~~~~~~~~~~~

    The "aud" (audience) claim identifies the recipients that the JWT is
    intended for.  Each principal intended to process the JWT MUST
    identify itself with a value in the audience claim.  If the principal
    processing the claim does not identify itself with a value in the
    "aud" claim when this claim is present, then the JWT MUST be
    rejected.

In the general case, the "aud" value is an array of case-
sensitive strings, each containing a StringOrURI value.

.. code-block:: pycon

    >>> payload = {"some": "payload", "aud": ["urn:foo", "urn:bar"]}
    >>> token = jwt.encode(payload, "secret")
    >>> decoded = jwt.decode(token, "secret", audience="urn:foo", algorithms=["HS256"])
    >>> decoded = jwt.decode(token, "secret", audience="urn:bar", algorithms=["HS256"])

In the special case when the JWT has one audience, the "aud" value MAY be
a single case-sensitive string containing a StringOrURI value.

.. code-block:: pycon

    >>> payload = {"some": "payload", "aud": "urn:foo"}
    >>> token = jwt.encode(payload, "secret")
    >>> decoded = jwt.decode(token, "secret", audience="urn:foo", algorithms=["HS256"])

If multiple audiences are accepted, the ``audience`` parameter for
``jwt.decode`` can also be an iterable

.. code-block:: pycon

    >>> payload = {"some": "payload", "aud": "urn:foo"}
    >>> token = jwt.encode(payload, "secret")
    >>> decoded = jwt.decode(
    ...     token, "secret", audience=["urn:foo", "urn:bar"], algorithms=["HS256"]
    ... )
    >>> try:
    ...     jwt.decode(token, "secret", audience=["urn:invalid"], algorithms=["HS256"])
    ... except jwt.InvalidAudienceError:
    ...     print("invalid audience")
    ...
    invalid audience

The interpretation of audience values is generally application specific.
Use of this claim is OPTIONAL.

If the audience claim is incorrect, `jwt.InvalidAudienceError` will be raised.

Issued At Claim (iat)
~~~~~~~~~~~~~~~~~~~~~

    The iat (issued at) claim identifies the time at which the JWT was issued.
    This claim can be used to determine the age of the JWT. Its value MUST be a
    number containing a NumericDate value. Use of this claim is OPTIONAL.

    If the `iat` claim is not a number, an `jwt.InvalidIssuedAtError` exception will be raised.

.. code-block:: pycon

    >>> token = jwt.encode({"iat": 1371720939}, "secret")
    >>> token = jwt.encode({"iat": datetime.datetime.now(tz=timezone.utc)}, "secret")

Subject Claim (sub)
~~~~~~~~~~~~~~~~~~~

    The "sub" (subject) claim identifies the principal that is the subject of the JWT.
    The subject value MUST either be scoped to be locally unique in the context of the issuer or be globally unique.
    Use of this claim is OPTIONAL.

.. code-block:: pycon

    >>> payload = {"some": "payload", "sub": "1234567890"}
    >>> token = jwt.encode(payload, "secret")
    >>> decoded = jwt.decode(token, "secret", algorithms=["HS256"])
    >>> decoded["sub"]
    '1234567890'

Think of the `sub` claim as the **"who"** of the JWT.
It identifies the subject of the token — the user or entity that the token is about.
The claims inside a JWT are essentially statements about this subject.

For example, if you have a JWT for a logged-in user, the `sub` claim would typically be their unique user ID, like `1234567890`.
This value needs to be unique within your application's context so you can reliably identify who the token belongs to.
While the `sub` claim is optional, it's a fundamental part of most JWT-based authentication systems.

JWT ID Claim (jti)
~~~~~~~~~~~~~~~~~~

    The "jti" (JWT ID) claim provides a unique identifier for the JWT.
    The identifier value MUST be assigned in a manner that ensures that there is a negligible probability that the same value will be accidentally assigned to a different data object.
    If the application uses multiple issuers, collisions MUST be prevented among values produced by different issuers as well.
    The "jti" value is a case-sensitive string.
    Use of this claim is OPTIONAL.

.. code-block:: pycon

    >>> import uuid
    >>> payload = {"some": "payload", "jti": str(uuid.uuid4())}
    >>> token = jwt.encode(payload, "secret")
    >>> decoded = jwt.decode(token, "secret", algorithms=["HS256"])
    >>> decoded["jti"]  # doctest: +SKIP
    '3fa85f64-5717-4562-b3fc-2c963f66afa6'

The `jti` claim is giving your JWT a unique identifier.
Think of it like a serial number for the token.
This ID must be assigned in a way that makes it virtually impossible for two different tokens to have the same `jti` value.
A common practice is to use a Universally Unique Identifier (UUID).

The `jti` claim is used to **prevent replay attacks**.
A replay attack happens when a bad actor intercepts a valid token and uses it to make a request again.
By storing the `jti` of every token you've already processed in a database or cache, you can check if a token has been used before.
If a token with a previously-seen `jti` shows up, you can reject the request, stopping the attack.


.. _key-length-validation:

Key Length Validation
---------------------

PyJWT validates that cryptographic keys meet minimum recommended lengths.
By default, a warning (``InsecureKeyLengthWarning``) is emitted when a key
is too short. You can configure PyJWT to raise an ``InvalidKeyError`` instead.

The minimum key lengths are:

* **HMAC** (HS256, HS384, HS512): Key must be at least as long as the hash
  output (32, 48, or 64 bytes respectively), per `RFC 7518 Section 3.2
  <https://www.rfc-editor.org/rfc/rfc7518#section-3.2>`_.
* **RSA** (RS256, RS384, RS512, PS256, PS384, PS512): Key must be at least
  2048 bits, per `NIST SP 800-131A
  <https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final>`_.

By default, short keys produce an ``InsecureKeyLengthWarning``:

.. code-block:: pycon

    >>> import jwt
    >>> encoded = jwt.encode({"some": "payload"}, "short", algorithm="HS256")

To enforce minimum key lengths (raise ``InvalidKeyError`` on short keys),
pass ``enforce_minimum_key_length=True`` in the options when creating a
``PyJWT`` or ``PyJWS`` instance:

.. code-block:: pycon

    >>> strict_jwt = jwt.PyJWT(options={"enforce_minimum_key_length": True})
    >>> try:
    ...     strict_jwt.encode({"some": "payload"}, "short", algorithm="HS256")
    ... except jwt.InvalidKeyError:
    ...     print("key too short")
    ...
    key too short

To suppress the warning without enforcing, use Python's standard
``warnings`` module:

.. code-block:: python

    import warnings
    import jwt

    warnings.filterwarnings("ignore", category=jwt.InsecureKeyLengthWarning)

Requiring Presence of Claims
----------------------------

If you wish to require one or more claims to be present in the claimset, you can set the ``require`` parameter to include these claims.

.. code-block:: pycon

    >>> token = jwt.encode({"sub": "1234567890", "iat": 1371720939}, "secret")
    >>> try:
    ...     jwt.decode(
    ...         token,
    ...         "secret",
    ...         options={"require": ["exp", "iss", "sub"]},
    ...         algorithms=["HS256"],
    ...     )
    ... except jwt.MissingRequiredClaimError as e:
    ...     print(e)
    ...
    Token is missing the "exp" claim

Retrieve RSA signing keys from a JWKS endpoint
----------------------------------------------


.. code-block:: pycon

    >>> import jwt
    >>> from jwt import PyJWKClient
    >>> token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik5FRTFRVVJCT1RNNE16STVSa0ZETlRZeE9UVTFNRGcyT0Rnd1EwVXpNVGsxUWpZeVJrUkZRdyJ9.eyJpc3MiOiJodHRwczovL2Rldi04N2V2eDlydS5hdXRoMC5jb20vIiwic3ViIjoiYVc0Q2NhNzl4UmVMV1V6MGFFMkg2a0QwTzNjWEJWdENAY2xpZW50cyIsImF1ZCI6Imh0dHBzOi8vZXhwZW5zZXMtYXBpIiwiaWF0IjoxNTcyMDA2OTU0LCJleHAiOjE1NzIwMDY5NjQsImF6cCI6ImFXNENjYTc5eFJlTFdVejBhRTJINmtEME8zY1hCVnRDIiwiZ3R5IjoiY2xpZW50LWNyZWRlbnRpYWxzIn0.PUxE7xn52aTCohGiWoSdMBZGiYAHwE5FYie0Y1qUT68IHSTXwXVd6hn02HTah6epvHHVKA2FqcFZ4GGv5VTHEvYpeggiiZMgbxFrmTEY0csL6VNkX1eaJGcuehwQCRBKRLL3zKmA5IKGy5GeUnIbpPHLHDxr-GXvgFzsdsyWlVQvPX2xjeaQ217r2PtxDeqjlf66UYl6oY6AqNS8DH3iryCvIfCcybRZkc_hdy-6ZMoKT6Piijvk_aXdm7-QQqKJFHLuEqrVSOuBqqiNfVrG27QzAPuPOxvfXTVLXL2jek5meH6n-VWgrBdoMFH93QEszEDowDAEhQPHVs0xj7SIzA"
    >>> url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"
    >>> optional_custom_headers = {"User-agent": "custom-user-agent"}
    >>> jwks_client = PyJWKClient(url, headers=optional_custom_headers)
    >>> signing_key = jwks_client.get_signing_key_from_jwt(token)
    >>> jwt.decode(
    ...     token,
    ...     signing_key,
    ...     audience="https://expenses-api",
    ...     options={"verify_exp": False},
    ...     algorithms=["RS256"],
    ... )
    {'iss': 'https://dev-87evx9ru.auth0.com/', 'sub': 'aW4Cca79xReLWUz0aE2H6kD0O3cXBVtC@clients', 'aud': 'https://expenses-api', 'iat': 1572006954, 'exp': 1572006964, 'azp': 'aW4Cca79xReLWUz0aE2H6kD0O3cXBVtC', 'gty': 'client-credentials'}

OIDC Login Flow
---------------

The following usage demonstrates an OIDC login flow using pyjwt. Further
reading about the OIDC spec is recommended for implementers.

In particular, this demonstrates validation of the ``at_hash`` claim.
This claim relies on data from outside of the the JWT for validation. Methods
are provided which support computation and validation of this claim, but it
is not built into pyjwt.

.. code-block:: python

    import base64
    import jwt
    import requests

    # Part 1: setup
    # get the OIDC config and JWKs to use

    # in OIDC, you must know your client_id (this is the OAuth 2.0 client_id)
    client_id = ...

    # example of fetching data from your OIDC server
    # see: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
    oidc_server = ...
    oidc_config = requests.get(
        f"https://{oidc_server}/.well-known/openid-configuration"
    ).json()
    signing_algos = oidc_config["id_token_signing_alg_values_supported"]

    # setup a PyJWKClient to get the appropriate signing key
    jwks_client = jwt.PyJWKClient(oidc_config["jwks_uri"])

    # Part 2: login / authorization
    # when a user completes an OIDC login flow, there will be a well-formed
    # response object to parse/handle

    # data from the login flow
    # see: https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
    token_response = ...
    id_token = token_response["id_token"]
    access_token = token_response["access_token"]

    # Part 3: decode and validate at_hash
    # after the login is complete, the id_token needs to be decoded
    # this is the stage at which an OIDC client must verify the at_hash

    # get signing_key from id_token
    signing_key = jwks_client.get_signing_key_from_jwt(id_token)

    # now, decode_complete to get payload + header
    data = jwt.decode_complete(
        id_token,
        key=signing_key,
        audience=client_id,
        algorithms=signing_algos,
    )
    payload, header = data["payload"], data["header"]

    # get the pyjwt algorithm object
    alg_obj = jwt.get_algorithm_by_name(header["alg"])

    # compute at_hash, then validate / assert
    digest = alg_obj.compute_hash_digest(access_token)
    at_hash = base64.urlsafe_b64encode(digest[: (len(digest) // 2)]).rstrip("=")
    assert at_hash == payload["at_hash"]
