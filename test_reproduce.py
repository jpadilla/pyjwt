from cryptography.hazmat.primitives.asymmetric import ec

import jwt

# KEY_TYPE = ec.SECP256R1()
KEY_TYPE = ec.SECP256K1()

privkey = ec.generate_private_key(KEY_TYPE)

my_jwt = jwt.encode(
    {"hello": "world"},
    privkey,
    algorithm="ES256",  # nistp256 aka ec.SECP256R1()
)

print(my_jwt)  # I think this should raise an exception!

decoded = jwt.decode(my_jwt, key=privkey.public_key(), algorithms=["ES256"])

print(decoded)  # This should raise an exception even more so!
