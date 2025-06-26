import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from jwt.algorithms import ECAlgorithm
from jwt.exceptions import InvalidKeyError


def test_ec_curve_validation():
    # Test that ES256 requires SECP256R1 curve
    es256 = ECAlgorithm(ECAlgorithm.SHA256, ec.SECP256R1)
    secp256r1_key = ec.generate_private_key(ec.SECP256R1())
    secp256k1_key = ec.generate_private_key(ec.SECP256K1())

    # SECP256R1 should work with ES256
    es256.prepare_key(secp256r1_key)

    # SECP256K1 should raise InvalidKeyError with ES256
    with pytest.raises(InvalidKeyError):
        es256.prepare_key(secp256k1_key)

    # Test that ES256K requires SECP256K1 curve
    es256k = ECAlgorithm(ECAlgorithm.SHA256, expected_curve=ec.SECP256K1())

    # SECP256K1 should work with ES256K
    es256k.prepare_key(secp256k1_key)

    # SECP256R1 should raise InvalidKeyError with ES256K
    with pytest.raises(InvalidKeyError):
        es256k.prepare_key(secp256r1_key)
