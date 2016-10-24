import base64

from jwt.utils import force_bytes, force_unicode

import pytest

from ..utils import key_path

try:
    from jwt.contrib.algorithms.pycrypto import RSAAlgorithm
    has_pycrypto = True
except ImportError:
    has_pycrypto = False

try:
    from jwt.contrib.algorithms.py_ecdsa import ECAlgorithm
    has_ecdsa = True
except ImportError:
    has_ecdsa = False


@pytest.mark.skipif(not has_pycrypto, reason='Not supported without PyCrypto library')
class TestPycryptoAlgorithms:
    def test_rsa_should_parse_pem_public_key(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path('testkey2_rsa.pub.pem'), 'r') as pem_key:
            algo.prepare_key(pem_key.read())

    def test_rsa_should_accept_unicode_key(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path('testkey_rsa'), 'r') as rsa_key:
            algo.prepare_key(force_unicode(rsa_key.read()))

    def test_rsa_should_reject_non_string_key(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with pytest.raises(TypeError):
            algo.prepare_key(None)

    def test_rsa_sign_should_generate_correct_signature_value(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        jwt_message = force_bytes('Hello World!')

        expected_sig = base64.b64decode(force_bytes(
            'yS6zk9DBkuGTtcBzLUzSpo9gGJxJFOGvUqN01iLhWHrzBQ9ZEz3+Ae38AXp'
            '10RWwscp42ySC85Z6zoN67yGkLNWnfmCZSEv+xqELGEvBJvciOKsrhiObUl'
            '2mveSc1oeO/2ujkGDkkkJ2epn0YliacVjZF5+/uDmImUfAAj8lzjnHlzYix'
            'sn5jGz1H07jYYbi9diixN8IUhXeTafwFg02IcONhum29V40Wu6O5tAKWlJX'
            'fHJnNUzAEUOXS0WahHVb57D30pcgIji9z923q90p5c7E2cU8V+E1qe8NdCA'
            'APCDzZZ9zQ/dgcMVaBrGrgimrcLbPjueOKFgSO+SSjIElKA=='))

        with open(key_path('testkey_rsa'), 'r') as keyfile:
            jwt_key = algo.prepare_key(keyfile.read())

        with open(key_path('testkey_rsa.pub'), 'r') as keyfile:
            jwt_pub_key = algo.prepare_key(keyfile.read())

        algo.sign(jwt_message, jwt_key)
        result = algo.verify(jwt_message, jwt_pub_key, expected_sig)
        assert result

    def test_rsa_verify_should_return_false_if_signature_invalid(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        jwt_message = force_bytes('Hello World!')

        jwt_sig = base64.b64decode(force_bytes(
            'yS6zk9DBkuGTtcBzLUzSpo9gGJxJFOGvUqN01iLhWHrzBQ9ZEz3+Ae38AXp'
            '10RWwscp42ySC85Z6zoN67yGkLNWnfmCZSEv+xqELGEvBJvciOKsrhiObUl'
            '2mveSc1oeO/2ujkGDkkkJ2epn0YliacVjZF5+/uDmImUfAAj8lzjnHlzYix'
            'sn5jGz1H07jYYbi9diixN8IUhXeTafwFg02IcONhum29V40Wu6O5tAKWlJX'
            'fHJnNUzAEUOXS0WahHVb57D30pcgIji9z923q90p5c7E2cU8V+E1qe8NdCA'
            'APCDzZZ9zQ/dgcMVaBrGrgimrcLbPjueOKFgSO+SSjIElKA=='))

        jwt_sig += force_bytes('123')  # Signature is now invalid

        with open(key_path('testkey_rsa.pub'), 'r') as keyfile:
            jwt_pub_key = algo.prepare_key(keyfile.read())

        result = algo.verify(jwt_message, jwt_pub_key, jwt_sig)
        assert not result

    def test_rsa_verify_should_return_true_if_signature_valid(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        jwt_message = force_bytes('Hello World!')

        jwt_sig = base64.b64decode(force_bytes(
            'yS6zk9DBkuGTtcBzLUzSpo9gGJxJFOGvUqN01iLhWHrzBQ9ZEz3+Ae38AXp'
            '10RWwscp42ySC85Z6zoN67yGkLNWnfmCZSEv+xqELGEvBJvciOKsrhiObUl'
            '2mveSc1oeO/2ujkGDkkkJ2epn0YliacVjZF5+/uDmImUfAAj8lzjnHlzYix'
            'sn5jGz1H07jYYbi9diixN8IUhXeTafwFg02IcONhum29V40Wu6O5tAKWlJX'
            'fHJnNUzAEUOXS0WahHVb57D30pcgIji9z923q90p5c7E2cU8V+E1qe8NdCA'
            'APCDzZZ9zQ/dgcMVaBrGrgimrcLbPjueOKFgSO+SSjIElKA=='))

        with open(key_path('testkey_rsa.pub'), 'r') as keyfile:
            jwt_pub_key = algo.prepare_key(keyfile.read())

        result = algo.verify(jwt_message, jwt_pub_key, jwt_sig)
        assert result

    def test_rsa_prepare_key_should_be_idempotent(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path('testkey_rsa.pub'), 'r') as keyfile:
            jwt_pub_key_first = algo.prepare_key(keyfile.read())
            jwt_pub_key_second = algo.prepare_key(jwt_pub_key_first)

        assert jwt_pub_key_first == jwt_pub_key_second


@pytest.mark.skipif(not has_ecdsa, reason='Not supported without ecdsa library')
class TestEcdsaAlgorithms:
    def test_ec_should_reject_non_string_key(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        with pytest.raises(TypeError):
            algo.prepare_key(None)

    def test_ec_should_accept_unicode_key(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        with open(key_path('testkey_ec'), 'r') as ec_key:
            algo.prepare_key(force_unicode(ec_key.read()))

    def test_ec_sign_should_generate_correct_signature_value(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        jwt_message = force_bytes('Hello World!')

        expected_sig = base64.b64decode(force_bytes(
            'AC+m4Jf/xI3guAC6w0w37t5zRpSCF6F4udEz5LiMiTIjCS4vcVe6dDOxK+M'
            'mvkF8PxJuvqxP2CO3TR3okDPCl/NjATTO1jE+qBZ966CRQSSzcCM+tzcHzw'
            'LZS5kbvKu0Acd/K6Ol2/W3B1NeV5F/gjvZn/jOwaLgWEUYsg0o4XVrAg65'))

        with open(key_path('testkey_ec'), 'r') as keyfile:
            jwt_key = algo.prepare_key(keyfile.read())

        with open(key_path('testkey_ec.pub'), 'r') as keyfile:
            jwt_pub_key = algo.prepare_key(keyfile.read())

        algo.sign(jwt_message, jwt_key)
        result = algo.verify(jwt_message, jwt_pub_key, expected_sig)
        assert result

    def test_ec_verify_should_return_false_if_signature_invalid(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        jwt_message = force_bytes('Hello World!')

        jwt_sig = base64.b64decode(force_bytes(
            'AC+m4Jf/xI3guAC6w0w37t5zRpSCF6F4udEz5LiMiTIjCS4vcVe6dDOxK+M'
            'mvkF8PxJuvqxP2CO3TR3okDPCl/NjATTO1jE+qBZ966CRQSSzcCM+tzcHzw'
            'LZS5kbvKu0Acd/K6Ol2/W3B1NeV5F/gjvZn/jOwaLgWEUYsg0o4XVrAg65'))

        jwt_sig += force_bytes('123')  # Signature is now invalid

        with open(key_path('testkey_ec.pub'), 'r') as keyfile:
            jwt_pub_key = algo.prepare_key(keyfile.read())

        result = algo.verify(jwt_message, jwt_pub_key, jwt_sig)
        assert not result

    def test_ec_verify_should_return_true_if_signature_valid(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        jwt_message = force_bytes('Hello World!')

        jwt_sig = base64.b64decode(force_bytes(
            'AC+m4Jf/xI3guAC6w0w37t5zRpSCF6F4udEz5LiMiTIjCS4vcVe6dDOxK+M'
            'mvkF8PxJuvqxP2CO3TR3okDPCl/NjATTO1jE+qBZ966CRQSSzcCM+tzcHzw'
            'LZS5kbvKu0Acd/K6Ol2/W3B1NeV5F/gjvZn/jOwaLgWEUYsg0o4XVrAg65'))

        with open(key_path('testkey_ec.pub'), 'r') as keyfile:
            jwt_pub_key = algo.prepare_key(keyfile.read())

        result = algo.verify(jwt_message, jwt_pub_key, jwt_sig)
        assert result

    def test_ec_prepare_key_should_be_idempotent(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        with open(key_path('testkey_ec.pub'), 'r') as keyfile:
            jwt_pub_key_first = algo.prepare_key(keyfile.read())
            jwt_pub_key_second = algo.prepare_key(jwt_pub_key_first)

        assert jwt_pub_key_first == jwt_pub_key_second
