import base64

from ..compat import unittest
from ..utils import ensure_bytes, ensure_unicode, key_path

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


@unittest.skipIf(not has_pycrypto, 'Not supported without PyCrypto library')
class TestPycryptoAlgorithms(unittest.TestCase):
    def setUp(self):  # noqa
        pass

    def test_rsa_should_parse_pem_public_key(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path('testkey2_rsa.pub.pem'), 'r') as pem_key:
            algo.prepare_key(pem_key.read())

    def test_rsa_should_accept_unicode_key(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path('testkey_rsa'), 'r') as rsa_key:
            algo.prepare_key(ensure_unicode(rsa_key.read()))

    def test_rsa_should_reject_non_string_key(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with self.assertRaises(TypeError):
            algo.prepare_key(None)

    def test_rsa_sign_should_generate_correct_signature_value(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        jwt_message = ensure_bytes('Hello World!')

        expected_sig = base64.b64decode(ensure_bytes(
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
        self.assertTrue(result)

    def test_rsa_verify_should_return_false_if_signature_invalid(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        jwt_message = ensure_bytes('Hello World!')

        jwt_sig = base64.b64decode(ensure_bytes(
            'yS6zk9DBkuGTtcBzLUzSpo9gGJxJFOGvUqN01iLhWHrzBQ9ZEz3+Ae38AXp'
            '10RWwscp42ySC85Z6zoN67yGkLNWnfmCZSEv+xqELGEvBJvciOKsrhiObUl'
            '2mveSc1oeO/2ujkGDkkkJ2epn0YliacVjZF5+/uDmImUfAAj8lzjnHlzYix'
            'sn5jGz1H07jYYbi9diixN8IUhXeTafwFg02IcONhum29V40Wu6O5tAKWlJX'
            'fHJnNUzAEUOXS0WahHVb57D30pcgIji9z923q90p5c7E2cU8V+E1qe8NdCA'
            'APCDzZZ9zQ/dgcMVaBrGrgimrcLbPjueOKFgSO+SSjIElKA=='))

        jwt_sig += ensure_bytes('123')  # Signature is now invalid

        with open(key_path('testkey_rsa.pub'), 'r') as keyfile:
            jwt_pub_key = algo.prepare_key(keyfile.read())

        result = algo.verify(jwt_message, jwt_pub_key, jwt_sig)
        self.assertFalse(result)

    def test_rsa_verify_should_return_true_if_signature_valid(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        jwt_message = ensure_bytes('Hello World!')

        jwt_sig = base64.b64decode(ensure_bytes(
            'yS6zk9DBkuGTtcBzLUzSpo9gGJxJFOGvUqN01iLhWHrzBQ9ZEz3+Ae38AXp'
            '10RWwscp42ySC85Z6zoN67yGkLNWnfmCZSEv+xqELGEvBJvciOKsrhiObUl'
            '2mveSc1oeO/2ujkGDkkkJ2epn0YliacVjZF5+/uDmImUfAAj8lzjnHlzYix'
            'sn5jGz1H07jYYbi9diixN8IUhXeTafwFg02IcONhum29V40Wu6O5tAKWlJX'
            'fHJnNUzAEUOXS0WahHVb57D30pcgIji9z923q90p5c7E2cU8V+E1qe8NdCA'
            'APCDzZZ9zQ/dgcMVaBrGrgimrcLbPjueOKFgSO+SSjIElKA=='))

        with open(key_path('testkey_rsa.pub'), 'r') as keyfile:
            jwt_pub_key = algo.prepare_key(keyfile.read())

        result = algo.verify(jwt_message, jwt_pub_key, jwt_sig)
        self.assertTrue(result)

    def test_rsa_prepare_key_should_be_idempotent(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path('testkey_rsa.pub'), 'r') as keyfile:
            jwt_pub_key_first = algo.prepare_key(keyfile.read())
            jwt_pub_key_second = algo.prepare_key(jwt_pub_key_first)

        self.assertEqual(jwt_pub_key_first, jwt_pub_key_second)


@unittest.skipIf(not has_ecdsa, 'Not supported without ecdsa library')
class TestEcdsaAlgorithms(unittest.TestCase):
    def test_ec_should_reject_non_string_key(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        with self.assertRaises(TypeError):
            algo.prepare_key(None)

    def test_ec_should_accept_unicode_key(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        with open(key_path('testkey_ec'), 'r') as ec_key:
            algo.prepare_key(ensure_unicode(ec_key.read()))

    def test_ec_sign_should_generate_correct_signature_value(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        jwt_message = ensure_bytes('Hello World!')

        expected_sig = base64.b64decode(ensure_bytes(
            'MIGIAkIB9vYz+inBL8aOTA4auYz/zVuig7TT1bQgKROIQX9YpViHkFa4DT5'
            '5FuFKn9XzVlk90p6ldEj42DC9YecXHbC2t+cCQgCicY+8f3f/KCNtWK7cif'
            '6vdsVwm6Lrjs0Ag6ZqCf+olN11hVt1qKBC4lXppqB1gNWEmNQaiz1z2QRyc'
            'zJ8hSJmbw=='))

        with open(key_path('testkey_ec'), 'r') as keyfile:
            jwt_key = algo.prepare_key(keyfile.read())

        with open(key_path('testkey_ec.pub'), 'r') as keyfile:
            jwt_pub_key = algo.prepare_key(keyfile.read())

        algo.sign(jwt_message, jwt_key)
        result = algo.verify(jwt_message, jwt_pub_key, expected_sig)
        self.assertTrue(result)

    def test_ec_verify_should_return_false_if_signature_invalid(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        jwt_message = ensure_bytes('Hello World!')

        jwt_sig = base64.b64decode(ensure_bytes(
            'MIGIAkIB9vYz+inBL8aOTA4auYz/zVuig7TT1bQgKROIQX9YpViHkFa4DT5'
            '5FuFKn9XzVlk90p6ldEj42DC9YecXHbC2t+cCQgCicY+8f3f/KCNtWK7cif'
            '6vdsVwm6Lrjs0Ag6ZqCf+olN11hVt1qKBC4lXppqB1gNWEmNQaiz1z2QRyc'
            'zJ8hSJmbw=='))

        jwt_sig += ensure_bytes('123')  # Signature is now invalid

        with open(key_path('testkey_ec.pub'), 'r') as keyfile:
            jwt_pub_key = algo.prepare_key(keyfile.read())

        result = algo.verify(jwt_message, jwt_pub_key, jwt_sig)
        self.assertFalse(result)

    def test_ec_verify_should_return_true_if_signature_valid(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        jwt_message = ensure_bytes('Hello World!')

        jwt_sig = base64.b64decode(ensure_bytes(
            'MIGIAkIB9vYz+inBL8aOTA4auYz/zVuig7TT1bQgKROIQX9YpViHkFa4DT5'
            '5FuFKn9XzVlk90p6ldEj42DC9YecXHbC2t+cCQgCicY+8f3f/KCNtWK7cif'
            '6vdsVwm6Lrjs0Ag6ZqCf+olN11hVt1qKBC4lXppqB1gNWEmNQaiz1z2QRyc'
            'zJ8hSJmbw=='))

        with open(key_path('testkey_ec.pub'), 'r') as keyfile:
            jwt_pub_key = algo.prepare_key(keyfile.read())

        result = algo.verify(jwt_message, jwt_pub_key, jwt_sig)
        self.assertTrue(result)

    def test_ec_prepare_key_should_be_idempotent(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        with open(key_path('testkey_ec.pub'), 'r') as keyfile:
            jwt_pub_key_first = algo.prepare_key(keyfile.read())
            jwt_pub_key_second = algo.prepare_key(jwt_pub_key_first)

        self.assertEqual(jwt_pub_key_first, jwt_pub_key_second)
