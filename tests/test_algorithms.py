import base64
import hashlib

from jwt.algorithms import Algorithm, HMACAlgorithm

from .compat import unittest
from .utils import ensure_bytes, ensure_unicode

try:
    from cryptography.hazmat.primitives import hashes
    from jwt.algorithms import RSAAlgorithm, ECAlgorithm

    has_crypto = True
except ImportError:
    has_crypto = False


class TestJWT(unittest.TestCase):
    def setUp(self):  # noqa
        pass

    def test_algorithm_should_throw_exception_if_prepare_key_not_impl(self):
        algo = Algorithm()

        with self.assertRaises(NotImplementedError):
            algo.prepare_key('test')

    def test_algorithm_should_throw_exception_if_sign_not_impl(self):
        algo = Algorithm()

        with self.assertRaises(NotImplementedError):
            algo.sign('message', 'key')

    def test_algorithm_should_throw_exception_if_verify_not_impl(self):
        algo = Algorithm()

        with self.assertRaises(NotImplementedError):
            algo.verify('message', 'key', 'signature')

    def test_hmac_should_reject_nonstring_key(self):
        algo = HMACAlgorithm(hashlib.sha256())

        with self.assertRaises(TypeError) as context:
            algo.prepare_key(object())

        exception = context.exception
        self.assertEqual(str(exception), 'Expecting a string- or bytes-formatted key.')

    def test_hmac_should_accept_unicode_key(self):
        algo = HMACAlgorithm(hashlib.sha256())

        algo.prepare_key(ensure_unicode('awesome'))

    @unittest.skipIf(not has_crypto, 'Not supported without cryptography library')
    def test_rsa_should_parse_pem_public_key(self):
        algo = RSAAlgorithm(hashes.SHA256())

        with open('tests/keys/testkey2_rsa.pub.pem', 'r') as pem_key:
            algo.prepare_key(pem_key.read())

    @unittest.skipIf(not has_crypto, 'Not supported without cryptography library')
    def test_rsa_should_accept_unicode_key(self):
        algo = RSAAlgorithm(hashes.SHA256())

        with open('tests/keys/testkey_rsa', 'r') as rsa_key:
            algo.prepare_key(ensure_unicode(rsa_key.read()))

    @unittest.skipIf(not has_crypto, 'Not supported without cryptography library')
    def test_rsa_should_reject_non_string_key(self):
        algo = RSAAlgorithm(hashes.SHA256())

        with self.assertRaises(TypeError):
            algo.prepare_key(None)

    @unittest.skipIf(not has_crypto, 'Not supported without cryptography library')
    def test_rsa_verify_should_return_false_if_signature_invalid(self):
        algo = RSAAlgorithm(hashes.SHA256())

        jwt_message = ensure_bytes('Hello World!')

        jwt_sig = base64.b64decode(ensure_bytes(
            'yS6zk9DBkuGTtcBzLUzSpo9gGJxJFOGvUqN01iLhWHrzBQ9ZEz3+Ae38AXp'
            '10RWwscp42ySC85Z6zoN67yGkLNWnfmCZSEv+xqELGEvBJvciOKsrhiObUl'
            '2mveSc1oeO/2ujkGDkkkJ2epn0YliacVjZF5+/uDmImUfAAj8lzjnHlzYix'
            'sn5jGz1H07jYYbi9diixN8IUhXeTafwFg02IcONhum29V40Wu6O5tAKWlJX'
            'fHJnNUzAEUOXS0WahHVb57D30pcgIji9z923q90p5c7E2cU8V+E1qe8NdCA'
            'APCDzZZ9zQ/dgcMVaBrGrgimrcLbPjueOKFgSO+SSjIElKA=='))

        jwt_sig = jwt_sig + ensure_bytes('123')  # Signature is now invalid

        with open('tests/keys/testkey_rsa.pub', 'r') as keyfile:
            jwt_pub_key = algo.prepare_key(keyfile.read())

        result = algo.verify(jwt_message, jwt_pub_key, jwt_sig)
        self.assertFalse(result)

    @unittest.skipIf(not has_crypto, 'Not supported without cryptography library')
    def test_rsa_verify_should_return_true_if_signature_valid(self):
        algo = RSAAlgorithm(hashes.SHA256())

        jwt_message = ensure_bytes('Hello World!')

        jwt_sig = base64.b64decode(ensure_bytes(
            'yS6zk9DBkuGTtcBzLUzSpo9gGJxJFOGvUqN01iLhWHrzBQ9ZEz3+Ae38AXp'
            '10RWwscp42ySC85Z6zoN67yGkLNWnfmCZSEv+xqELGEvBJvciOKsrhiObUl'
            '2mveSc1oeO/2ujkGDkkkJ2epn0YliacVjZF5+/uDmImUfAAj8lzjnHlzYix'
            'sn5jGz1H07jYYbi9diixN8IUhXeTafwFg02IcONhum29V40Wu6O5tAKWlJX'
            'fHJnNUzAEUOXS0WahHVb57D30pcgIji9z923q90p5c7E2cU8V+E1qe8NdCA'
            'APCDzZZ9zQ/dgcMVaBrGrgimrcLbPjueOKFgSO+SSjIElKA=='))

        with open('tests/keys/testkey_rsa.pub', 'r') as keyfile:
            jwt_pub_key = algo.prepare_key(keyfile.read())

        result = algo.verify(jwt_message, jwt_pub_key, jwt_sig)
        self.assertTrue(result)

    @unittest.skipIf(not has_crypto, 'Not supported without cryptography library')
    def test_ec_should_reject_non_string_key(self):
        algo = ECAlgorithm(hashes.SHA256())

        with self.assertRaises(TypeError):
            algo.prepare_key(None)

    @unittest.skipIf(not has_crypto, 'Not supported without cryptography library')
    def test_ec_verify_should_return_false_if_signature_invalid(self):
        algo = ECAlgorithm(hashes.SHA256())

        jwt_message = ensure_bytes('Hello World!')

        jwt_sig = base64.b64decode(ensure_bytes(
            'MIGIAkIB9vYz+inBL8aOTA4auYz/zVuig7TT1bQgKROIQX9YpViHkFa4DT5'
            '5FuFKn9XzVlk90p6ldEj42DC9YecXHbC2t+cCQgCicY+8f3f/KCNtWK7cif'
            '6vdsVwm6Lrjs0Ag6ZqCf+olN11hVt1qKBC4lXppqB1gNWEmNQaiz1z2QRyc'
            'zJ8hSJmbw=='))

        jwt_sig = ensure_bytes('123')  # Signature is now invalid

        with open('tests/keys/testkey_ec.pub', 'r') as keyfile:
            jwt_pub_key = algo.prepare_key(keyfile.read())

        result = algo.verify(jwt_message, jwt_pub_key, jwt_sig)
        self.assertFalse(result)

    @unittest.skipIf(not has_crypto, 'Not supported without cryptography library')
    def test_ec_verify_should_return_true_if_signature_valid(self):
        algo = ECAlgorithm(hashes.SHA256())

        jwt_message = ensure_bytes('Hello World!')

        jwt_sig = base64.b64decode(ensure_bytes(
            'MIGIAkIB9vYz+inBL8aOTA4auYz/zVuig7TT1bQgKROIQX9YpViHkFa4DT5'
            '5FuFKn9XzVlk90p6ldEj42DC9YecXHbC2t+cCQgCicY+8f3f/KCNtWK7cif'
            '6vdsVwm6Lrjs0Ag6ZqCf+olN11hVt1qKBC4lXppqB1gNWEmNQaiz1z2QRyc'
            'zJ8hSJmbw=='))

        with open('tests/keys/testkey_ec.pub', 'r') as keyfile:
            jwt_pub_key = algo.prepare_key(keyfile.read())

        result = algo.verify(jwt_message, jwt_pub_key, jwt_sig)
        self.assertTrue(result)
