import base64

from jwt.algorithms import Algorithm, HMACAlgorithm, NoneAlgorithm
from jwt.exceptions import InvalidKeyError

import pytest

from .utils import ensure_bytes, ensure_unicode, key_path

try:
    from jwt.algorithms import RSAAlgorithm, ECAlgorithm, RSAPSSAlgorithm

    has_crypto = True
except ImportError:
    has_crypto = False


class TestAlgorithms:
    def test_algorithm_should_throw_exception_if_prepare_key_not_impl(self):
        algo = Algorithm()

        with pytest.raises(NotImplementedError):
            algo.prepare_key('test')

    def test_algorithm_should_throw_exception_if_sign_not_impl(self):
        algo = Algorithm()

        with pytest.raises(NotImplementedError):
            algo.sign('message', 'key')

    def test_algorithm_should_throw_exception_if_verify_not_impl(self):
        algo = Algorithm()

        with pytest.raises(NotImplementedError):
            algo.verify('message', 'key', 'signature')

    def test_none_algorithm_should_throw_exception_if_key_is_not_none(self):
        algo = NoneAlgorithm()

        with pytest.raises(InvalidKeyError):
            algo.prepare_key('123')

    def test_hmac_should_reject_nonstring_key(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)

        with pytest.raises(TypeError) as context:
            algo.prepare_key(object())

        exception = context.value
        assert str(exception) == 'Expecting a string- or bytes-formatted key.'

    def test_hmac_should_accept_unicode_key(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)

        algo.prepare_key(ensure_unicode('awesome'))

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_hmac_should_throw_exception_if_key_is_pem_public_key(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)

        with pytest.raises(InvalidKeyError):
            with open(key_path('testkey2_rsa.pub.pem'), 'r') as keyfile:
                algo.prepare_key(keyfile.read())

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_hmac_should_throw_exception_if_key_is_x509_certificate(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)

        with pytest.raises(InvalidKeyError):
            with open(key_path('testkey_rsa.cer'), 'r') as keyfile:
                algo.prepare_key(keyfile.read())

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_hmac_should_throw_exception_if_key_is_ssh_public_key(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)

        with pytest.raises(InvalidKeyError):
            with open(key_path('testkey_rsa.pub'), 'r') as keyfile:
                algo.prepare_key(keyfile.read())

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_hmac_should_throw_exception_if_key_is_x509_cert(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)

        with pytest.raises(InvalidKeyError):
            with open(key_path('testkey2_rsa.pub.pem'), 'r') as keyfile:
                algo.prepare_key(keyfile.read())

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_rsa_should_parse_pem_public_key(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path('testkey2_rsa.pub.pem'), 'r') as pem_key:
            algo.prepare_key(pem_key.read())

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_rsa_should_accept_unicode_key(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path('testkey_rsa'), 'r') as rsa_key:
            algo.prepare_key(ensure_unicode(rsa_key.read()))

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_rsa_should_reject_non_string_key(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with pytest.raises(TypeError):
            algo.prepare_key(None)

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_rsa_verify_should_return_false_if_signature_invalid(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        message = ensure_bytes('Hello World!')

        sig = base64.b64decode(ensure_bytes(
            'yS6zk9DBkuGTtcBzLUzSpo9gGJxJFOGvUqN01iLhWHrzBQ9ZEz3+Ae38AXp'
            '10RWwscp42ySC85Z6zoN67yGkLNWnfmCZSEv+xqELGEvBJvciOKsrhiObUl'
            '2mveSc1oeO/2ujkGDkkkJ2epn0YliacVjZF5+/uDmImUfAAj8lzjnHlzYix'
            'sn5jGz1H07jYYbi9diixN8IUhXeTafwFg02IcONhum29V40Wu6O5tAKWlJX'
            'fHJnNUzAEUOXS0WahHVb57D30pcgIji9z923q90p5c7E2cU8V+E1qe8NdCA'
            'APCDzZZ9zQ/dgcMVaBrGrgimrcLbPjueOKFgSO+SSjIElKA=='))

        sig += ensure_bytes('123')  # Signature is now invalid

        with open(key_path('testkey_rsa.pub'), 'r') as keyfile:
            pub_key = algo.prepare_key(keyfile.read())

        result = algo.verify(message, pub_key, sig)
        assert not result

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_rsa_verify_should_return_true_if_signature_valid(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        message = ensure_bytes('Hello World!')

        sig = base64.b64decode(ensure_bytes(
            'yS6zk9DBkuGTtcBzLUzSpo9gGJxJFOGvUqN01iLhWHrzBQ9ZEz3+Ae38AXp'
            '10RWwscp42ySC85Z6zoN67yGkLNWnfmCZSEv+xqELGEvBJvciOKsrhiObUl'
            '2mveSc1oeO/2ujkGDkkkJ2epn0YliacVjZF5+/uDmImUfAAj8lzjnHlzYix'
            'sn5jGz1H07jYYbi9diixN8IUhXeTafwFg02IcONhum29V40Wu6O5tAKWlJX'
            'fHJnNUzAEUOXS0WahHVb57D30pcgIji9z923q90p5c7E2cU8V+E1qe8NdCA'
            'APCDzZZ9zQ/dgcMVaBrGrgimrcLbPjueOKFgSO+SSjIElKA=='))

        with open(key_path('testkey_rsa.pub'), 'r') as keyfile:
            pub_key = algo.prepare_key(keyfile.read())

        result = algo.verify(message, pub_key, sig)
        assert result

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_ec_should_reject_non_string_key(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        with pytest.raises(TypeError):
            algo.prepare_key(None)

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_ec_should_accept_unicode_key(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        with open(key_path('testkey_ec'), 'r') as ec_key:
            algo.prepare_key(ensure_unicode(ec_key.read()))

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_ec_verify_should_return_false_if_signature_invalid(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        message = ensure_bytes('Hello World!')

        # Mess up the signature by replacing a known byte
        sig = base64.b64decode(ensure_bytes(
            'MIGIAkIB9vYz+inBL8aOTA4auYz/zVuig7TT1bQgKROIQX9YpViHkFa4DT5'
            '5FuFKn9XzVlk90p6ldEj42DC9YecXHbC2t+cCQgCicY+8f3f/KCNtWK7cif'
            '6vdsVwm6Lrjs0Ag6ZqCf+olN11hVt1qKBC4lXppqB1gNWEmNQaiz1z2QRyc'
            'zJ8hSJmbw=='.replace('r', 's')))

        with open(key_path('testkey_ec.pub'), 'r') as keyfile:
            pub_key = algo.prepare_key(keyfile.read())

        result = algo.verify(message, pub_key, sig)
        assert not result

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_ec_verify_should_return_true_if_signature_valid(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        message = ensure_bytes('Hello World!')

        sig = base64.b64decode(ensure_bytes(
            'MIGIAkIB9vYz+inBL8aOTA4auYz/zVuig7TT1bQgKROIQX9YpViHkFa4DT5'
            '5FuFKn9XzVlk90p6ldEj42DC9YecXHbC2t+cCQgCicY+8f3f/KCNtWK7cif'
            '6vdsVwm6Lrjs0Ag6ZqCf+olN11hVt1qKBC4lXppqB1gNWEmNQaiz1z2QRyc'
            'zJ8hSJmbw=='))

        with open(key_path('testkey_ec.pub'), 'r') as keyfile:
            pub_key = algo.prepare_key(keyfile.read())

        result = algo.verify(message, pub_key, sig)
        assert result

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_rsa_pss_sign_then_verify_should_return_true(self):
        algo = RSAPSSAlgorithm(RSAPSSAlgorithm.SHA256)

        message = ensure_bytes('Hello World!')

        with open(key_path('testkey_rsa'), 'r') as keyfile:
            priv_key = algo.prepare_key(keyfile.read())
            sig = algo.sign(message, priv_key)

        with open(key_path('testkey_rsa.pub'), 'r') as keyfile:
            pub_key = algo.prepare_key(keyfile.read())

        result = algo.verify(message, pub_key, sig)
        assert result

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_rsa_pss_verify_should_return_false_if_signature_invalid(self):
        algo = RSAPSSAlgorithm(RSAPSSAlgorithm.SHA256)

        jwt_message = ensure_bytes('Hello World!')

        jwt_sig = base64.b64decode(ensure_bytes(
            'ywKAUGRIDC//6X+tjvZA96yEtMqpOrSppCNfYI7NKyon3P7doud5v65oWNu'
            'vQsz0fzPGfF7mQFGo9Cm9Vn0nljm4G6PtqZRbz5fXNQBH9k10gq34AtM02c'
            '/cveqACQ8gF3zxWh6qr9jVqIpeMEaEBIkvqG954E0HT9s9ybHShgHX9mlWk'
            '186/LopP4xe5c/hxOQjwhv6yDlTiwJFiqjNCvj0GyBKsc4iECLGIIO+4mC4'
            'daOCWqbpZDuLb1imKpmm8Nsm56kAxijMLZnpCcnPgyb7CqG+B93W9GHglA5'
            'drUeR1gRtO7vqbZMsCAQ4bpjXxwbYyjQlEVuMl73UL6sOWg=='))

        jwt_sig += ensure_bytes('123')  # Signature is now invalid

        with open(key_path('testkey_rsa.pub'), 'r') as keyfile:
            jwt_pub_key = algo.prepare_key(keyfile.read())

        result = algo.verify(jwt_message, jwt_pub_key, jwt_sig)
        assert not result

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_rsa_pss_verify_should_return_true_if_signature_valid(self):
        algo = RSAPSSAlgorithm(RSAPSSAlgorithm.SHA256)

        jwt_message = ensure_bytes('Hello World!')

        jwt_sig = base64.b64decode(ensure_bytes(
            'ywKAUGRIDC//6X+tjvZA96yEtMqpOrSppCNfYI7NKyon3P7doud5v65oWNu'
            'vQsz0fzPGfF7mQFGo9Cm9Vn0nljm4G6PtqZRbz5fXNQBH9k10gq34AtM02c'
            '/cveqACQ8gF3zxWh6qr9jVqIpeMEaEBIkvqG954E0HT9s9ybHShgHX9mlWk'
            '186/LopP4xe5c/hxOQjwhv6yDlTiwJFiqjNCvj0GyBKsc4iECLGIIO+4mC4'
            'daOCWqbpZDuLb1imKpmm8Nsm56kAxijMLZnpCcnPgyb7CqG+B93W9GHglA5'
            'drUeR1gRtO7vqbZMsCAQ4bpjXxwbYyjQlEVuMl73UL6sOWg=='))

        with open(key_path('testkey_rsa.pub'), 'r') as keyfile:
            jwt_pub_key = algo.prepare_key(keyfile.read())

        result = algo.verify(jwt_message, jwt_pub_key, jwt_sig)
        assert result
