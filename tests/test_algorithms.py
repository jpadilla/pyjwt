import base64

from jwt.algorithms import Algorithm, HMACAlgorithm, NoneAlgorithm
from jwt.exceptions import InvalidKeyError
from jwt.utils import base64url_decode

import pytest

from .keys import load_hmac_key
from .utils import ensure_bytes, ensure_unicode, key_path

try:
    from jwt.algorithms import RSAAlgorithm, ECAlgorithm, RSAPSSAlgorithm
    from .keys import load_rsa_pub_key, load_ec_pub_key
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
            'AC+m4Jf/xI3guAC6w0w37t5zRpSCF6F4udEz5LiMiTIjCS4vcVe6dDOxK+M'
            'mvkF8PxJuvqxP2CO3TR3okDPCl/NjATTO1jE+qBZ966CRQSSzcCM+tzcHzw'
            'LZS5kbvKu0Acd/K6Ol2/W3B1NeV5F/gjvZn/jOwaLgWEUYsg0o4XVrAg65'.replace('r', 's')))

        with open(key_path('testkey_ec.pub'), 'r') as keyfile:
            pub_key = algo.prepare_key(keyfile.read())

        result = algo.verify(message, pub_key, sig)
        assert not result

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_ec_verify_should_return_false_if_signature_wrong_length(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        message = ensure_bytes('Hello World!')

        sig = base64.b64decode(ensure_bytes('AC+m4Jf/xI3guAC6w0w3'))

        with open(key_path('testkey_ec.pub'), 'r') as keyfile:
            pub_key = algo.prepare_key(keyfile.read())

        result = algo.verify(message, pub_key, sig)
        assert not result

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


class TestAlgorithmsRFC7520:
    """
    These test vectors were taken from RFC 7520
    (https://tools.ietf.org/html/rfc7520)
    """

    def test_hmac_verify_should_return_true_for_test_vector(self):
        """
        This test verifies that HMAC verification works with a known good
        signature and key.

        Reference: https://tools.ietf.org/html/rfc7520#section-4.4
        """
        signing_input = ensure_bytes(
            'eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZ'
            'jMxNGJjNzAzNyJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ'
            '29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIG'
            'lmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmc'
            'gd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4'
        )

        signature = base64url_decode(ensure_bytes(
            's0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0'
        ))

        algo = HMACAlgorithm(HMACAlgorithm.SHA256)
        key = algo.prepare_key(load_hmac_key())

        result = algo.verify(signing_input, key, signature)
        assert result

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_rsa_verify_should_return_true_for_test_vector(self):
        """
        This test verifies that RSA PKCS v1.5 verification works with a known
        good signature and key.

        Reference: https://tools.ietf.org/html/rfc7520#section-4.1
        """
        signing_input = ensure_bytes(
            'eyJhbGciOiJSUzI1NiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhb'
            'XBsZSJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb'
            '3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdS'
            'Bkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmU'
            'geW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4'
        )

        signature = base64url_decode(ensure_bytes(
            'MRjdkly7_-oTPTS3AXP41iQIGKa80A0ZmTuV5MEaHoxnW2e5CZ5NlKtainoFmKZop'
            'dHM1O2U4mwzJdQx996ivp83xuglII7PNDi84wnB-BDkoBwA78185hX-Es4JIwmDLJ'
            'K3lfWRa-XtL0RnltuYv746iYTh_qHRD68BNt1uSNCrUCTJDt5aAE6x8wW1Kt9eRo4'
            'QPocSadnHXFxnt8Is9UzpERV0ePPQdLuW3IS_de3xyIrDaLGdjluPxUAhb6L2aXic'
            '1U12podGU0KLUQSE_oI-ZnmKJ3F4uOZDnd6QZWJushZ41Axf_fcIe8u9ipH84ogor'
            'ee7vjbU5y18kDquDg'
        ))

        algo = RSAAlgorithm(RSAAlgorithm.SHA256)
        key = algo.prepare_key(load_rsa_pub_key())

        result = algo.verify(signing_input, key, signature)
        assert result

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_rsapss_verify_should_return_true_for_test_vector(self):
        """
        This test verifies that RSA-PSS verification works with a known good
        signature and key.

        Reference: https://tools.ietf.org/html/rfc7520#section-4.2
        """
        signing_input = ensure_bytes(
            'eyJhbGciOiJQUzM4NCIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhb'
            'XBsZSJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb'
            '3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdS'
            'Bkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmU'
            'geW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4'
        )

        signature = base64url_decode(ensure_bytes(
            'cu22eBqkYDKgIlTpzDXGvaFfz6WGoz7fUDcfT0kkOy42miAh2qyBzk1xEsnk2IpN6'
            '-tPid6VrklHkqsGqDqHCdP6O8TTB5dDDItllVo6_1OLPpcbUrhiUSMxbbXUvdvWXz'
            'g-UD8biiReQFlfz28zGWVsdiNAUf8ZnyPEgVFn442ZdNqiVJRmBqrYRXe8P_ijQ7p'
            '8Vdz0TTrxUeT3lm8d9shnr2lfJT8ImUjvAA2Xez2Mlp8cBE5awDzT0qI0n6uiP1aC'
            'N_2_jLAeQTlqRHtfa64QQSUmFAAjVKPbByi7xho0uTOcbH510a6GYmJUAfmWjwZ6o'
            'D4ifKo8DYM-X72Eaw'
        ))

        algo = RSAPSSAlgorithm(RSAPSSAlgorithm.SHA384)
        key = algo.prepare_key(load_rsa_pub_key())

        result = algo.verify(signing_input, key, signature)
        assert result

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_ec_verify_should_return_true_for_test_vector(self):
        """
        This test verifies that ECDSA verification works with a known good
        signature and key.

        Reference: https://tools.ietf.org/html/rfc7520#section-4.3
        """
        signing_input = ensure_bytes(
            'eyJhbGciOiJFUzUxMiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhb'
            'XBsZSJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb'
            '3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdS'
            'Bkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmU'
            'geW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4'
        )

        signature = base64url_decode(ensure_bytes(
            'AE_R_YZCChjn4791jSQCrdPZCNYqHXCTZH0-JZGYNlaAjP2kqaluUIIUnC9qvbu9P'
            'lon7KRTzoNEuT4Va2cmL1eJAQy3mtPBu_u_sDDyYjnAMDxXPn7XrT0lw-kvAD890j'
            'l8e2puQens_IEKBpHABlsbEPX6sFY8OcGDqoRuBomu9xQ2'
        ))

        algo = ECAlgorithm(ECAlgorithm.SHA512)
        key = algo.prepare_key(load_ec_pub_key())

        result = algo.verify(signing_input, key, signature)
        assert result
