import base64
import json

from jwt.algorithms import Algorithm, HMACAlgorithm, NoneAlgorithm
from jwt.exceptions import InvalidKeyError
from jwt.utils import base64url_decode, force_bytes, force_unicode

import pytest

from .keys import load_hmac_key
from .utils import key_path

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

    def test_algorithm_should_throw_exception_if_to_jwk_not_impl(self):
        algo = Algorithm()

        with pytest.raises(NotImplementedError):
            algo.from_jwk('value')

    def test_algorithm_should_throw_exception_if_from_jwk_not_impl(self):
        algo = Algorithm()

        with pytest.raises(NotImplementedError):
            algo.to_jwk('value')

    def test_none_algorithm_should_throw_exception_if_key_is_not_none(self):
        algo = NoneAlgorithm()

        with pytest.raises(InvalidKeyError):
            algo.prepare_key('123')

    def test_hmac_should_reject_nonstring_key(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)

        with pytest.raises(TypeError) as context:
            algo.prepare_key(object())

        exception = context.value
        assert str(exception) == 'Expected a string value'

    def test_hmac_should_accept_unicode_key(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)

        algo.prepare_key(force_unicode('awesome'))

    def test_hmac_should_throw_exception_if_key_is_pem_public_key(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)

        with pytest.raises(InvalidKeyError):
            with open(key_path('testkey2_rsa.pub.pem'), 'r') as keyfile:
                algo.prepare_key(keyfile.read())

    def test_hmac_should_throw_exception_if_key_is_x509_certificate(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)

        with pytest.raises(InvalidKeyError):
            with open(key_path('testkey_rsa.cer'), 'r') as keyfile:
                algo.prepare_key(keyfile.read())

    def test_hmac_should_throw_exception_if_key_is_ssh_public_key(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)

        with pytest.raises(InvalidKeyError):
            with open(key_path('testkey_rsa.pub'), 'r') as keyfile:
                algo.prepare_key(keyfile.read())

    def test_hmac_should_throw_exception_if_key_is_x509_cert(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)

        with pytest.raises(InvalidKeyError):
            with open(key_path('testkey2_rsa.pub.pem'), 'r') as keyfile:
                algo.prepare_key(keyfile.read())

    def test_hmac_should_throw_exception_if_key_is_pkcs1_pem_public(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)

        with pytest.raises(InvalidKeyError):
            with open(key_path('testkey_pkcs1.pub.pem'), 'r') as keyfile:
                algo.prepare_key(keyfile.read())

    def test_hmac_jwk_should_parse_and_verify(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)

        with open(key_path('jwk_hmac.json'), 'r') as keyfile:
            key = algo.from_jwk(keyfile.read())

        signature = algo.sign(b'Hello World!', key)
        assert algo.verify(b'Hello World!', key, signature)

    def test_hmac_to_jwk_returns_correct_values(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)
        key = algo.to_jwk('secret')

        assert json.loads(key) == {'kty': 'oct', 'k': 'c2VjcmV0'}

    def test_hmac_from_jwk_should_raise_exception_if_not_hmac_key(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)

        with open(key_path('jwk_rsa_pub.json'), 'r') as keyfile:
            with pytest.raises(InvalidKeyError):
                algo.from_jwk(keyfile.read())

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_rsa_should_parse_pem_public_key(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path('testkey2_rsa.pub.pem'), 'r') as pem_key:
            algo.prepare_key(pem_key.read())

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_rsa_should_accept_pem_private_key_bytes(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path('testkey_rsa'), 'rb') as pem_key:
            algo.prepare_key(pem_key.read())

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_rsa_should_accept_unicode_key(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path('testkey_rsa'), 'r') as rsa_key:
            algo.prepare_key(force_unicode(rsa_key.read()))

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_rsa_should_reject_non_string_key(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with pytest.raises(TypeError):
            algo.prepare_key(None)

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_rsa_verify_should_return_false_if_signature_invalid(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        message = force_bytes('Hello World!')

        sig = base64.b64decode(force_bytes(
            'yS6zk9DBkuGTtcBzLUzSpo9gGJxJFOGvUqN01iLhWHrzBQ9ZEz3+Ae38AXp'
            '10RWwscp42ySC85Z6zoN67yGkLNWnfmCZSEv+xqELGEvBJvciOKsrhiObUl'
            '2mveSc1oeO/2ujkGDkkkJ2epn0YliacVjZF5+/uDmImUfAAj8lzjnHlzYix'
            'sn5jGz1H07jYYbi9diixN8IUhXeTafwFg02IcONhum29V40Wu6O5tAKWlJX'
            'fHJnNUzAEUOXS0WahHVb57D30pcgIji9z923q90p5c7E2cU8V+E1qe8NdCA'
            'APCDzZZ9zQ/dgcMVaBrGrgimrcLbPjueOKFgSO+SSjIElKA=='))

        sig += force_bytes('123')  # Signature is now invalid

        with open(key_path('testkey_rsa.pub'), 'r') as keyfile:
            pub_key = algo.prepare_key(keyfile.read())

        result = algo.verify(message, pub_key, sig)
        assert not result

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_rsa_jwk_public_and_private_keys_should_parse_and_verify(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path('jwk_rsa_pub.json'), 'r') as keyfile:
            pub_key = algo.from_jwk(keyfile.read())

        with open(key_path('jwk_rsa_key.json'), 'r') as keyfile:
            priv_key = algo.from_jwk(keyfile.read())

        signature = algo.sign(force_bytes('Hello World!'), priv_key)
        assert algo.verify(force_bytes('Hello World!'), pub_key, signature)

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_rsa_private_key_to_jwk_works_with_from_jwk(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path('testkey_rsa'), 'r') as rsa_key:
            orig_key = algo.prepare_key(force_unicode(rsa_key.read()))

        parsed_key = algo.from_jwk(algo.to_jwk(orig_key))
        assert parsed_key.private_numbers() == orig_key.private_numbers()
        assert parsed_key.private_numbers().public_numbers == orig_key.private_numbers().public_numbers

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_rsa_public_key_to_jwk_works_with_from_jwk(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path('testkey_rsa.pub'), 'r') as rsa_key:
            orig_key = algo.prepare_key(force_unicode(rsa_key.read()))

        parsed_key = algo.from_jwk(algo.to_jwk(orig_key))
        assert parsed_key.public_numbers() == orig_key.public_numbers()

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_rsa_jwk_private_key_with_other_primes_is_invalid(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path('jwk_rsa_key.json'), 'r') as keyfile:
            with pytest.raises(InvalidKeyError):
                keydata = json.loads(keyfile.read())
                keydata['oth'] = []

                algo.from_jwk(json.dumps(keydata))

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_rsa_jwk_private_key_with_missing_values_is_invalid(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path('jwk_rsa_key.json'), 'r') as keyfile:
            with pytest.raises(InvalidKeyError):
                keydata = json.loads(keyfile.read())
                del keydata['p']

                algo.from_jwk(json.dumps(keydata))

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_rsa_jwk_private_key_can_recover_prime_factors(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path('jwk_rsa_key.json'), 'r') as keyfile:
            keybytes = keyfile.read()
            control_key = algo.from_jwk(keybytes).private_numbers()

            keydata = json.loads(keybytes)
            delete_these = ['p', 'q', 'dp', 'dq', 'qi']
            for field in delete_these:
                del keydata[field]

            parsed_key = algo.from_jwk(json.dumps(keydata)).private_numbers()

        assert control_key.d == parsed_key.d
        assert control_key.p == parsed_key.p
        assert control_key.q == parsed_key.q
        assert control_key.dmp1 == parsed_key.dmp1
        assert control_key.dmq1 == parsed_key.dmq1
        assert control_key.iqmp == parsed_key.iqmp

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_rsa_jwk_private_key_with_missing_required_values_is_invalid(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path('jwk_rsa_key.json'), 'r') as keyfile:
            with pytest.raises(InvalidKeyError):
                keydata = json.loads(keyfile.read())
                del keydata['p']

                algo.from_jwk(json.dumps(keydata))

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_rsa_jwk_raises_exception_if_not_a_valid_key(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        # Invalid JSON
        with pytest.raises(InvalidKeyError):
            algo.from_jwk('{not-a-real-key')

        # Missing key parts
        with pytest.raises(InvalidKeyError):
            algo.from_jwk('{"kty": "RSA"}')

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_rsa_to_jwk_returns_correct_values_for_public_key(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path('testkey_rsa.pub'), 'r') as keyfile:
            pub_key = algo.prepare_key(keyfile.read())

        key = algo.to_jwk(pub_key)

        expected = {
            'e': 'AQAB',
            'key_ops': ['verify'],
            'kty': 'RSA',
            'n': (
                '1HgzBfJv2cOjQryCwe8NEelriOTNFWKZUivevUrRhlqcmZJdCvuCJRr-xCN-'
                'OmO8qwgJJR98feNujxVg-J9Ls3_UOA4HcF9nYH6aqVXELAE8Hk_ALvxi96ms'
                '1DDuAvQGaYZ-lANxlvxeQFOZSbjkz_9mh8aLeGKwqJLp3p-OhUBQpwvAUAPg'
                '82-OUtgTW3nSljjeFr14B8qAneGSc_wl0ni--1SRZUXFSovzcqQOkla3W27r'
                'rLfrD6LXgj_TsDs4vD1PnIm1zcVenKT7TfYI17bsG_O_Wecwz2Nl19pL7gDo'
                'sNruF3ogJWNq1Lyn_ijPQnkPLpZHyhvuiycYcI3DiQ'
            ),
        }
        assert json.loads(key) == expected

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_rsa_to_jwk_returns_correct_values_for_private_key(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path('testkey_rsa'), 'r') as keyfile:
            priv_key = algo.prepare_key(keyfile.read())

        key = algo.to_jwk(priv_key)

        expected = {
            'key_ops': [u'sign'],
            'kty': 'RSA',
            'e': 'AQAB',
            'n': (
                '1HgzBfJv2cOjQryCwe8NEelriOTNFWKZUivevUrRhlqcmZJdCvuCJRr-xCN-'
                'OmO8qwgJJR98feNujxVg-J9Ls3_UOA4HcF9nYH6aqVXELAE8Hk_ALvxi96ms'
                '1DDuAvQGaYZ-lANxlvxeQFOZSbjkz_9mh8aLeGKwqJLp3p-OhUBQpwvAUAPg'
                '82-OUtgTW3nSljjeFr14B8qAneGSc_wl0ni--1SRZUXFSovzcqQOkla3W27r'
                'rLfrD6LXgj_TsDs4vD1PnIm1zcVenKT7TfYI17bsG_O_Wecwz2Nl19pL7gDo'
                'sNruF3ogJWNq1Lyn_ijPQnkPLpZHyhvuiycYcI3DiQ'
            ),
            'd': ('rfbs8AWdB1RkLJRlC51LukrAvYl5UfU1TE6XRa4o-DTg2-03OXLNEMyVpMr'
                  'a47weEnu14StypzC8qXL7vxXOyd30SSFTffLfleaTg-qxgMZSDw-Fb_M-pU'
                  'HMPMEDYG-lgGma4l4fd1yTX2ATtoUo9BVOQgWS1LMZqi0ASEOkUfzlBgL04'
                  'UoaLhPSuDdLygdlDzgruVPnec0t1uOEObmrcWIkhwU2CGQzeLtuzX6OVgPh'
                  'k7xcnjbDurTTVpWH0R0gbZ5ukmQ2P-YuCX8T9iWNMGjPNSkb7h02s2Oe9ZR'
                  'zP007xQ0VF-Z7xyLuxk6ASmoX1S39ujSbk2WF0eXNPRgFwQ'),
            'q': ('47hlW2f1ARuWYJf9Dl6MieXjdj2dGx9PL2UH0unVzJYInd56nqXNPrQrc5k'
                  'ZU65KApC9n9oKUwIxuqwAAbh8oGNEQDqnuTj-powCkdC6bwA8KH1Y-wotpq'
                  '_GSjxkNzjWRm2GArJSzZc6Fb8EuObOrAavKJ285-zMPCEfus1WZG0'),
            'p': ('7tr0z929Lp4OHIRJjIKM_rDrWMPtRgnV-51pgWsN6qdpDzns_PgFwrHcoyY'
                  'sWIO-4yCdVWPxFOgEZ8xXTM_uwOe4VEmdZhw55Tx7axYZtmZYZbO_RIP4CG'
                  'mlJlOFTiYnxpr-2Cx6kIeQmd-hf7fA3tL018aEzwYMbFMcnAGnEg0'),
            'qi': ('djo95mB0LVYikNPa-NgyDwLotLqrueb9IviMmn6zKHCwiOXReqXDX9slB8'
                   'RA15uv56bmN04O__NyVFcgJ2ef169GZHiRFIgIy0Pl8LYkMhCYKKhyqM7g'
                   'xN-SqGqDTKDC22j00S7jcvCaa1qadn1qbdfukZ4NXv7E2d_LO0Y2Kkc'),
            'dp': ('tgZ2-tJpEdWxu1m1EzeKa644LHVjpTRptk7H0LDc8i6SieADEuWQvkb9df'
                   'fpY6tDFaQNQr3fQ6dtdAztmsP7l1b_ynwvT1nDZUcqZvl4ruBgDWFmKbjI'
                   'lOCt0v9jX6MEPP5xqBx9axdkw18BnGtUuHrbzHSlUX-yh_rumpVH1SE'),
            'dq': ('xxCIuhD0YlWFbUcwFgGdBWcLIm_WCMGj7SB6aGu1VDTLr4Wu10TFWM0TNu'
                   'hc9YPker2gpj5qzAmdAzwcfWSSvXpJTYR43jfulBTMoj8-2o3wCM0anclW'
                   'AuKhin-kc4mh9ssDXRQZwlMymZP0QtaxUDw_nlfVrUCZgO7L1_ZsUTk')
        }
        assert json.loads(key) == expected

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_rsa_to_jwk_raises_exception_on_invalid_key(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with pytest.raises(InvalidKeyError):
            algo.to_jwk({'not': 'a valid key'})

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_rsa_from_jwk_raises_exception_on_invalid_key(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path('jwk_hmac.json'), 'r') as keyfile:
            with pytest.raises(InvalidKeyError):
                algo.from_jwk(keyfile.read())

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_ec_should_reject_non_string_key(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        with pytest.raises(TypeError):
            algo.prepare_key(None)

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_ec_should_accept_unicode_key(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        with open(key_path('testkey_ec'), 'r') as ec_key:
            algo.prepare_key(force_unicode(ec_key.read()))

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_ec_should_accept_pem_private_key_bytes(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        with open(key_path('testkey_ec'), 'rb') as ec_key:
            algo.prepare_key(ec_key.read())

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_ec_should_accept_ssh_public_key_bytes(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        with open(key_path('testkey_ec_ssh.pub'), 'r') as ec_key:
            algo.prepare_key(ec_key.read())

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_ec_verify_should_return_false_if_signature_invalid(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        message = force_bytes('Hello World!')

        # Mess up the signature by replacing a known byte
        sig = base64.b64decode(force_bytes(
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

        message = force_bytes('Hello World!')

        sig = base64.b64decode(force_bytes('AC+m4Jf/xI3guAC6w0w3'))

        with open(key_path('testkey_ec.pub'), 'r') as keyfile:
            pub_key = algo.prepare_key(keyfile.read())

        result = algo.verify(message, pub_key, sig)
        assert not result

    @pytest.mark.skipif(not has_crypto, reason='Not supported without cryptography library')
    def test_rsa_pss_sign_then_verify_should_return_true(self):
        algo = RSAPSSAlgorithm(RSAPSSAlgorithm.SHA256)

        message = force_bytes('Hello World!')

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

        jwt_message = force_bytes('Hello World!')

        jwt_sig = base64.b64decode(force_bytes(
            'ywKAUGRIDC//6X+tjvZA96yEtMqpOrSppCNfYI7NKyon3P7doud5v65oWNu'
            'vQsz0fzPGfF7mQFGo9Cm9Vn0nljm4G6PtqZRbz5fXNQBH9k10gq34AtM02c'
            '/cveqACQ8gF3zxWh6qr9jVqIpeMEaEBIkvqG954E0HT9s9ybHShgHX9mlWk'
            '186/LopP4xe5c/hxOQjwhv6yDlTiwJFiqjNCvj0GyBKsc4iECLGIIO+4mC4'
            'daOCWqbpZDuLb1imKpmm8Nsm56kAxijMLZnpCcnPgyb7CqG+B93W9GHglA5'
            'drUeR1gRtO7vqbZMsCAQ4bpjXxwbYyjQlEVuMl73UL6sOWg=='))

        jwt_sig += force_bytes('123')  # Signature is now invalid

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
        signing_input = force_bytes(
            'eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZ'
            'jMxNGJjNzAzNyJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ'
            '29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIG'
            'lmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmc'
            'gd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4'
        )

        signature = base64url_decode(force_bytes(
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
        signing_input = force_bytes(
            'eyJhbGciOiJSUzI1NiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhb'
            'XBsZSJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb'
            '3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdS'
            'Bkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmU'
            'geW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4'
        )

        signature = base64url_decode(force_bytes(
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
        signing_input = force_bytes(
            'eyJhbGciOiJQUzM4NCIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhb'
            'XBsZSJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb'
            '3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdS'
            'Bkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmU'
            'geW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4'
        )

        signature = base64url_decode(force_bytes(
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
        signing_input = force_bytes(
            'eyJhbGciOiJFUzUxMiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhb'
            'XBsZSJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb'
            '3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdS'
            'Bkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmU'
            'geW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4'
        )

        signature = base64url_decode(force_bytes(
            'AE_R_YZCChjn4791jSQCrdPZCNYqHXCTZH0-JZGYNlaAjP2kqaluUIIUnC9qvbu9P'
            'lon7KRTzoNEuT4Va2cmL1eJAQy3mtPBu_u_sDDyYjnAMDxXPn7XrT0lw-kvAD890j'
            'l8e2puQens_IEKBpHABlsbEPX6sFY8OcGDqoRuBomu9xQ2'
        ))

        algo = ECAlgorithm(ECAlgorithm.SHA512)
        key = algo.prepare_key(load_ec_pub_key())

        result = algo.verify(signing_input, key, signature)
        assert result
