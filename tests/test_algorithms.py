import base64
import json

import pytest

from jwt.algorithms import Algorithm, HMACAlgorithm, NoneAlgorithm, has_crypto
from jwt.exceptions import InvalidKeyError
from jwt.utils import base64url_decode

from .keys import load_ec_pub_key_p_521, load_hmac_key, load_rsa_pub_key
from .utils import crypto_required, key_path

if has_crypto:
    from jwt.algorithms import (
        ECAlgorithm,
        Ed25519Algorithm,
        RSAAlgorithm,
        RSAPSSAlgorithm,
    )


class TestAlgorithms:
    def test_algorithm_should_throw_exception_if_prepare_key_not_impl(self):
        algo = Algorithm()

        with pytest.raises(NotImplementedError):
            algo.prepare_key("test")

    def test_algorithm_should_throw_exception_if_sign_not_impl(self):
        algo = Algorithm()

        with pytest.raises(NotImplementedError):
            algo.sign("message", "key")

    def test_algorithm_should_throw_exception_if_verify_not_impl(self):
        algo = Algorithm()

        with pytest.raises(NotImplementedError):
            algo.verify("message", "key", "signature")

    def test_algorithm_should_throw_exception_if_to_jwk_not_impl(self):
        algo = Algorithm()

        with pytest.raises(NotImplementedError):
            algo.from_jwk("value")

    def test_algorithm_should_throw_exception_if_from_jwk_not_impl(self):
        algo = Algorithm()

        with pytest.raises(NotImplementedError):
            algo.to_jwk("value")

    def test_none_algorithm_should_throw_exception_if_key_is_not_none(self):
        algo = NoneAlgorithm()

        with pytest.raises(InvalidKeyError):
            algo.prepare_key("123")

    def test_hmac_should_reject_nonstring_key(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)

        with pytest.raises(TypeError) as context:
            algo.prepare_key(object())

        exception = context.value
        assert str(exception) == "Expected a string value"

    def test_hmac_should_accept_unicode_key(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)

        algo.prepare_key("awesome")

    def test_hmac_should_throw_exception_if_key_is_pem_public_key(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)

        with pytest.raises(InvalidKeyError):
            with open(key_path("testkey2_rsa.pub.pem")) as keyfile:
                algo.prepare_key(keyfile.read())

    def test_hmac_should_throw_exception_if_key_is_x509_certificate(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)

        with pytest.raises(InvalidKeyError):
            with open(key_path("testkey_rsa.cer")) as keyfile:
                algo.prepare_key(keyfile.read())

    def test_hmac_should_throw_exception_if_key_is_ssh_public_key(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)

        with pytest.raises(InvalidKeyError):
            with open(key_path("testkey_rsa.pub")) as keyfile:
                algo.prepare_key(keyfile.read())

    def test_hmac_should_throw_exception_if_key_is_x509_cert(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)

        with pytest.raises(InvalidKeyError):
            with open(key_path("testkey2_rsa.pub.pem")) as keyfile:
                algo.prepare_key(keyfile.read())

    def test_hmac_should_throw_exception_if_key_is_pkcs1_pem_public(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)

        with pytest.raises(InvalidKeyError):
            with open(key_path("testkey_pkcs1.pub.pem")) as keyfile:
                algo.prepare_key(keyfile.read())

    def test_hmac_jwk_should_parse_and_verify(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)

        with open(key_path("jwk_hmac.json")) as keyfile:
            key = algo.from_jwk(keyfile.read())

        signature = algo.sign(b"Hello World!", key)
        assert algo.verify(b"Hello World!", key, signature)

    def test_hmac_to_jwk_returns_correct_values(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)
        key = algo.to_jwk("secret")

        assert json.loads(key) == {"kty": "oct", "k": "c2VjcmV0"}

    def test_hmac_from_jwk_should_raise_exception_if_not_hmac_key(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)

        with open(key_path("jwk_rsa_pub.json")) as keyfile:
            with pytest.raises(InvalidKeyError):
                algo.from_jwk(keyfile.read())

    @crypto_required
    def test_rsa_should_parse_pem_public_key(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path("testkey2_rsa.pub.pem")) as pem_key:
            algo.prepare_key(pem_key.read())

    @crypto_required
    def test_rsa_should_accept_pem_private_key_bytes(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path("testkey_rsa.priv"), "rb") as pem_key:
            algo.prepare_key(pem_key.read())

    @crypto_required
    def test_rsa_should_accept_unicode_key(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path("testkey_rsa.priv")) as rsa_key:
            algo.prepare_key(rsa_key.read())

    @crypto_required
    def test_rsa_should_reject_non_string_key(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with pytest.raises(TypeError):
            algo.prepare_key(None)

    @crypto_required
    def test_rsa_verify_should_return_false_if_signature_invalid(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        message = b"Hello World!"

        sig = base64.b64decode(
            b"yS6zk9DBkuGTtcBzLUzSpo9gGJxJFOGvUqN01iLhWHrzBQ9ZEz3+Ae38AXp"
            b"10RWwscp42ySC85Z6zoN67yGkLNWnfmCZSEv+xqELGEvBJvciOKsrhiObUl"
            b"2mveSc1oeO/2ujkGDkkkJ2epn0YliacVjZF5+/uDmImUfAAj8lzjnHlzYix"
            b"sn5jGz1H07jYYbi9diixN8IUhXeTafwFg02IcONhum29V40Wu6O5tAKWlJX"
            b"fHJnNUzAEUOXS0WahHVb57D30pcgIji9z923q90p5c7E2cU8V+E1qe8NdCA"
            b"APCDzZZ9zQ/dgcMVaBrGrgimrcLbPjueOKFgSO+SSjIElKA=="
        )

        sig += b"123"  # Signature is now invalid

        with open(key_path("testkey_rsa.pub")) as keyfile:
            pub_key = algo.prepare_key(keyfile.read())

        result = algo.verify(message, pub_key, sig)
        assert not result

    @crypto_required
    def test_ec_jwk_public_and_private_keys_should_parse_and_verify(self):
        tests = {
            "P-256": ECAlgorithm.SHA256,
            "P-384": ECAlgorithm.SHA384,
            "P-521": ECAlgorithm.SHA512,
        }
        for (curve, hash) in tests.items():
            algo = ECAlgorithm(hash)

            with open(key_path(f"jwk_ec_pub_{curve}.json")) as keyfile:
                pub_key = algo.from_jwk(keyfile.read())

            with open(key_path(f"jwk_ec_key_{curve}.json")) as keyfile:
                priv_key = algo.from_jwk(keyfile.read())

            signature = algo.sign(b"Hello World!", priv_key)
            assert algo.verify(b"Hello World!", pub_key, signature)

    @crypto_required
    def test_ec_jwk_fails_on_invalid_json(self):
        algo = ECAlgorithm(ECAlgorithm.SHA512)

        valid_points = {
            "P-256": {
                "x": "PTTjIY84aLtaZCxLTrG_d8I0G6YKCV7lg8M4xkKfwQ4=",
                "y": "ank6KA34vv24HZLXlChVs85NEGlpg2sbqNmR_BcgyJU=",
            },
            "P-384": {
                "x": "IDC-5s6FERlbC4Nc_4JhKW8sd51AhixtMdNUtPxhRFP323QY6cwWeIA3leyZhz-J",
                "y": "eovmN9ocANS8IJxDAGSuC1FehTq5ZFLJU7XSPg36zHpv4H2byKGEcCBiwT4sFJsy",
            },
            "P-521": {
                "x": "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
                "y": "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1",
            },
        }

        # Invalid JSON
        with pytest.raises(InvalidKeyError):
            algo.from_jwk("<this isn't json>")

        # Bad key type
        with pytest.raises(InvalidKeyError):
            algo.from_jwk('{"kty": "RSA"}')

        # Missing data
        with pytest.raises(InvalidKeyError):
            algo.from_jwk('{"kty": "EC"}')
        with pytest.raises(InvalidKeyError):
            algo.from_jwk('{"kty": "EC", "x": "1"}')
        with pytest.raises(InvalidKeyError):
            algo.from_jwk('{"kty": "EC", "y": "1"}')

        # Missing curve
        with pytest.raises(InvalidKeyError):
            algo.from_jwk('{"kty": "EC", "x": "dGVzdA==", "y": "dGVzdA=="}')

        # EC coordinates not equally long
        with pytest.raises(InvalidKeyError):
            algo.from_jwk(
                '{"kty": "EC", "x": "dGVzdHRlc3Q=", "y": "dGVzdA=="}'
            )

        # EC coordinates length invalid
        for curve in ("P-256", "P-384", "P-521"):
            with pytest.raises(InvalidKeyError):
                algo.from_jwk(
                    '{{"kty": "EC", "crv": "{}", "x": "dGVzdA==", '
                    '"y": "dGVzdA=="}}'.format(curve)
                )

        # EC private key length invalid
        for (curve, point) in valid_points.items():
            with pytest.raises(InvalidKeyError):
                algo.from_jwk(
                    '{{"kty": "EC", "crv": "{}", "x": "{}", "y": "{}", '
                    '"d": "dGVzdA=="}}'.format(curve, point["x"], point["y"])
                )

    @crypto_required
    def test_rsa_jwk_public_and_private_keys_should_parse_and_verify(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path("jwk_rsa_pub.json")) as keyfile:
            pub_key = algo.from_jwk(keyfile.read())

        with open(key_path("jwk_rsa_key.json")) as keyfile:
            priv_key = algo.from_jwk(keyfile.read())

        signature = algo.sign(b"Hello World!", priv_key)
        assert algo.verify(b"Hello World!", pub_key, signature)

    @crypto_required
    def test_rsa_private_key_to_jwk_works_with_from_jwk(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path("testkey_rsa.priv")) as rsa_key:
            orig_key = algo.prepare_key(rsa_key.read())

        parsed_key = algo.from_jwk(algo.to_jwk(orig_key))
        assert parsed_key.private_numbers() == orig_key.private_numbers()
        assert (
            parsed_key.private_numbers().public_numbers
            == orig_key.private_numbers().public_numbers
        )

    @crypto_required
    def test_rsa_public_key_to_jwk_works_with_from_jwk(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path("testkey_rsa.pub")) as rsa_key:
            orig_key = algo.prepare_key(rsa_key.read())

        parsed_key = algo.from_jwk(algo.to_jwk(orig_key))
        assert parsed_key.public_numbers() == orig_key.public_numbers()

    @crypto_required
    def test_rsa_jwk_private_key_with_other_primes_is_invalid(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path("jwk_rsa_key.json")) as keyfile:
            with pytest.raises(InvalidKeyError):
                keydata = json.loads(keyfile.read())
                keydata["oth"] = []

                algo.from_jwk(json.dumps(keydata))

    @crypto_required
    def test_rsa_jwk_private_key_with_missing_values_is_invalid(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path("jwk_rsa_key.json")) as keyfile:
            with pytest.raises(InvalidKeyError):
                keydata = json.loads(keyfile.read())
                del keydata["p"]

                algo.from_jwk(json.dumps(keydata))

    @crypto_required
    def test_rsa_jwk_private_key_can_recover_prime_factors(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path("jwk_rsa_key.json")) as keyfile:
            keybytes = keyfile.read()
            control_key = algo.from_jwk(keybytes).private_numbers()

            keydata = json.loads(keybytes)
            delete_these = ["p", "q", "dp", "dq", "qi"]
            for field in delete_these:
                del keydata[field]

            parsed_key = algo.from_jwk(json.dumps(keydata)).private_numbers()

        assert control_key.d == parsed_key.d
        assert control_key.p == parsed_key.p
        assert control_key.q == parsed_key.q
        assert control_key.dmp1 == parsed_key.dmp1
        assert control_key.dmq1 == parsed_key.dmq1
        assert control_key.iqmp == parsed_key.iqmp

    @crypto_required
    def test_rsa_jwk_private_key_with_missing_required_values_is_invalid(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path("jwk_rsa_key.json")) as keyfile:
            with pytest.raises(InvalidKeyError):
                keydata = json.loads(keyfile.read())
                del keydata["p"]

                algo.from_jwk(json.dumps(keydata))

    @crypto_required
    def test_rsa_jwk_raises_exception_if_not_a_valid_key(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        # Invalid JSON
        with pytest.raises(InvalidKeyError):
            algo.from_jwk("{not-a-real-key")

        # Missing key parts
        with pytest.raises(InvalidKeyError):
            algo.from_jwk('{"kty": "RSA"}')

    @crypto_required
    def test_rsa_to_jwk_returns_correct_values_for_public_key(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path("testkey_rsa.pub")) as keyfile:
            pub_key = algo.prepare_key(keyfile.read())

        key = algo.to_jwk(pub_key)

        expected = {
            "e": "AQAB",
            "key_ops": ["verify"],
            "kty": "RSA",
            "n": (
                "1HgzBfJv2cOjQryCwe8NEelriOTNFWKZUivevUrRhlqcmZJdCvuCJRr-xCN-"
                "OmO8qwgJJR98feNujxVg-J9Ls3_UOA4HcF9nYH6aqVXELAE8Hk_ALvxi96ms"
                "1DDuAvQGaYZ-lANxlvxeQFOZSbjkz_9mh8aLeGKwqJLp3p-OhUBQpwvAUAPg"
                "82-OUtgTW3nSljjeFr14B8qAneGSc_wl0ni--1SRZUXFSovzcqQOkla3W27r"
                "rLfrD6LXgj_TsDs4vD1PnIm1zcVenKT7TfYI17bsG_O_Wecwz2Nl19pL7gDo"
                "sNruF3ogJWNq1Lyn_ijPQnkPLpZHyhvuiycYcI3DiQ"
            ),
        }
        assert json.loads(key) == expected

    @crypto_required
    def test_rsa_to_jwk_returns_correct_values_for_private_key(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path("testkey_rsa.priv")) as keyfile:
            priv_key = algo.prepare_key(keyfile.read())

        key = algo.to_jwk(priv_key)

        expected = {
            "key_ops": ["sign"],
            "kty": "RSA",
            "e": "AQAB",
            "n": (
                "1HgzBfJv2cOjQryCwe8NEelriOTNFWKZUivevUrRhlqcmZJdCvuCJRr-xCN-"
                "OmO8qwgJJR98feNujxVg-J9Ls3_UOA4HcF9nYH6aqVXELAE8Hk_ALvxi96ms"
                "1DDuAvQGaYZ-lANxlvxeQFOZSbjkz_9mh8aLeGKwqJLp3p-OhUBQpwvAUAPg"
                "82-OUtgTW3nSljjeFr14B8qAneGSc_wl0ni--1SRZUXFSovzcqQOkla3W27r"
                "rLfrD6LXgj_TsDs4vD1PnIm1zcVenKT7TfYI17bsG_O_Wecwz2Nl19pL7gDo"
                "sNruF3ogJWNq1Lyn_ijPQnkPLpZHyhvuiycYcI3DiQ"
            ),
            "d": (
                "rfbs8AWdB1RkLJRlC51LukrAvYl5UfU1TE6XRa4o-DTg2-03OXLNEMyVpMr"
                "a47weEnu14StypzC8qXL7vxXOyd30SSFTffLfleaTg-qxgMZSDw-Fb_M-pU"
                "HMPMEDYG-lgGma4l4fd1yTX2ATtoUo9BVOQgWS1LMZqi0ASEOkUfzlBgL04"
                "UoaLhPSuDdLygdlDzgruVPnec0t1uOEObmrcWIkhwU2CGQzeLtuzX6OVgPh"
                "k7xcnjbDurTTVpWH0R0gbZ5ukmQ2P-YuCX8T9iWNMGjPNSkb7h02s2Oe9ZR"
                "zP007xQ0VF-Z7xyLuxk6ASmoX1S39ujSbk2WF0eXNPRgFwQ"
            ),
            "q": (
                "47hlW2f1ARuWYJf9Dl6MieXjdj2dGx9PL2UH0unVzJYInd56nqXNPrQrc5k"
                "ZU65KApC9n9oKUwIxuqwAAbh8oGNEQDqnuTj-powCkdC6bwA8KH1Y-wotpq"
                "_GSjxkNzjWRm2GArJSzZc6Fb8EuObOrAavKJ285-zMPCEfus1WZG0"
            ),
            "p": (
                "7tr0z929Lp4OHIRJjIKM_rDrWMPtRgnV-51pgWsN6qdpDzns_PgFwrHcoyY"
                "sWIO-4yCdVWPxFOgEZ8xXTM_uwOe4VEmdZhw55Tx7axYZtmZYZbO_RIP4CG"
                "mlJlOFTiYnxpr-2Cx6kIeQmd-hf7fA3tL018aEzwYMbFMcnAGnEg0"
            ),
            "qi": (
                "djo95mB0LVYikNPa-NgyDwLotLqrueb9IviMmn6zKHCwiOXReqXDX9slB8"
                "RA15uv56bmN04O__NyVFcgJ2ef169GZHiRFIgIy0Pl8LYkMhCYKKhyqM7g"
                "xN-SqGqDTKDC22j00S7jcvCaa1qadn1qbdfukZ4NXv7E2d_LO0Y2Kkc"
            ),
            "dp": (
                "tgZ2-tJpEdWxu1m1EzeKa644LHVjpTRptk7H0LDc8i6SieADEuWQvkb9df"
                "fpY6tDFaQNQr3fQ6dtdAztmsP7l1b_ynwvT1nDZUcqZvl4ruBgDWFmKbjI"
                "lOCt0v9jX6MEPP5xqBx9axdkw18BnGtUuHrbzHSlUX-yh_rumpVH1SE"
            ),
            "dq": (
                "xxCIuhD0YlWFbUcwFgGdBWcLIm_WCMGj7SB6aGu1VDTLr4Wu10TFWM0TNu"
                "hc9YPker2gpj5qzAmdAzwcfWSSvXpJTYR43jfulBTMoj8-2o3wCM0anclW"
                "AuKhin-kc4mh9ssDXRQZwlMymZP0QtaxUDw_nlfVrUCZgO7L1_ZsUTk"
            ),
        }
        assert json.loads(key) == expected

    @crypto_required
    def test_rsa_to_jwk_raises_exception_on_invalid_key(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with pytest.raises(InvalidKeyError):
            algo.to_jwk({"not": "a valid key"})

    @crypto_required
    def test_rsa_from_jwk_raises_exception_on_invalid_key(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path("jwk_hmac.json")) as keyfile:
            with pytest.raises(InvalidKeyError):
                algo.from_jwk(keyfile.read())

    @crypto_required
    def test_ec_should_reject_non_string_key(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        with pytest.raises(TypeError):
            algo.prepare_key(None)

    @crypto_required
    def test_ec_should_accept_pem_private_key_bytes(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        with open(key_path("testkey_ec.priv"), "rb") as ec_key:
            algo.prepare_key(ec_key.read())

    @crypto_required
    def test_ec_should_accept_ssh_public_key_bytes(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        with open(key_path("testkey_ec_ssh.pub")) as ec_key:
            algo.prepare_key(ec_key.read())

    @crypto_required
    def test_ec_verify_should_return_false_if_signature_invalid(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        message = b"Hello World!"

        # Mess up the signature by replacing a known byte
        sig = base64.b64decode(
            b"AC+m4Jf/xI3guAC6w0w37t5zRpSCF6F4udEz5LiMiTIjCS4vcVe6dDOxK+M"
            b"mvkF8PxJuvqxP2CO3TR3okDPCl/NjATTO1jE+qBZ966CRQSSzcCM+tzcHzw"
            b"LZS5kbvKu0Acd/K6Ol2/W3B1NeV5F/gjvZn/jOwaLgWEUYsg0o4XVrAg65".replace(
                b"r", b"s"
            )
        )

        with open(key_path("testkey_ec.pub")) as keyfile:
            pub_key = algo.prepare_key(keyfile.read())

        result = algo.verify(message, pub_key, sig)
        assert not result

    @crypto_required
    def test_ec_verify_should_return_false_if_signature_wrong_length(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        message = b"Hello World!"

        sig = base64.b64decode(b"AC+m4Jf/xI3guAC6w0w3")

        with open(key_path("testkey_ec.pub")) as keyfile:
            pub_key = algo.prepare_key(keyfile.read())

        result = algo.verify(message, pub_key, sig)
        assert not result

    @crypto_required
    def test_rsa_pss_sign_then_verify_should_return_true(self):
        algo = RSAPSSAlgorithm(RSAPSSAlgorithm.SHA256)

        message = b"Hello World!"

        with open(key_path("testkey_rsa.priv")) as keyfile:
            priv_key = algo.prepare_key(keyfile.read())
            sig = algo.sign(message, priv_key)

        with open(key_path("testkey_rsa.pub")) as keyfile:
            pub_key = algo.prepare_key(keyfile.read())

        result = algo.verify(message, pub_key, sig)
        assert result

    @crypto_required
    def test_rsa_pss_verify_should_return_false_if_signature_invalid(self):
        algo = RSAPSSAlgorithm(RSAPSSAlgorithm.SHA256)

        jwt_message = b"Hello World!"

        jwt_sig = base64.b64decode(
            b"ywKAUGRIDC//6X+tjvZA96yEtMqpOrSppCNfYI7NKyon3P7doud5v65oWNu"
            b"vQsz0fzPGfF7mQFGo9Cm9Vn0nljm4G6PtqZRbz5fXNQBH9k10gq34AtM02c"
            b"/cveqACQ8gF3zxWh6qr9jVqIpeMEaEBIkvqG954E0HT9s9ybHShgHX9mlWk"
            b"186/LopP4xe5c/hxOQjwhv6yDlTiwJFiqjNCvj0GyBKsc4iECLGIIO+4mC4"
            b"daOCWqbpZDuLb1imKpmm8Nsm56kAxijMLZnpCcnPgyb7CqG+B93W9GHglA5"
            b"drUeR1gRtO7vqbZMsCAQ4bpjXxwbYyjQlEVuMl73UL6sOWg=="
        )

        jwt_sig += b"123"  # Signature is now invalid

        with open(key_path("testkey_rsa.pub")) as keyfile:
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
        signing_input = (
            b"eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZ"
            b"jMxNGJjNzAzNyJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ"
            b"29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIG"
            b"lmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmc"
            b"gd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4"
        )

        signature = base64url_decode(
            b"s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0"
        )

        algo = HMACAlgorithm(HMACAlgorithm.SHA256)
        key = algo.prepare_key(load_hmac_key())

        result = algo.verify(signing_input, key, signature)
        assert result

    @crypto_required
    def test_rsa_verify_should_return_true_for_test_vector(self):
        """
        This test verifies that RSA PKCS v1.5 verification works with a known
        good signature and key.

        Reference: https://tools.ietf.org/html/rfc7520#section-4.1
        """
        signing_input = (
            b"eyJhbGciOiJSUzI1NiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhb"
            b"XBsZSJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb"
            b"3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdS"
            b"Bkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmU"
            b"geW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4"
        )

        signature = base64url_decode(
            b"MRjdkly7_-oTPTS3AXP41iQIGKa80A0ZmTuV5MEaHoxnW2e5CZ5NlKtainoFmKZop"
            b"dHM1O2U4mwzJdQx996ivp83xuglII7PNDi84wnB-BDkoBwA78185hX-Es4JIwmDLJ"
            b"K3lfWRa-XtL0RnltuYv746iYTh_qHRD68BNt1uSNCrUCTJDt5aAE6x8wW1Kt9eRo4"
            b"QPocSadnHXFxnt8Is9UzpERV0ePPQdLuW3IS_de3xyIrDaLGdjluPxUAhb6L2aXic"
            b"1U12podGU0KLUQSE_oI-ZnmKJ3F4uOZDnd6QZWJushZ41Axf_fcIe8u9ipH84ogor"
            b"ee7vjbU5y18kDquDg"
        )

        algo = RSAAlgorithm(RSAAlgorithm.SHA256)
        key = algo.prepare_key(load_rsa_pub_key())

        result = algo.verify(signing_input, key, signature)
        assert result

    @crypto_required
    def test_rsapss_verify_should_return_true_for_test_vector(self):
        """
        This test verifies that RSA-PSS verification works with a known good
        signature and key.

        Reference: https://tools.ietf.org/html/rfc7520#section-4.2
        """
        signing_input = (
            b"eyJhbGciOiJQUzM4NCIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhb"
            b"XBsZSJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb"
            b"3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdS"
            b"Bkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmU"
            b"geW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4"
        )

        signature = base64url_decode(
            b"cu22eBqkYDKgIlTpzDXGvaFfz6WGoz7fUDcfT0kkOy42miAh2qyBzk1xEsnk2IpN6"
            b"-tPid6VrklHkqsGqDqHCdP6O8TTB5dDDItllVo6_1OLPpcbUrhiUSMxbbXUvdvWXz"
            b"g-UD8biiReQFlfz28zGWVsdiNAUf8ZnyPEgVFn442ZdNqiVJRmBqrYRXe8P_ijQ7p"
            b"8Vdz0TTrxUeT3lm8d9shnr2lfJT8ImUjvAA2Xez2Mlp8cBE5awDzT0qI0n6uiP1aC"
            b"N_2_jLAeQTlqRHtfa64QQSUmFAAjVKPbByi7xho0uTOcbH510a6GYmJUAfmWjwZ6o"
            b"D4ifKo8DYM-X72Eaw"
        )

        algo = RSAPSSAlgorithm(RSAPSSAlgorithm.SHA384)
        key = algo.prepare_key(load_rsa_pub_key())

        result = algo.verify(signing_input, key, signature)
        assert result

    @crypto_required
    def test_ec_verify_should_return_true_for_test_vector(self):
        """
        This test verifies that ECDSA verification works with a known good
        signature and key.

        Reference: https://tools.ietf.org/html/rfc7520#section-4.3
        """
        signing_input = (
            b"eyJhbGciOiJFUzUxMiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhb"
            b"XBsZSJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb"
            b"3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdS"
            b"Bkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmU"
            b"geW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4"
        )

        signature = base64url_decode(
            b"AE_R_YZCChjn4791jSQCrdPZCNYqHXCTZH0-JZGYNlaAjP2kqaluUIIUnC9qvbu9P"
            b"lon7KRTzoNEuT4Va2cmL1eJAQy3mtPBu_u_sDDyYjnAMDxXPn7XrT0lw-kvAD890j"
            b"l8e2puQens_IEKBpHABlsbEPX6sFY8OcGDqoRuBomu9xQ2"
        )

        algo = ECAlgorithm(ECAlgorithm.SHA512)
        key = algo.prepare_key(load_ec_pub_key_p_521())

        result = algo.verify(signing_input, key, signature)
        assert result


@crypto_required
class TestEd25519Algorithms:
    hello_world_sig = b"Qxa47mk/azzUgmY2StAOguAd4P7YBLpyCfU3JdbaiWnXM4o4WibXwmIHvNYgN3frtE2fcyd8OYEaOiD/KiwkCg=="
    hello_world = b"Hello World!"

    def test_ed25519_should_reject_non_string_key(self):
        algo = Ed25519Algorithm()

        with pytest.raises(TypeError):
            algo.prepare_key(None)

        with open(key_path("testkey_ed25519")) as keyfile:
            algo.prepare_key(keyfile.read())

        with open(key_path("testkey_ed25519.pub")) as keyfile:
            algo.prepare_key(keyfile.read())

    def test_ed25519_should_accept_unicode_key(self):
        algo = Ed25519Algorithm()

        with open(key_path("testkey_ed25519")) as ec_key:
            algo.prepare_key(ec_key.read())

    def test_ed25519_sign_should_generate_correct_signature_value(self):
        algo = Ed25519Algorithm()

        jwt_message = self.hello_world

        expected_sig = base64.b64decode(self.hello_world_sig)

        with open(key_path("testkey_ed25519")) as keyfile:
            jwt_key = algo.prepare_key(keyfile.read())

        with open(key_path("testkey_ed25519.pub")) as keyfile:
            jwt_pub_key = algo.prepare_key(keyfile.read())

        algo.sign(jwt_message, jwt_key)
        result = algo.verify(jwt_message, jwt_pub_key, expected_sig)
        assert result

    def test_ed25519_verify_should_return_false_if_signature_invalid(self):
        algo = Ed25519Algorithm()

        jwt_message = self.hello_world
        jwt_sig = base64.b64decode(self.hello_world_sig)

        jwt_sig += b"123"  # Signature is now invalid

        with open(key_path("testkey_ed25519.pub")) as keyfile:
            jwt_pub_key = algo.prepare_key(keyfile.read())

        result = algo.verify(jwt_message, jwt_pub_key, jwt_sig)
        assert not result

    def test_ed25519_verify_should_return_true_if_signature_valid(self):
        algo = Ed25519Algorithm()

        jwt_message = self.hello_world
        jwt_sig = base64.b64decode(self.hello_world_sig)

        with open(key_path("testkey_ed25519.pub")) as keyfile:
            jwt_pub_key = algo.prepare_key(keyfile.read())

        result = algo.verify(jwt_message, jwt_pub_key, jwt_sig)
        assert result

    def test_ed25519_prepare_key_should_be_idempotent(self):
        algo = Ed25519Algorithm()

        with open(key_path("testkey_ed25519.pub")) as keyfile:
            jwt_pub_key_first = algo.prepare_key(keyfile.read())
            jwt_pub_key_second = algo.prepare_key(jwt_pub_key_first)

        assert jwt_pub_key_first == jwt_pub_key_second
