import base64
import json
from typing import Any, cast

import pytest

from jwt.algorithms import HMACAlgorithm, NoneAlgorithm, has_crypto
from jwt.exceptions import InvalidKeyError
from jwt.utils import base64url_decode

from .keys import load_ec_pub_key_p_521, load_hmac_key, load_rsa_pub_key
from .utils import crypto_required, key_path

if has_crypto:
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurvePrivateKey,
        EllipticCurvePublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.ed448 import (
        Ed448PrivateKey,
        Ed448PublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.rsa import (
        RSAPrivateKey,
        RSAPublicKey,
    )

    from jwt.algorithms import ECAlgorithm, OKPAlgorithm, RSAAlgorithm, RSAPSSAlgorithm


class TestAlgorithms:
    def test_check_crypto_key_type_should_fail_when_not_using_crypto(self):
        """If has_crypto is False, or if _crypto_key_types is None, then this method should throw."""

        algo = NoneAlgorithm()
        with pytest.raises(ValueError):
            algo.check_crypto_key_type("key")  # type: ignore[arg-type]

    def test_none_algorithm_should_throw_exception_if_key_is_not_none(self):
        algo = NoneAlgorithm()

        with pytest.raises(InvalidKeyError):
            algo.prepare_key("123")

    def test_none_algorithm_should_throw_exception_on_to_jwk(self):
        algo = NoneAlgorithm()

        with pytest.raises(NotImplementedError):
            algo.to_jwk("dummy")  # Using a dummy argument as is it not relevant

    def test_none_algorithm_should_throw_exception_on_from_jwk(self):
        algo = NoneAlgorithm()

        with pytest.raises(NotImplementedError):
            algo.from_jwk({})  # Using a dummy argument as is it not relevant

    def test_hmac_should_reject_nonstring_key(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)

        with pytest.raises(TypeError) as context:
            algo.prepare_key(object())  # type: ignore[arg-type]

        exception = context.value
        assert str(exception) == "Expected a string value"

    def test_hmac_should_accept_unicode_key(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)

        algo.prepare_key("awesome")

    @pytest.mark.parametrize(
        "key",
        [
            "testkey2_rsa.pub.pem",
            "testkey2_rsa.pub.pem",
            "testkey_pkcs1.pub.pem",
            "testkey_rsa.cer",
            "testkey_rsa.pub",
        ],
    )
    def test_hmac_should_throw_exception(self, key):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)

        with pytest.raises(InvalidKeyError):
            with open(key_path(key)) as keyfile:
                algo.prepare_key(keyfile.read())

    def test_hmac_jwk_should_parse_and_verify(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)

        with open(key_path("jwk_hmac.json")) as keyfile:
            key = algo.from_jwk(keyfile.read())

        signature = algo.sign(b"Hello World!", key)
        assert algo.verify(b"Hello World!", key, signature)

    @pytest.mark.parametrize("as_dict", (False, True))
    def test_hmac_to_jwk_returns_correct_values(self, as_dict):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)
        key: Any = algo.to_jwk("secret", as_dict=as_dict)

        if not as_dict:
            key = json.loads(key)

        assert key == {"kty": "oct", "k": "c2VjcmV0"}

    def test_hmac_from_jwk_should_raise_exception_if_not_hmac_key(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)

        with open(key_path("jwk_rsa_pub.json")) as keyfile:
            with pytest.raises(InvalidKeyError):
                algo.from_jwk(keyfile.read())

    def test_hmac_from_jwk_should_raise_exception_if_empty_json(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)

        with open(key_path("jwk_empty.json")) as keyfile:
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
            algo.prepare_key(None)  # type: ignore[arg-type]

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
            pub_key = cast(RSAPublicKey, algo.prepare_key(keyfile.read()))

        result = algo.verify(message, pub_key, sig)
        assert not result

    @crypto_required
    def test_ec_jwk_public_and_private_keys_should_parse_and_verify(self):
        tests = {
            "P-256": ECAlgorithm.SHA256,
            "P-384": ECAlgorithm.SHA384,
            "P-521": ECAlgorithm.SHA512,
            "secp256k1": ECAlgorithm.SHA256,
        }
        for curve, hash in tests.items():
            algo = ECAlgorithm(hash)

            with open(key_path(f"jwk_ec_pub_{curve}.json")) as keyfile:
                pub_key = cast(EllipticCurvePublicKey, algo.from_jwk(keyfile.read()))

            with open(key_path(f"jwk_ec_key_{curve}.json")) as keyfile:
                priv_key = cast(EllipticCurvePrivateKey, algo.from_jwk(keyfile.read()))

            signature = algo.sign(b"Hello World!", priv_key)
            assert algo.verify(b"Hello World!", pub_key, signature)

    @crypto_required
    def test_ec_jwk_fails_on_invalid_json(self):
        algo = ECAlgorithm(ECAlgorithm.SHA512)

        valid_points = {
            "P-256": {
                "x": "PTTjIY84aLtaZCxLTrG_d8I0G6YKCV7lg8M4xkKfwQ4",
                "y": "ank6KA34vv24HZLXlChVs85NEGlpg2sbqNmR_BcgyJU",
            },
            "P-384": {
                "x": "IDC-5s6FERlbC4Nc_4JhKW8sd51AhixtMdNUtPxhRFP323QY6cwWeIA3leyZhz-J",
                "y": "eovmN9ocANS8IJxDAGSuC1FehTq5ZFLJU7XSPg36zHpv4H2byKGEcCBiwT4sFJsy",
            },
            "P-521": {
                "x": "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
                "y": "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1",
            },
            "secp256k1": {
                "x": "MLnVyPDPQpNm0KaaO4iEh0i8JItHXJE0NcIe8GK1SYs",
                "y": "7r8d-xF7QAgT5kSRdly6M8xeg4Jz83Gs_CQPQRH65QI",
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
            algo.from_jwk('{"kty": "EC", "x": "dGVzdHRlc3Q=", "y": "dGVzdA=="}')

        # EC coordinates length invalid
        for curve in ("P-256", "P-384", "P-521", "secp256k1"):
            with pytest.raises(InvalidKeyError):
                algo.from_jwk(
                    f'{{"kty": "EC", "crv": "{curve}", "x": "dGVzdA==", "y": "dGVzdA=="}}'
                )

        # EC private key length invalid
        for curve, point in valid_points.items():
            with pytest.raises(InvalidKeyError):
                algo.from_jwk(
                    f'{{"kty": "EC", "crv": "{curve}", "x": "{point["x"]}", "y": "{point["y"]}", "d": "dGVzdA=="}}'
                )

    @crypto_required
    def test_ec_private_key_to_jwk_works_with_from_jwk(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        with open(key_path("testkey_ec.priv")) as ec_key:
            orig_key = cast(EllipticCurvePrivateKey, algo.prepare_key(ec_key.read()))

        parsed_key = cast(EllipticCurvePrivateKey, algo.from_jwk(algo.to_jwk(orig_key)))
        assert parsed_key.private_numbers() == orig_key.private_numbers()
        assert (
            parsed_key.private_numbers().public_numbers
            == orig_key.private_numbers().public_numbers
        )

    @crypto_required
    def test_ec_public_key_to_jwk_works_with_from_jwk(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        with open(key_path("testkey_ec.pub")) as ec_key:
            orig_key = cast(EllipticCurvePublicKey, algo.prepare_key(ec_key.read()))

        parsed_key = cast(EllipticCurvePublicKey, algo.from_jwk(algo.to_jwk(orig_key)))
        assert parsed_key.public_numbers() == orig_key.public_numbers()

    @crypto_required
    @pytest.mark.parametrize("as_dict", (False, True))
    def test_ec_to_jwk_returns_correct_values_for_public_key(self, as_dict):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        with open(key_path("testkey_ec.pub")) as keyfile:
            pub_key = algo.prepare_key(keyfile.read())

        key: Any = algo.to_jwk(pub_key, as_dict=as_dict)

        if not as_dict:
            key = json.loads(key)

        expected = {
            "kty": "EC",
            "crv": "P-256",
            "x": "HzAcUWSlGBHcuf3y3RiNrWI-pE6-dD2T7fIzg9t6wEc",
            "y": "t2G02kbWiOqimYfQAfnARdp2CTycsJPhwA8rn1Cn0SQ",
        }

        assert key == expected

    @crypto_required
    @pytest.mark.parametrize("as_dict", (False, True))
    def test_ec_to_jwk_returns_correct_values_for_private_key(self, as_dict):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        with open(key_path("testkey_ec.priv")) as keyfile:
            priv_key = algo.prepare_key(keyfile.read())

        key: Any = algo.to_jwk(priv_key, as_dict=as_dict)

        if not as_dict:
            key = json.loads(key)

        expected = {
            "kty": "EC",
            "crv": "P-256",
            "x": "HzAcUWSlGBHcuf3y3RiNrWI-pE6-dD2T7fIzg9t6wEc",
            "y": "t2G02kbWiOqimYfQAfnARdp2CTycsJPhwA8rn1Cn0SQ",
            "d": "2nninfu2jMHDwAbn9oERUhRADS6duQaJEadybLaa0YQ",
        }

        assert key == expected

    @crypto_required
    def test_ec_to_jwk_raises_exception_on_invalid_key(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        with pytest.raises(InvalidKeyError):
            algo.to_jwk({"not": "a valid key"})  # type: ignore[call-overload]

    @crypto_required
    @pytest.mark.parametrize("as_dict", (False, True))
    def test_ec_to_jwk_with_valid_curves(self, as_dict):
        tests = {
            "P-256": ECAlgorithm.SHA256,
            "P-384": ECAlgorithm.SHA384,
            "P-521": ECAlgorithm.SHA512,
            "secp256k1": ECAlgorithm.SHA256,
        }
        for curve, hash in tests.items():
            algo = ECAlgorithm(hash)

            with open(key_path(f"jwk_ec_pub_{curve}.json")) as keyfile:
                pub_key = algo.from_jwk(keyfile.read())
                jwk: Any = algo.to_jwk(pub_key, as_dict=as_dict)

                if not as_dict:
                    jwk = json.loads(jwk)

                assert jwk["crv"] == curve

            with open(key_path(f"jwk_ec_key_{curve}.json")) as keyfile:
                priv_key = algo.from_jwk(keyfile.read())
                jwk = algo.to_jwk(priv_key, as_dict=as_dict)

                if not as_dict:
                    jwk = json.loads(jwk)

                assert jwk["crv"] == curve

    @crypto_required
    def test_ec_to_jwk_with_invalid_curve(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        with open(key_path("testkey_ec_secp192r1.priv")) as keyfile:
            priv_key = algo.prepare_key(keyfile.read())

        with pytest.raises(InvalidKeyError):
            algo.to_jwk(priv_key)

    @crypto_required
    def test_rsa_jwk_public_and_private_keys_should_parse_and_verify(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path("jwk_rsa_pub.json")) as keyfile:
            pub_key = cast(RSAPublicKey, algo.from_jwk(keyfile.read()))

        with open(key_path("jwk_rsa_key.json")) as keyfile:
            priv_key = cast(RSAPrivateKey, algo.from_jwk(keyfile.read()))

        signature = algo.sign(b"Hello World!", priv_key)
        assert algo.verify(b"Hello World!", pub_key, signature)

    @crypto_required
    def test_rsa_private_key_to_jwk_works_with_from_jwk(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path("testkey_rsa.priv")) as rsa_key:
            orig_key = cast(RSAPrivateKey, algo.prepare_key(rsa_key.read()))

        parsed_key = cast(RSAPrivateKey, algo.from_jwk(algo.to_jwk(orig_key)))
        assert parsed_key.private_numbers() == orig_key.private_numbers()
        assert (
            parsed_key.private_numbers().public_numbers
            == orig_key.private_numbers().public_numbers
        )

    @crypto_required
    def test_rsa_public_key_to_jwk_works_with_from_jwk(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path("testkey_rsa.pub")) as rsa_key:
            orig_key = cast(RSAPublicKey, algo.prepare_key(rsa_key.read()))

        parsed_key = cast(RSAPublicKey, algo.from_jwk(algo.to_jwk(orig_key)))
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
            control_key = cast(RSAPrivateKey, algo.from_jwk(keybytes)).private_numbers()

            keydata = json.loads(keybytes)
            delete_these = ["p", "q", "dp", "dq", "qi"]
            for field in delete_these:
                del keydata[field]

            parsed_key = cast(
                RSAPrivateKey, algo.from_jwk(json.dumps(keydata))
            ).private_numbers()

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
    @pytest.mark.parametrize("as_dict", (False, True))
    def test_rsa_to_jwk_returns_correct_values_for_public_key(self, as_dict):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path("testkey_rsa.pub")) as keyfile:
            pub_key = algo.prepare_key(keyfile.read())

        key: Any = algo.to_jwk(pub_key, as_dict=as_dict)

        if not as_dict:
            key = json.loads(key)

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
        assert key == expected

    @crypto_required
    @pytest.mark.parametrize("as_dict", (False, True))
    def test_rsa_to_jwk_returns_correct_values_for_private_key(self, as_dict):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path("testkey_rsa.priv")) as keyfile:
            priv_key = algo.prepare_key(keyfile.read())

        key: Any = algo.to_jwk(priv_key, as_dict=as_dict)

        if not as_dict:
            key = json.loads(key)

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
        assert key == expected

    @crypto_required
    def test_rsa_to_jwk_raises_exception_on_invalid_key(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with pytest.raises(InvalidKeyError):
            algo.to_jwk({"not": "a valid key"})  # type: ignore[call-overload]

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
            algo.prepare_key(None)  # type: ignore[arg-type]

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
    def test_ec_should_throw_exception_on_wrong_key(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        with pytest.raises(InvalidKeyError):
            with open(key_path("testkey_rsa.priv")) as keyfile:
                algo.prepare_key(keyfile.read())

        with pytest.raises(InvalidKeyError):
            with open(key_path("testkey2_rsa.pub.pem")) as pem_key:
                algo.prepare_key(pem_key.read())

    @crypto_required
    def test_rsa_pss_sign_then_verify_should_return_true(self):
        algo = RSAPSSAlgorithm(RSAPSSAlgorithm.SHA256)

        message = b"Hello World!"

        with open(key_path("testkey_rsa.priv")) as keyfile:
            priv_key = cast(RSAPrivateKey, algo.prepare_key(keyfile.read()))
            sig = algo.sign(message, priv_key)

        with open(key_path("testkey_rsa.pub")) as keyfile:
            pub_key = cast(RSAPublicKey, algo.prepare_key(keyfile.read()))

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
            jwt_pub_key = cast(RSAPublicKey, algo.prepare_key(keyfile.read()))

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

        signature = base64url_decode(b"s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0")

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
        key = cast(RSAPublicKey, algo.prepare_key(load_rsa_pub_key()))

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
        key = cast(RSAPublicKey, algo.prepare_key(load_rsa_pub_key()))

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

        # private key can also be used.
        with open(key_path("jwk_ec_key_P-521.json")) as keyfile:
            private_key = algo.from_jwk(keyfile.read())

        result = algo.verify(signing_input, private_key, signature)
        assert result


@crypto_required
class TestOKPAlgorithms:
    hello_world_sig = b"Qxa47mk/azzUgmY2StAOguAd4P7YBLpyCfU3JdbaiWnXM4o4WibXwmIHvNYgN3frtE2fcyd8OYEaOiD/KiwkCg=="
    hello_world_sig_pem = b"9ueQE7PT8uudHIQb2zZZ7tB7k1X3jeTnIfOVvGCINZejrqQbru1EXPeuMlGcQEZrGkLVcfMmr99W/+byxfppAg=="
    hello_world = b"Hello World!"

    def test_okp_ed25519_should_reject_non_string_key(self):
        algo = OKPAlgorithm()

        with pytest.raises(InvalidKeyError):
            algo.prepare_key(None)  # type: ignore[arg-type]

        with open(key_path("testkey_ed25519")) as keyfile:
            algo.prepare_key(keyfile.read())

        with open(key_path("testkey_ed25519.pub")) as keyfile:
            algo.prepare_key(keyfile.read())

    @pytest.mark.parametrize(
        "private_key_file,public_key_file,sig_attr",
        [
            ("testkey_ed25519", "testkey_ed25519.pub", "hello_world_sig"),
            ("testkey_ed25519.pem", "testkey_ed25519.pub.pem", "hello_world_sig_pem"),
        ],
    )
    def test_okp_ed25519_sign_should_generate_correct_signature_value(
        self, private_key_file, public_key_file, sig_attr
    ):
        algo = OKPAlgorithm()

        jwt_message = self.hello_world

        expected_sig = base64.b64decode(getattr(self, sig_attr))

        with open(key_path(private_key_file)) as keyfile:
            jwt_key = cast(Ed25519PrivateKey, algo.prepare_key(keyfile.read()))

        with open(key_path(public_key_file)) as keyfile:
            jwt_pub_key = cast(Ed25519PublicKey, algo.prepare_key(keyfile.read()))

        algo.sign(jwt_message, jwt_key)
        result = algo.verify(jwt_message, jwt_pub_key, expected_sig)
        assert result

    @pytest.mark.parametrize(
        "public_key_file,sig_attr",
        [
            ("testkey_ed25519.pub", "hello_world_sig"),
            ("testkey_ed25519.pub.pem", "hello_world_sig_pem"),
        ],
    )
    def test_okp_ed25519_verify_should_return_false_if_signature_invalid(
        self, public_key_file, sig_attr
    ):
        algo = OKPAlgorithm()

        jwt_message = self.hello_world
        jwt_sig = base64.b64decode(getattr(self, sig_attr))

        jwt_sig += b"123"  # Signature is now invalid

        with open(key_path(public_key_file)) as keyfile:
            jwt_pub_key = algo.prepare_key(keyfile.read())

        result = algo.verify(jwt_message, jwt_pub_key, jwt_sig)
        assert not result

    @pytest.mark.parametrize(
        "public_key_file,sig_attr",
        [
            ("testkey_ed25519.pub", "hello_world_sig"),
            ("testkey_ed25519.pub.pem", "hello_world_sig_pem"),
        ],
    )
    def test_okp_ed25519_verify_should_return_true_if_signature_valid(
        self, public_key_file, sig_attr
    ):
        algo = OKPAlgorithm()

        jwt_message = self.hello_world
        jwt_sig = base64.b64decode(getattr(self, sig_attr))

        with open(key_path(public_key_file)) as keyfile:
            jwt_pub_key = algo.prepare_key(keyfile.read())

        result = algo.verify(jwt_message, jwt_pub_key, jwt_sig)
        assert result

    @pytest.mark.parametrize(
        "public_key_file", ("testkey_ed25519.pub", "testkey_ed25519.pub.pem")
    )
    def test_okp_ed25519_prepare_key_should_be_idempotent(self, public_key_file):
        algo = OKPAlgorithm()

        with open(key_path(public_key_file)) as keyfile:
            jwt_pub_key_first = algo.prepare_key(keyfile.read())
            jwt_pub_key_second = algo.prepare_key(jwt_pub_key_first)

        assert jwt_pub_key_first == jwt_pub_key_second

    def test_okp_ed25519_prepare_key_should_reject_invalid_key(self):
        algo = OKPAlgorithm()

        with pytest.raises(InvalidKeyError):
            algo.prepare_key("not a valid key")

    def test_okp_ed25519_jwk_private_key_should_parse_and_verify(self):
        algo = OKPAlgorithm()

        with open(key_path("jwk_okp_key_Ed25519.json")) as keyfile:
            key = cast(Ed25519PrivateKey, algo.from_jwk(keyfile.read()))

        signature = algo.sign(b"Hello World!", key)
        assert algo.verify(b"Hello World!", key.public_key(), signature)

    def test_okp_ed25519_jwk_private_key_should_parse_and_verify_with_private_key_as_is(
        self,
    ):
        algo = OKPAlgorithm()

        with open(key_path("jwk_okp_key_Ed25519.json")) as keyfile:
            key = cast(Ed25519PrivateKey, algo.from_jwk(keyfile.read()))

        signature = algo.sign(b"Hello World!", key)
        assert algo.verify(b"Hello World!", key, signature)

    def test_okp_ed25519_jwk_public_key_should_parse_and_verify(self):
        algo = OKPAlgorithm()

        with open(key_path("jwk_okp_key_Ed25519.json")) as keyfile:
            priv_key = cast(Ed25519PrivateKey, algo.from_jwk(keyfile.read()))

        with open(key_path("jwk_okp_pub_Ed25519.json")) as keyfile:
            pub_key = cast(Ed25519PublicKey, algo.from_jwk(keyfile.read()))

        signature = algo.sign(b"Hello World!", priv_key)
        assert algo.verify(b"Hello World!", pub_key, signature)

    def test_okp_ed25519_jwk_fails_on_invalid_json(self):
        algo = OKPAlgorithm()

        with open(key_path("jwk_okp_pub_Ed25519.json")) as keyfile:
            valid_pub = json.loads(keyfile.read())
        with open(key_path("jwk_okp_key_Ed25519.json")) as keyfile:
            valid_key = json.loads(keyfile.read())

        # Invalid instance type
        with pytest.raises(InvalidKeyError):
            algo.from_jwk(123)  # type: ignore[arg-type]

        # Invalid JSON
        with pytest.raises(InvalidKeyError):
            algo.from_jwk("<this isn't json>")

        # Invalid kty, not "OKP"
        v = valid_pub.copy()
        v["kty"] = "oct"
        with pytest.raises(InvalidKeyError):
            algo.from_jwk(v)

        # Invalid crv, not "Ed25519"
        v = valid_pub.copy()
        v["crv"] = "P-256"
        with pytest.raises(InvalidKeyError):
            algo.from_jwk(v)

        # Invalid crv, "Ed448"
        v = valid_pub.copy()
        v["crv"] = "Ed448"
        with pytest.raises(InvalidKeyError):
            algo.from_jwk(v)

        # Missing x
        v = valid_pub.copy()
        del v["x"]
        with pytest.raises(InvalidKeyError):
            algo.from_jwk(v)

        # Invalid x
        v = valid_pub.copy()
        v["x"] = "123"
        with pytest.raises(InvalidKeyError):
            algo.from_jwk(v)

        # Invalid d
        v = valid_key.copy()
        v["d"] = "123"
        with pytest.raises(InvalidKeyError):
            algo.from_jwk(v)

    @pytest.mark.parametrize("as_dict", (False, True))
    def test_okp_ed25519_to_jwk_works_with_from_jwk(self, as_dict):
        algo = OKPAlgorithm()

        with open(key_path("jwk_okp_key_Ed25519.json")) as keyfile:
            priv_key_1 = cast(Ed25519PrivateKey, algo.from_jwk(keyfile.read()))

        with open(key_path("jwk_okp_pub_Ed25519.json")) as keyfile:
            pub_key_1 = cast(Ed25519PublicKey, algo.from_jwk(keyfile.read()))

        pub = algo.to_jwk(pub_key_1, as_dict=as_dict)
        pub_key_2 = algo.from_jwk(pub)
        pri = algo.to_jwk(priv_key_1, as_dict=as_dict)
        priv_key_2 = cast(Ed25519PrivateKey, algo.from_jwk(pri))

        signature_1 = algo.sign(b"Hello World!", priv_key_1)
        signature_2 = algo.sign(b"Hello World!", priv_key_2)
        assert algo.verify(b"Hello World!", pub_key_2, signature_1)
        assert algo.verify(b"Hello World!", pub_key_2, signature_2)

    def test_okp_to_jwk_raises_exception_on_invalid_key(self):
        algo = OKPAlgorithm()

        with pytest.raises(InvalidKeyError):
            algo.to_jwk({"not": "a valid key"})  # type: ignore[call-overload]

    def test_okp_ed448_jwk_private_key_should_parse_and_verify(self):
        algo = OKPAlgorithm()

        with open(key_path("jwk_okp_key_Ed448.json")) as keyfile:
            key = cast(Ed448PrivateKey, algo.from_jwk(keyfile.read()))

        signature = algo.sign(b"Hello World!", key)
        assert algo.verify(b"Hello World!", key.public_key(), signature)

    def test_okp_ed448_jwk_private_key_should_parse_and_verify_with_private_key_as_is(
        self,
    ):
        algo = OKPAlgorithm()

        with open(key_path("jwk_okp_key_Ed448.json")) as keyfile:
            key = cast(Ed448PrivateKey, algo.from_jwk(keyfile.read()))

        signature = algo.sign(b"Hello World!", key)
        assert algo.verify(b"Hello World!", key, signature)

    def test_okp_ed448_jwk_public_key_should_parse_and_verify(self):
        algo = OKPAlgorithm()

        with open(key_path("jwk_okp_key_Ed448.json")) as keyfile:
            priv_key = cast(Ed448PrivateKey, algo.from_jwk(keyfile.read()))

        with open(key_path("jwk_okp_pub_Ed448.json")) as keyfile:
            pub_key = cast(Ed448PublicKey, algo.from_jwk(keyfile.read()))

        signature = algo.sign(b"Hello World!", priv_key)
        assert algo.verify(b"Hello World!", pub_key, signature)

    def test_okp_ed448_jwk_fails_on_invalid_json(self):
        algo = OKPAlgorithm()

        with open(key_path("jwk_okp_pub_Ed448.json")) as keyfile:
            valid_pub = json.loads(keyfile.read())
        with open(key_path("jwk_okp_key_Ed448.json")) as keyfile:
            valid_key = json.loads(keyfile.read())

        # Invalid instance type
        with pytest.raises(InvalidKeyError):
            algo.from_jwk(123)  # type: ignore[arg-type]

        # Invalid JSON
        with pytest.raises(InvalidKeyError):
            algo.from_jwk("<this isn't json>")

        # Invalid kty, not "OKP"
        v = valid_pub.copy()
        v["kty"] = "oct"
        with pytest.raises(InvalidKeyError):
            algo.from_jwk(v)

        # Invalid crv, not "Ed448"
        v = valid_pub.copy()
        v["crv"] = "P-256"
        with pytest.raises(InvalidKeyError):
            algo.from_jwk(v)

        # Invalid crv, "Ed25519"
        v = valid_pub.copy()
        v["crv"] = "Ed25519"
        with pytest.raises(InvalidKeyError):
            algo.from_jwk(v)

        # Missing x
        v = valid_pub.copy()
        del v["x"]
        with pytest.raises(InvalidKeyError):
            algo.from_jwk(v)

        # Invalid x
        v = valid_pub.copy()
        v["x"] = "123"
        with pytest.raises(InvalidKeyError):
            algo.from_jwk(v)

        # Invalid d
        v = valid_key.copy()
        v["d"] = "123"
        with pytest.raises(InvalidKeyError):
            algo.from_jwk(v)

    @pytest.mark.parametrize("as_dict", (False, True))
    def test_okp_ed448_to_jwk_works_with_from_jwk(self, as_dict):
        algo = OKPAlgorithm()

        with open(key_path("jwk_okp_key_Ed448.json")) as keyfile:
            priv_key_1 = cast(Ed448PrivateKey, algo.from_jwk(keyfile.read()))

        with open(key_path("jwk_okp_pub_Ed448.json")) as keyfile:
            pub_key_1 = cast(Ed448PublicKey, algo.from_jwk(keyfile.read()))

        pub = algo.to_jwk(pub_key_1, as_dict=as_dict)
        pub_key_2 = algo.from_jwk(pub)
        pri = algo.to_jwk(priv_key_1, as_dict=as_dict)
        priv_key_2 = cast(Ed448PrivateKey, algo.from_jwk(pri))

        signature_1 = algo.sign(b"Hello World!", priv_key_1)
        signature_2 = algo.sign(b"Hello World!", priv_key_2)
        assert algo.verify(b"Hello World!", pub_key_2, signature_1)
        assert algo.verify(b"Hello World!", pub_key_2, signature_2)

    @crypto_required
    def test_rsa_can_compute_digest(self):
        # this is the well-known sha256 hash of "foo"
        foo_hash = base64.b64decode(b"LCa0a2j/xo/5m0U8HTBBNBNCLXBkg7+g+YpeiGJm564=")

        algo = RSAAlgorithm(RSAAlgorithm.SHA256)
        computed_hash = algo.compute_hash_digest(b"foo")
        assert computed_hash == foo_hash

    def test_hmac_can_compute_digest(self):
        # this is the well-known sha256 hash of "foo"
        foo_hash = base64.b64decode(b"LCa0a2j/xo/5m0U8HTBBNBNCLXBkg7+g+YpeiGJm564=")

        algo = HMACAlgorithm(HMACAlgorithm.SHA256)
        computed_hash = algo.compute_hash_digest(b"foo")
        assert computed_hash == foo_hash

    @crypto_required
    def test_rsa_prepare_key_raises_invalid_key_error_on_invalid_pem(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)
        invalid_key = "invalid key"

        with pytest.raises(InvalidKeyError) as excinfo:
            algo.prepare_key(invalid_key)

        # Check that the exception message is correct
        assert "Could not parse the provided public key." in str(excinfo.value)


@crypto_required
class TestECCurveValidation:
    """Tests for ECDSA curve validation per RFC 7518 Section 3.4."""

    def test_ec_curve_validation_rejects_wrong_curve_for_es256(self):
        """ES256 should reject keys that are not P-256."""
        from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1

        algo = ECAlgorithm(ECAlgorithm.SHA256, SECP256R1)

        # P-384 key should be rejected
        with open(key_path("jwk_ec_key_P-384.json")) as keyfile:
            p384_key = ECAlgorithm.from_jwk(keyfile.read())

        with pytest.raises(InvalidKeyError) as excinfo:
            algo.prepare_key(p384_key)
        assert "secp384r1" in str(excinfo.value)
        assert "secp256r1" in str(excinfo.value)

    def test_ec_curve_validation_rejects_wrong_curve_for_es384(self):
        """ES384 should reject keys that are not P-384."""
        from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1

        algo = ECAlgorithm(ECAlgorithm.SHA384, SECP384R1)

        # P-256 key should be rejected
        with open(key_path("jwk_ec_key_P-256.json")) as keyfile:
            p256_key = ECAlgorithm.from_jwk(keyfile.read())

        with pytest.raises(InvalidKeyError) as excinfo:
            algo.prepare_key(p256_key)
        assert "secp256r1" in str(excinfo.value)
        assert "secp384r1" in str(excinfo.value)

    def test_ec_curve_validation_rejects_wrong_curve_for_es512(self):
        """ES512 should reject keys that are not P-521."""
        from cryptography.hazmat.primitives.asymmetric.ec import SECP521R1

        algo = ECAlgorithm(ECAlgorithm.SHA512, SECP521R1)

        # P-256 key should be rejected
        with open(key_path("jwk_ec_key_P-256.json")) as keyfile:
            p256_key = ECAlgorithm.from_jwk(keyfile.read())

        with pytest.raises(InvalidKeyError) as excinfo:
            algo.prepare_key(p256_key)
        assert "secp256r1" in str(excinfo.value)
        assert "secp521r1" in str(excinfo.value)

    def test_ec_curve_validation_rejects_wrong_curve_for_es256k(self):
        """ES256K should reject keys that are not secp256k1."""
        from cryptography.hazmat.primitives.asymmetric.ec import SECP256K1

        algo = ECAlgorithm(ECAlgorithm.SHA256, SECP256K1)

        # P-256 key should be rejected
        with open(key_path("jwk_ec_key_P-256.json")) as keyfile:
            p256_key = ECAlgorithm.from_jwk(keyfile.read())

        with pytest.raises(InvalidKeyError) as excinfo:
            algo.prepare_key(p256_key)
        assert "secp256r1" in str(excinfo.value)
        assert "secp256k1" in str(excinfo.value)

    def test_ec_curve_validation_accepts_correct_curve_for_es256(self):
        """ES256 should accept P-256 keys."""
        from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1

        algo = ECAlgorithm(ECAlgorithm.SHA256, SECP256R1)

        with open(key_path("jwk_ec_key_P-256.json")) as keyfile:
            key = algo.from_jwk(keyfile.read())
            prepared = algo.prepare_key(key)
            assert prepared is key

    def test_ec_curve_validation_accepts_correct_curve_for_es384(self):
        """ES384 should accept P-384 keys."""
        from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1

        algo = ECAlgorithm(ECAlgorithm.SHA384, SECP384R1)

        with open(key_path("jwk_ec_key_P-384.json")) as keyfile:
            key = algo.from_jwk(keyfile.read())
            prepared = algo.prepare_key(key)
            assert prepared is key

    def test_ec_curve_validation_accepts_correct_curve_for_es512(self):
        """ES512 should accept P-521 keys."""
        from cryptography.hazmat.primitives.asymmetric.ec import SECP521R1

        algo = ECAlgorithm(ECAlgorithm.SHA512, SECP521R1)

        with open(key_path("jwk_ec_key_P-521.json")) as keyfile:
            key = algo.from_jwk(keyfile.read())
            prepared = algo.prepare_key(key)
            assert prepared is key

    def test_ec_curve_validation_accepts_correct_curve_for_es256k(self):
        """ES256K should accept secp256k1 keys."""
        from cryptography.hazmat.primitives.asymmetric.ec import SECP256K1

        algo = ECAlgorithm(ECAlgorithm.SHA256, SECP256K1)

        with open(key_path("jwk_ec_key_secp256k1.json")) as keyfile:
            key = algo.from_jwk(keyfile.read())
            prepared = algo.prepare_key(key)
            assert prepared is key

    def test_ec_curve_validation_rejects_p192_for_es256(self):
        """ES256 should reject P-192 keys (weaker than P-256)."""
        from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1

        algo = ECAlgorithm(ECAlgorithm.SHA256, SECP256R1)

        with open(key_path("testkey_ec_secp192r1.priv")) as keyfile:
            with pytest.raises(InvalidKeyError) as excinfo:
                algo.prepare_key(keyfile.read())
            assert "secp192r1" in str(excinfo.value)
            assert "secp256r1" in str(excinfo.value)

    def test_ec_algorithm_without_expected_curve_accepts_any_curve(self):
        """ECAlgorithm without expected_curve should accept any curve (backwards compat)."""
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        # Should accept P-256
        with open(key_path("jwk_ec_key_P-256.json")) as keyfile:
            p256_key = algo.from_jwk(keyfile.read())
            algo.prepare_key(p256_key)

        # Should accept P-384
        with open(key_path("jwk_ec_key_P-384.json")) as keyfile:
            p384_key = algo.from_jwk(keyfile.read())
            algo.prepare_key(p384_key)

        # Should accept P-521
        with open(key_path("jwk_ec_key_P-521.json")) as keyfile:
            p521_key = algo.from_jwk(keyfile.read())
            algo.prepare_key(p521_key)

        # Should accept secp256k1
        with open(key_path("jwk_ec_key_secp256k1.json")) as keyfile:
            secp256k1_key = algo.from_jwk(keyfile.read())
            algo.prepare_key(secp256k1_key)

    def test_default_algorithms_have_correct_expected_curve(self):
        """Default algorithms returned by get_default_algorithms should have expected_curve set."""
        from cryptography.hazmat.primitives.asymmetric.ec import (
            SECP256K1,
            SECP256R1,
            SECP384R1,
            SECP521R1,
        )

        from jwt.algorithms import get_default_algorithms

        algorithms = get_default_algorithms()

        es256 = algorithms["ES256"]
        assert isinstance(es256, ECAlgorithm)
        assert es256.expected_curve == SECP256R1

        es256k = algorithms["ES256K"]
        assert isinstance(es256k, ECAlgorithm)
        assert es256k.expected_curve == SECP256K1

        es384 = algorithms["ES384"]
        assert isinstance(es384, ECAlgorithm)
        assert es384.expected_curve == SECP384R1

        es521 = algorithms["ES521"]
        assert isinstance(es521, ECAlgorithm)
        assert es521.expected_curve == SECP521R1

        es512 = algorithms["ES512"]
        assert isinstance(es512, ECAlgorithm)
        assert es512.expected_curve == SECP521R1

    def test_ec_curve_validation_with_pem_key(self):
        """Curve validation should work with PEM-formatted keys."""
        from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1

        algo = ECAlgorithm(ECAlgorithm.SHA256, SECP256R1)

        # P-256 PEM key should be accepted
        with open(key_path("testkey_ec.priv")) as keyfile:
            algo.prepare_key(keyfile.read())

        # P-192 PEM key should be rejected
        with open(key_path("testkey_ec_secp192r1.priv")) as keyfile:
            with pytest.raises(InvalidKeyError):
                algo.prepare_key(keyfile.read())

    def test_jwt_encode_decode_rejects_wrong_curve(self):
        """Integration test: jwt.encode/decode should reject wrong curve keys."""
        import jwt

        # Use P-384 key with ES256 algorithm (expects P-256)
        with open(key_path("jwk_ec_key_P-384.json")) as keyfile:
            p384_key = ECAlgorithm.from_jwk(keyfile.read())

        # Encoding should fail
        with pytest.raises(InvalidKeyError):
            jwt.encode({"hello": "world"}, p384_key, algorithm="ES256")

        # Create a valid token with P-256 key
        with open(key_path("jwk_ec_key_P-256.json")) as keyfile:
            p256_key = ECAlgorithm.from_jwk(keyfile.read())

        token = jwt.encode({"hello": "world"}, p256_key, algorithm="ES256")

        # Decoding with wrong curve key should fail
        with open(key_path("jwk_ec_pub_P-384.json")) as keyfile:
            p384_pub_key = ECAlgorithm.from_jwk(keyfile.read())

        with pytest.raises(InvalidKeyError):
            jwt.decode(token, p384_pub_key, algorithms=["ES256"])

        # Decoding with correct curve key should succeed
        with open(key_path("jwk_ec_pub_P-256.json")) as keyfile:
            p256_pub_key = ECAlgorithm.from_jwk(keyfile.read())

        decoded = jwt.decode(token, p256_pub_key, algorithms=["ES256"])
        assert decoded == {"hello": "world"}


class TestKeyLengthValidation:
    """Tests for minimum key length validation (CWE-326)."""

    # --- HMAC tests ---

    def test_hmac_short_key_warns_by_default_hs256(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)
        key = algo.prepare_key(b"short")
        msg = algo.check_key_length(key)
        assert msg is not None
        assert "below" in msg
        assert "32" in msg

    def test_hmac_short_key_warns_by_default_hs384(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA384)
        key = algo.prepare_key(b"a" * 47)
        msg = algo.check_key_length(key)
        assert msg is not None
        assert "48" in msg

    def test_hmac_short_key_warns_by_default_hs512(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA512)
        key = algo.prepare_key(b"a" * 63)
        msg = algo.check_key_length(key)
        assert msg is not None
        assert "64" in msg

    def test_hmac_empty_key_returns_warning_message(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)
        key = algo.prepare_key(b"")
        msg = algo.check_key_length(key)
        assert msg is not None

    def test_hmac_exact_minimum_no_warning(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)
        key = algo.prepare_key(b"a" * 32)
        assert algo.check_key_length(key) is None

    def test_hmac_above_minimum_no_warning(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA512)
        key = algo.prepare_key(b"a" * 128)
        assert algo.check_key_length(key) is None

    def test_hmac_exact_minimum_hs384(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA384)
        key = algo.prepare_key(b"a" * 48)
        assert algo.check_key_length(key) is None

    def test_hmac_exact_minimum_hs512(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA512)
        key = algo.prepare_key(b"a" * 64)
        assert algo.check_key_length(key) is None

    # --- RSA tests ---

    @crypto_required
    def test_rsa_small_key_returns_warning_message(self):
        from cryptography.hazmat.primitives.asymmetric import rsa as rsa_module

        small_key = rsa_module.generate_private_key(
            public_exponent=65537,
            key_size=1024,
        )
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)
        msg = algo.check_key_length(small_key)
        assert msg is not None
        assert "1024" in msg
        assert "2048" in msg

    @crypto_required
    def test_rsa_small_public_key_returns_warning_message(self):
        from cryptography.hazmat.primitives.asymmetric import rsa as rsa_module

        small_key = rsa_module.generate_private_key(
            public_exponent=65537,
            key_size=1024,
        )
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)
        msg = algo.check_key_length(small_key.public_key())
        assert msg is not None

    @crypto_required
    def test_rsa_2048_key_no_warning(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)
        with open(key_path("testkey_rsa.priv")) as f:
            key = algo.prepare_key(f.read())
        assert algo.check_key_length(key) is None

    @crypto_required
    def test_rsa_pss_inherits_validation(self):
        from cryptography.hazmat.primitives.asymmetric import rsa as rsa_module

        small_key = rsa_module.generate_private_key(
            public_exponent=65537,
            key_size=1024,
        )
        algo = RSAPSSAlgorithm(RSAPSSAlgorithm.SHA256)
        msg = algo.check_key_length(small_key)
        assert msg is not None

    @crypto_required
    def test_rsa_pem_weak_key_validated(self):
        from cryptography.hazmat.primitives.asymmetric import rsa as rsa_module
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
        )

        small_key = rsa_module.generate_private_key(
            public_exponent=65537,
            key_size=1024,
        )
        pem = small_key.private_bytes(
            Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()
        )
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)
        prepared = algo.prepare_key(pem)
        msg = algo.check_key_length(prepared)
        assert msg is not None

    # --- PyJWS integration tests ---

    def test_pyjws_encode_warns_short_hmac_key(self):
        import jwt

        jws = jwt.PyJWS()
        with pytest.warns(jwt.InsecureKeyLengthWarning, match="below"):
            jws.encode(b'{"test":"payload"}', b"short", algorithm="HS256")

    def test_pyjws_encode_enforces_short_hmac_key(self):
        import jwt

        jws = jwt.PyJWS(options={"enforce_minimum_key_length": True})
        with pytest.raises(InvalidKeyError, match="below"):
            jws.encode(b'{"test":"payload"}', b"short", algorithm="HS256")

    def test_pyjws_encode_no_warning_adequate_key(self):
        import warnings

        import jwt

        jws = jwt.PyJWS()
        with warnings.catch_warnings():
            warnings.simplefilter("error", jwt.InsecureKeyLengthWarning)
            jws.encode(b'{"test":"payload"}', b"a" * 32, algorithm="HS256")

    # --- PyJWT integration tests ---

    def test_pyjwt_encode_warns_short_hmac_key(self):
        import jwt

        with pytest.warns(jwt.InsecureKeyLengthWarning):
            jwt.encode({"hello": "world"}, "short", algorithm="HS256")

    def test_pyjwt_encode_enforces_short_hmac_key(self):
        import jwt

        pyjwt = jwt.PyJWT(options={"enforce_minimum_key_length": True})
        with pytest.raises(InvalidKeyError, match="below"):
            pyjwt.encode({"hello": "world"}, "short", algorithm="HS256")

    def test_pyjwt_decode_enforces_short_hmac_key(self):
        import jwt

        adequate_key = "a" * 32
        token = jwt.encode({"hello": "world"}, adequate_key, algorithm="HS256")

        pyjwt = jwt.PyJWT(options={"enforce_minimum_key_length": True})
        # Decoding with adequate key should work
        result = pyjwt.decode(token, adequate_key, algorithms=["HS256"])
        assert result == {"hello": "world"}

        # Decoding with short key should raise
        pyjwt_enforce = jwt.PyJWT(options={"enforce_minimum_key_length": True})
        with pytest.raises(InvalidKeyError):
            pyjwt_enforce.decode(token, "short", algorithms=["HS256"])

    def test_pyjwt_encode_no_warning_adequate_key(self):
        import warnings

        import jwt

        with warnings.catch_warnings():
            warnings.simplefilter("error", jwt.InsecureKeyLengthWarning)
            jwt.encode({"hello": "world"}, "a" * 32, algorithm="HS256")

    def test_global_register_algorithm_works_with_encode(self):
        """Backward compat: jwt.register_algorithm + jwt.encode use the same JWS."""
        import jwt

        # This test just verifies the global path still works
        # (register_algorithm and encode share the same JWS instance)
        token = jwt.encode({"hello": "world"}, "a" * 32, algorithm="HS256")
        decoded = jwt.decode(token, "a" * 32, algorithms=["HS256"])
        assert decoded == {"hello": "world"}
