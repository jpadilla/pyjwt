"""
Tests for HMAC Key Length Validation (CVE-2025-45768 Fix)

This module contains tests that verify HMAC key length validation according to
NIST SP 800-107 standards and ensure proper security enforcement.
"""

import warnings

import pytest

from jwt import PyJWS, PyJWT
from jwt.algorithms import HMACAlgorithm
from jwt.exceptions import InvalidKeyError
from jwt.warnings import WeakKeyWarning


class TestHMACKeyValidation:
    """Test HMAC key length validation and security enforcement."""

    def test_hmac_short_key_warning_in_default_mode(self):
        """Test that short HMAC keys generate warnings in default mode."""
        short_key = "short"  # 5 bytes, less than 32 required for HS256

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")

            alg = HMACAlgorithm(HMACAlgorithm.SHA256)
            alg.prepare_key(short_key)

            # Should have issued a warning
            assert len(w) == 1
            assert issubclass(w[0].category, WeakKeyWarning)
            assert "32 bytes" in str(w[0].message)
            assert "NIST SP 800-107" in str(w[0].message)

    def test_hmac_short_key_error_in_strict_mode(self):
        """Test that short HMAC keys raise errors in strict mode."""
        short_key = "short"  # 5 bytes, less than 32 required for HS256

        alg = HMACAlgorithm(HMACAlgorithm.SHA256, strict_key_validation=True)

        with pytest.raises(InvalidKeyError) as exc_info:
            alg.prepare_key(short_key)

        assert "32 bytes" in str(exc_info.value)
        assert "NIST SP 800-107" in str(exc_info.value)

    def test_hmac_valid_key_lengths(self):
        """Test that valid key lengths are accepted without warnings."""
        # Test minimum valid keys for each algorithm
        valid_keys = {
            HMACAlgorithm.SHA256: "a" * 32,  # 32 bytes for HS256
            HMACAlgorithm.SHA384: "a" * 48,  # 48 bytes for HS384
            HMACAlgorithm.SHA512: "a" * 64,  # 64 bytes for HS512
        }

        for hash_alg, key in valid_keys.items():
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")

                # Test in both modes
                alg_default = HMACAlgorithm(hash_alg)
                alg_default.prepare_key(key)

                alg_strict = HMACAlgorithm(hash_alg, strict_key_validation=True)
                alg_strict.prepare_key(key)

                # Should not have issued any warnings
                assert len(w) == 0

    def test_all_hmac_algorithms_key_validation(self):
        """Test key validation for all HMAC algorithms."""
        test_cases = [
            (HMACAlgorithm.SHA256, "short", 32),  # 5 bytes, need 32
            (HMACAlgorithm.SHA384, "x" * 20, 48),  # 20 bytes, need 48
            (HMACAlgorithm.SHA512, "y" * 30, 64),  # 30 bytes, need 64
        ]

        for hash_alg, short_key, expected_min in test_cases:
            # Test warning mode
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")

                alg = HMACAlgorithm(hash_alg)
                alg.prepare_key(short_key)

                assert len(w) == 1
                assert issubclass(w[0].category, WeakKeyWarning)
                assert f"{expected_min} bytes" in str(w[0].message)

            # Test strict mode
            alg_strict = HMACAlgorithm(hash_alg, strict_key_validation=True)
            with pytest.raises(InvalidKeyError) as exc_info:
                alg_strict.prepare_key(short_key)

            assert f"{expected_min} bytes" in str(exc_info.value)

    def test_pyjws_strict_key_validation(self):
        """Test PyJWS strict key validation integration."""
        short_key = "weak"  # 4 bytes, less than 32 required
        payload = b"test"

        # Default mode should warn
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")

            jws = PyJWS()
            jws.encode(payload, short_key, algorithm="HS256")

            assert len(w) == 1
            assert issubclass(w[0].category, WeakKeyWarning)

        # Strict mode should error
        jws_strict = PyJWS(strict_key_validation=True)
        with pytest.raises(InvalidKeyError):
            jws_strict.encode(payload, short_key, algorithm="HS256")

    def test_pyjwt_strict_key_validation(self):
        """Test PyJWT strict key validation integration."""
        short_key = "weak"  # 4 bytes, less than 32 required
        payload = {"test": "data"}

        # Default mode should warn
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")

            jwt_encoder = PyJWT()
            jwt_encoder.encode(payload, short_key, algorithm="HS256")

            assert len(w) == 1
            assert issubclass(w[0].category, WeakKeyWarning)

        # Strict mode should error
        jwt_strict = PyJWT(strict_key_validation=True)
        with pytest.raises(InvalidKeyError):
            jwt_strict.encode(payload, short_key, algorithm="HS256")

    def test_pyjwt_decode_strict_key_validation(self):
        """Test PyJWT decode with strict key validation."""
        short_key = "weak"  # 4 bytes, less than 32 required
        payload = {"test": "data"}

        # First create a token with warnings suppressed
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            jwt_encoder = PyJWT()
            token = jwt_encoder.encode(payload, short_key, algorithm="HS256")

        # Default mode decode should warn
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")

            jwt_decoder = PyJWT()
            jwt_decoder.decode(token, short_key, algorithms=["HS256"])

            assert len(w) == 1
            assert issubclass(w[0].category, WeakKeyWarning)

        # Strict mode decode should error
        jwt_strict = PyJWT(strict_key_validation=True)
        with pytest.raises(InvalidKeyError):
            jwt_strict.decode(token, short_key, algorithms=["HS256"])

    def test_backwards_compatibility_preserved(self):
        """Test that existing functionality works with warnings."""
        # Verify that existing code continues to work but issues warnings
        short_key = "secret"  # This is what many tutorials use (6 bytes)
        payload = {"user": "test"}

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")

            # This should work but warn
            jwt_encoder = PyJWT()
            token = jwt_encoder.encode(payload, short_key)
            decoded = jwt_encoder.decode(token, short_key, algorithms=["HS256"])

            # Should have issued warnings for both encode and decode
            assert len(w) == 2  # One for encode, one for decode
            assert all(issubclass(warning.category, WeakKeyWarning) for warning in w)
            assert decoded["user"] == "test"

    def test_secure_key_lengths_no_warnings(self):
        """Test that secure key lengths don't generate warnings."""
        # Test with cryptographically strong keys
        secure_keys = {
            "HS256": "a" * 32,  # 256 bits
            "HS384": "b" * 48,  # 384 bits
            "HS512": "c" * 64,  # 512 bits
        }

        payload = {"test": "data"}

        for alg, key in secure_keys.items():
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")

                # Test both PyJWT and PyJWS
                jwt_encoder = PyJWT()
                token = jwt_encoder.encode(payload, key, algorithm=alg)
                jwt_encoder.decode(token, key, algorithms=[alg])

                jws = PyJWS()
                jws_token = jws.encode(b"test", key, algorithm=alg)
                jws.decode(jws_token, key, algorithms=[alg])

                # Should not have issued any warnings
                assert len(w) == 0

    def test_error_message_quality(self):
        """Test that error messages are informative and helpful."""
        short_key = "x" * 5  # 5 bytes

        alg = HMACAlgorithm(HMACAlgorithm.SHA256, strict_key_validation=True)

        with pytest.raises(InvalidKeyError) as exc_info:
            alg.prepare_key(short_key)

        error_msg = str(exc_info.value)

        # Verify error message contains key information
        assert "32 bytes" in error_msg  # Expected minimum
        assert "256 bits" in error_msg  # Bits equivalent
        assert "5 bytes" in error_msg  # Actual length
        assert "NIST SP 800-107" in error_msg  # Standard reference
        assert "SHA-256" in error_msg  # Algorithm name
        assert "security" in error_msg  # Security implication

    def test_module_level_functions_still_work(self):
        """Test that module-level functions still work with warnings."""
        import jwt

        short_key = "secret"
        payload = {"test": "data"}

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")

            # Module level functions should still work but warn
            token = jwt.encode(payload, short_key)
            decoded = jwt.decode(token, short_key, algorithms=["HS256"])

            # Should work but generate warnings
            assert decoded["test"] == "data"
            # Note: Module-level functions use global PyJWS instance,
            # so they won't have strict validation by default
