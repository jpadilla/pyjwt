"""
Regression tests for HMAC Key Validation (CVE-2025-45768 Fix)

This module contains essential regression tests to ensure the HMAC key validation
implementation doesn't break existing functionality while maintaining security.
"""

import warnings
import secrets
import base64

import pytest

import jwt
from jwt import PyJWT
from jwt.algorithms import HMACAlgorithm
from jwt.exceptions import InvalidKeyError
from jwt.warnings import WeakKeyWarning


class TestHMACRegressionTests:
    """Essential regression tests for HMAC key validation implementation."""

    def test_module_level_functions_with_warnings(self):
        """Test that module-level functions generate warnings for weak keys."""
        short_key = "weak"  # 4 bytes, less than 32 required
        payload = {"test": "data"}

        # Test default mode (should warn)
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            token = jwt.encode(payload, short_key)
            decoded = jwt.decode(token, short_key, algorithms=["HS256"])
            assert decoded["test"] == "data"
            assert len(w) == 2  # One for encode, one for decode
            assert issubclass(w[0].category, WeakKeyWarning)
            assert issubclass(w[1].category, WeakKeyWarning)

    def test_performance_optimization(self):
        """Test that the performance optimizations work correctly."""
        # Test that pre-computed minimum length is used
        alg = HMACAlgorithm(HMACAlgorithm.SHA256)
        assert alg._min_key_length == 32

        alg = HMACAlgorithm(HMACAlgorithm.SHA384)
        assert alg._min_key_length == 48

        alg = HMACAlgorithm(HMACAlgorithm.SHA512)
        assert alg._min_key_length == 64

    def test_backward_compatibility_preserved(self):
        """Test that existing code patterns continue to work."""
        # Test pattern: direct algorithm usage
        alg = HMACAlgorithm(HMACAlgorithm.SHA256)
        short_key = "secret"

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            key_bytes = alg.prepare_key(short_key)
            assert key_bytes == b"secret"
            assert len(w) == 1

        # Test pattern: PyJWT instance usage
        jwt_encoder = PyJWT()
        payload = {"test": "data"}

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            token = jwt_encoder.encode(payload, short_key)
            decoded = jwt_encoder.decode(token, short_key, algorithms=["HS256"])
            assert decoded["test"] == "data"
            assert len(w) == 2  # One for encode, one for decode

    def test_no_regression_with_secure_keys(self):
        """Test that secure keys work without any warnings or errors."""
        # Generate secure keys using standard library
        secure_keys = {
            "HS256": base64.b64encode(secrets.token_bytes(32)).decode(),
            "HS384": base64.b64encode(secrets.token_bytes(48)).decode(),
            "HS512": base64.b64encode(secrets.token_bytes(64)).decode(),
        }

        payload = {"test": "data"}

        for algorithm, key in secure_keys.items():
            # Test algorithm directly
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")

                if algorithm == "HS256":
                    alg = HMACAlgorithm(HMACAlgorithm.SHA256)
                elif algorithm == "HS384":
                    alg = HMACAlgorithm(HMACAlgorithm.SHA384)
                else:  # HS512
                    alg = HMACAlgorithm(HMACAlgorithm.SHA512)

                alg.prepare_key(key)
                assert len(w) == 0

            # Test module-level functions
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                token = jwt.encode(payload, key, algorithm=algorithm)
                decoded = jwt.decode(token, key, algorithms=[algorithm])
                assert decoded["test"] == "data"
                assert len(w) == 0

            # Test strict mode
            jwt_strict = PyJWT(strict_key_validation=True)
            token = jwt_strict.encode(payload, key, algorithm=algorithm)
            decoded = jwt_strict.decode(token, key, algorithms=[algorithm])
            assert decoded["test"] == "data"

    def test_pem_and_ssh_key_rejection_still_works(self):
        """Ensure PEM and SSH key rejection still works with new validation."""
        alg = HMACAlgorithm(HMACAlgorithm.SHA256)

        # Use a real PEM format header - need to have complete lines
        pem_key = """-----BEGIN CERTIFICATE-----
MIIDhTCCAm2gAwIBAgIJANE4sir3EkX8MA0GCSqGSIb3DQEBCwUAMFkxCzAJBgNV
BAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEPMA0GA1UEBwwGQXVzdGluMQ4wDAYDVQQK
-----END CERTIFICATE-----"""
        with pytest.raises(InvalidKeyError) as exc_info:
            alg.prepare_key(pem_key)

        assert "asymmetric key" in str(exc_info.value)
        assert "NIST" not in str(exc_info.value)  # Should not be weak key error

    def test_none_algorithm_unchanged(self):
        """Ensure NoneAlgorithm behavior is unchanged."""
        from jwt.algorithms import NoneAlgorithm

        alg = NoneAlgorithm()

        # Should still work the same way
        assert alg.prepare_key(None) is None  # type: ignore[func-returns-value]

        with pytest.raises(InvalidKeyError):
            alg.prepare_key("some-key")

    def test_instance_level_strict_mode(self):
        """Test that instance-level strict mode works correctly."""
        short_key = "weak"
        payload = {"test": "data"}

        # Test strict mode instance
        jwt_strict = PyJWT(strict_key_validation=True)
        with pytest.raises(InvalidKeyError):
            jwt_strict.encode(payload, short_key)

        # Test non-strict mode instance
        jwt_warn = PyJWT(strict_key_validation=False)
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            token = jwt_warn.encode(payload, short_key)
            decoded = jwt_warn.decode(token, short_key, algorithms=["HS256"])
            assert decoded["test"] == "data"
            assert len(w) == 2  # One for encode, one for decode
