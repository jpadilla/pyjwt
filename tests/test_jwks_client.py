import contextlib
import json
import ssl
import time
from unittest import mock
from urllib.error import URLError

import pytest

import jwt
from jwt import PyJWKClient
from jwt.api_jwk import PyJWK
from jwt.exceptions import PyJWKClientConnectionError, PyJWKClientError

from .utils import crypto_required

RESPONSE_DATA_WITH_MATCHING_KID = {
    "keys": [
        {
            "alg": "RS256",
            "kty": "RSA",
            "use": "sig",
            "n": "0wtlJRY9-ru61LmOgieeI7_rD1oIna9QpBMAOWw8wTuoIhFQFwcIi7MFB7IEfelCPj08vkfLsuFtR8cG07EE4uvJ78bAqRjMsCvprWp4e2p7hqPnWcpRpDEyHjzirEJle1LPpjLLVaSWgkbrVaOD0lkWkP1T1TkrOset_Obh8BwtO-Ww-UfrEwxTyz1646AGkbT2nL8PX0trXrmira8GnrCkFUgTUS61GoTdb9bCJ19PLX9Gnxw7J0BtR0GubopXq8KlI0ThVql6ZtVGN2dvmrCPAVAZleM5TVB61m0VSXvGWaF6_GeOhbFoyWcyUmFvzWhBm8Q38vWgsSI7oHTkEw",
            "e": "AQAB",
            "kid": "NEE1QURBOTM4MzI5RkFDNTYxOTU1MDg2ODgwQ0UzMTk1QjYyRkRFQw",
            "x5t": "NEE1QURBOTM4MzI5RkFDNTYxOTU1MDg2ODgwQ0UzMTk1QjYyRkRFQw",
            "x5c": [
                "MIIDBzCCAe+gAwIBAgIJNtD9Ozi6j2jJMA0GCSqGSIb3DQEBCwUAMCExHzAdBgNVBAMTFmRldi04N2V2eDlydS5hdXRoMC5jb20wHhcNMTkwNjIwMTU0NDU4WhcNMzMwMjI2MTU0NDU4WjAhMR8wHQYDVQQDExZkZXYtODdldng5cnUuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wtlJRY9+ru61LmOgieeI7/rD1oIna9QpBMAOWw8wTuoIhFQFwcIi7MFB7IEfelCPj08vkfLsuFtR8cG07EE4uvJ78bAqRjMsCvprWp4e2p7hqPnWcpRpDEyHjzirEJle1LPpjLLVaSWgkbrVaOD0lkWkP1T1TkrOset/Obh8BwtO+Ww+UfrEwxTyz1646AGkbT2nL8PX0trXrmira8GnrCkFUgTUS61GoTdb9bCJ19PLX9Gnxw7J0BtR0GubopXq8KlI0ThVql6ZtVGN2dvmrCPAVAZleM5TVB61m0VSXvGWaF6/GeOhbFoyWcyUmFvzWhBm8Q38vWgsSI7oHTkEwIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQlGXpmYaXFB7Q3eG69Uhjd4cFp/jAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAIzQOF/h4T5WWAdjhcIwdNS7hS2Deq+UxxkRv+uavj6O9mHLuRG1q5onvSFShjECXaYT6OGibn7Ufw/JSm3+86ZouMYjBEqGh4OvWRkwARy1YTWUVDGpT2HAwtIq3lfYvhe8P4VfZByp1N4lfn6X2NcJflG+Q+mfXNmRFyyft3Oq51PCZyyAkU7bTun9FmMOyBtmJvQjZ8RXgBLvu9nUcZB8yTVoeUEg4cLczQlli/OkiFXhWgrhVr8uF0/9klslMFXtm78iYSgR8/oC+k1pSNd1+ESSt7n6+JiAQ2Co+ZNKta7LTDGAjGjNDymyoCrZpeuYQwwnHYEHu/0khjAxhXo="
            ],
        }
    ]
}

RESPONSE_DATA_NO_MATCHING_KID = {
    "keys": [
        {
            "alg": "RS256",
            "kty": "RSA",
            "use": "sig",
            "n": "39SJ39VgrQ0qMNK74CaueUBlyYsUyuA7yWlHYZ-jAj6tlFKugEVUTBUVbhGF44uOr99iL_cwmr-srqQDEi-jFHdkS6WFkYyZ03oyyx5dtBMtzrXPieFipSGfQ5EGUGloaKDjL-Ry9tiLnysH2VVWZ5WDDN-DGHxuCOWWjiBNcTmGfnj5_NvRHNUh2iTLuiJpHbGcPzWc5-lc4r-_ehw9EFfp2XsxE9xvtbMZ4SouJCiv9xnrnhe2bdpWuu34hXZCrQwE8DjRY3UR8LjyMxHHPLzX2LWNMHjfN3nAZMteS-Ok11VYDFI-4qCCVGo_WesBCAeqCjPLRyZoV27x1YGsUQ",
            "e": "AQAB",
            "kid": "MLYHNMMhwCNXw9roHIILFsK4nLs=",
        }
    ]
}


@contextlib.contextmanager
def mocked_success_response(data):
    with mock.patch("urllib.request.urlopen") as urlopen_mock:
        response = mock.Mock()
        response.__enter__ = mock.Mock(return_value=response)
        response.__exit__ = mock.Mock()
        response.read.side_effect = [json.dumps(data)]
        urlopen_mock.return_value = response
        yield urlopen_mock


@contextlib.contextmanager
def mocked_failed_response():
    with mock.patch("urllib.request.urlopen") as urlopen_mock:
        urlopen_mock.side_effect = URLError("Fail to process the request.")
        yield urlopen_mock


@contextlib.contextmanager
def mocked_first_call_wrong_kid_second_call_correct_kid(
    response_data_one, response_data_two
):
    with mock.patch("urllib.request.urlopen") as urlopen_mock:
        response = mock.Mock()
        response.__enter__ = mock.Mock(return_value=response)
        response.__exit__ = mock.Mock()
        response.read.side_effect = [
            json.dumps(response_data_one),
            json.dumps(response_data_two),
        ]
        urlopen_mock.return_value = response
        yield urlopen_mock


@contextlib.contextmanager
def mocked_timeout():
    with mock.patch("urllib.request.urlopen") as urlopen_mock:
        urlopen_mock.side_effect = TimeoutError("timed out")
        yield urlopen_mock


@crypto_required
class TestPyJWKClient:
    def test_fetch_data_forwards_headers_to_correct_url(self):
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"

        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID) as mock_request:
            custom_headers = {"User-agent": "my-custom-agent"}
            jwks_client = PyJWKClient(url, headers=custom_headers)
            jwk_set = jwks_client.get_jwk_set()
            request_params = mock_request.call_args[0][0]
            assert request_params.full_url == url
            assert request_params.headers == custom_headers

        assert len(jwk_set.keys) == 1

    def test_get_jwk_set(self):
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"

        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID):
            jwks_client = PyJWKClient(url)
            jwk_set = jwks_client.get_jwk_set()

        assert len(jwk_set.keys) == 1

    def test_get_signing_keys(self):
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"

        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID):
            jwks_client = PyJWKClient(url)
            signing_keys = jwks_client.get_signing_keys()

        assert len(signing_keys) == 1
        assert isinstance(signing_keys[0], PyJWK)

    def test_get_signing_keys_if_no_use_provided(self):
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"

        mocked_key = RESPONSE_DATA_WITH_MATCHING_KID["keys"][0].copy()
        del mocked_key["use"]
        response = {"keys": [mocked_key]}

        with mocked_success_response(response):
            jwks_client = PyJWKClient(url)
            signing_keys = jwks_client.get_signing_keys()

        assert len(signing_keys) == 1
        assert isinstance(signing_keys[0], PyJWK)

    def test_get_signing_keys_raises_if_none_found(self):
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"

        mocked_key = RESPONSE_DATA_WITH_MATCHING_KID["keys"][0].copy()
        mocked_key["use"] = "enc"
        response = {"keys": [mocked_key]}
        with mocked_success_response(response):
            jwks_client = PyJWKClient(url)

            with pytest.raises(PyJWKClientError) as exc:
                jwks_client.get_signing_keys()

        assert "The JWKS endpoint did not contain any signing keys" in str(exc.value)

    def test_get_signing_key(self):
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"
        kid = "NEE1QURBOTM4MzI5RkFDNTYxOTU1MDg2ODgwQ0UzMTk1QjYyRkRFQw"

        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID):
            jwks_client = PyJWKClient(url)
            signing_key = jwks_client.get_signing_key(kid)

        assert isinstance(signing_key, PyJWK)
        assert signing_key.key_type == "RSA"
        assert signing_key.key_id == kid
        assert signing_key.public_key_use == "sig"

    def test_get_signing_key_caches_result(self):
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"
        kid = "NEE1QURBOTM4MzI5RkFDNTYxOTU1MDg2ODgwQ0UzMTk1QjYyRkRFQw"

        jwks_client = PyJWKClient(url, cache_keys=True)

        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID):
            jwks_client.get_signing_key(kid)

        # mocked_response does not allow urllib.request.urlopen to be called twice
        # so a second mock is needed
        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID) as repeated_call:
            jwks_client.get_signing_key(kid)

        assert repeated_call.call_count == 0

    def test_get_signing_key_does_not_cache_opt_out(self):
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"
        kid = "NEE1QURBOTM4MzI5RkFDNTYxOTU1MDg2ODgwQ0UzMTk1QjYyRkRFQw"

        jwks_client = PyJWKClient(url, cache_jwk_set=False)

        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID):
            jwks_client.get_signing_key(kid)

        # mocked_response does not allow urllib.request.urlopen to be called twice
        # so a second mock is needed
        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID) as repeated_call:
            jwks_client.get_signing_key(kid)

        assert repeated_call.call_count == 1

    def test_get_signing_key_from_jwt(self):
        token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik5FRTFRVVJCT1RNNE16STVSa0ZETlRZeE9UVTFNRGcyT0Rnd1EwVXpNVGsxUWpZeVJrUkZRdyJ9.eyJpc3MiOiJodHRwczovL2Rldi04N2V2eDlydS5hdXRoMC5jb20vIiwic3ViIjoiYVc0Q2NhNzl4UmVMV1V6MGFFMkg2a0QwTzNjWEJWdENAY2xpZW50cyIsImF1ZCI6Imh0dHBzOi8vZXhwZW5zZXMtYXBpIiwiaWF0IjoxNTcyMDA2OTU0LCJleHAiOjE1NzIwMDY5NjQsImF6cCI6ImFXNENjYTc5eFJlTFdVejBhRTJINmtEME8zY1hCVnRDIiwiZ3R5IjoiY2xpZW50LWNyZWRlbnRpYWxzIn0.PUxE7xn52aTCohGiWoSdMBZGiYAHwE5FYie0Y1qUT68IHSTXwXVd6hn02HTah6epvHHVKA2FqcFZ4GGv5VTHEvYpeggiiZMgbxFrmTEY0csL6VNkX1eaJGcuehwQCRBKRLL3zKmA5IKGy5GeUnIbpPHLHDxr-GXvgFzsdsyWlVQvPX2xjeaQ217r2PtxDeqjlf66UYl6oY6AqNS8DH3iryCvIfCcybRZkc_hdy-6ZMoKT6Piijvk_aXdm7-QQqKJFHLuEqrVSOuBqqiNfVrG27QzAPuPOxvfXTVLXL2jek5meH6n-VWgrBdoMFH93QEszEDowDAEhQPHVs0xj7SIzA"
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"

        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID):
            jwks_client = PyJWKClient(url)
            signing_key = jwks_client.get_signing_key_from_jwt(token)

        data = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience="https://expenses-api",
            options={"verify_exp": False},
        )

        assert data == {
            "iss": "https://dev-87evx9ru.auth0.com/",
            "sub": "aW4Cca79xReLWUz0aE2H6kD0O3cXBVtC@clients",
            "aud": "https://expenses-api",
            "iat": 1572006954,
            "exp": 1572006964,
            "azp": "aW4Cca79xReLWUz0aE2H6kD0O3cXBVtC",
            "gty": "client-credentials",
        }

    def test_get_jwk_set_caches_result(self):
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"

        jwks_client = PyJWKClient(url)
        assert jwks_client.jwk_set_cache is not None

        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID):
            jwks_client.get_jwk_set()

        # mocked_response does not allow urllib.request.urlopen to be called twice
        # so a second mock is needed
        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID) as repeated_call:
            jwks_client.get_jwk_set()

        assert repeated_call.call_count == 0

    def test_get_jwt_set_cache_expired_result(self):
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"

        jwks_client = PyJWKClient(url, lifespan=1)
        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID):
            jwks_client.get_jwk_set()

        time.sleep(2)

        # mocked_response does not allow urllib.request.urlopen to be called twice
        # so a second mock is needed
        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID) as repeated_call:
            jwks_client.get_jwk_set()

        assert repeated_call.call_count == 1

    def test_get_jwt_set_cache_disabled(self):
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"

        jwks_client = PyJWKClient(url, cache_jwk_set=False)
        assert jwks_client.jwk_set_cache is None

        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID):
            jwks_client.get_jwk_set()

        assert jwks_client.jwk_set_cache is None

        time.sleep(2)

        # mocked_response does not allow urllib.request.urlopen to be called twice
        # so a second mock is needed
        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID) as repeated_call:
            jwks_client.get_jwk_set()

        assert repeated_call.call_count == 1

    def test_get_jwt_set_failed_request_should_clear_cache(self):
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"

        jwks_client = PyJWKClient(url)
        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID):
            jwks_client.get_jwk_set()

        with pytest.raises(PyJWKClientError):
            with mocked_failed_response():
                jwks_client.get_jwk_set(refresh=True)

            assert jwks_client.jwk_set_cache is None

    def test_failed_request_should_raise_connection_error(self):
        token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik5FRTFRVVJCT1RNNE16STVSa0ZETlRZeE9UVTFNRGcyT0Rnd1EwVXpNVGsxUWpZeVJrUkZRdyJ9.eyJpc3MiOiJodHRwczovL2Rldi04N2V2eDlydS5hdXRoMC5jb20vIiwic3ViIjoiYVc0Q2NhNzl4UmVMV1V6MGFFMkg2a0QwTzNjWEJWdENAY2xpZW50cyIsImF1ZCI6Imh0dHBzOi8vZXhwZW5zZXMtYXBpIiwiaWF0IjoxNTcyMDA2OTU0LCJleHAiOjE1NzIwMDY5NjQsImF6cCI6ImFXNENjYTc5eFJlTFdVejBhRTJINmtEME8zY1hCVnRDIiwiZ3R5IjoiY2xpZW50LWNyZWRlbnRpYWxzIn0.PUxE7xn52aTCohGiWoSdMBZGiYAHwE5FYie0Y1qUT68IHSTXwXVd6hn02HTah6epvHHVKA2FqcFZ4GGv5VTHEvYpeggiiZMgbxFrmTEY0csL6VNkX1eaJGcuehwQCRBKRLL3zKmA5IKGy5GeUnIbpPHLHDxr-GXvgFzsdsyWlVQvPX2xjeaQ217r2PtxDeqjlf66UYl6oY6AqNS8DH3iryCvIfCcybRZkc_hdy-6ZMoKT6Piijvk_aXdm7-QQqKJFHLuEqrVSOuBqqiNfVrG27QzAPuPOxvfXTVLXL2jek5meH6n-VWgrBdoMFH93QEszEDowDAEhQPHVs0xj7SIzA"
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"

        jwks_client = PyJWKClient(url)
        with pytest.raises(PyJWKClientConnectionError):
            with mocked_failed_response():
                jwks_client.get_signing_key_from_jwt(token)

    def test_get_jwt_set_refresh_cache(self):
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"
        jwks_client = PyJWKClient(url)

        kid = "NEE1QURBOTM4MzI5RkFDNTYxOTU1MDg2ODgwQ0UzMTk1QjYyRkRFQw"

        # The first call will return response with no matching kid,
        # the function should make another call to try to refresh the cache.
        with mocked_first_call_wrong_kid_second_call_correct_kid(
            RESPONSE_DATA_NO_MATCHING_KID, RESPONSE_DATA_WITH_MATCHING_KID
        ) as call_data:
            jwks_client.get_signing_key(kid)

        assert call_data.call_count == 2

    def test_get_jwt_set_no_matching_kid_after_second_attempt(self):
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"
        jwks_client = PyJWKClient(url)

        kid = "NEE1QURBOTM4MzI5RkFDNTYxOTU1MDg2ODgwQ0UzMTk1QjYyRkRFQw"

        with pytest.raises(PyJWKClientError):
            with mocked_first_call_wrong_kid_second_call_correct_kid(
                RESPONSE_DATA_NO_MATCHING_KID, RESPONSE_DATA_NO_MATCHING_KID
            ):
                jwks_client.get_signing_key(kid)

    def test_get_jwt_set_invalid_lifespan(self):
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"

        with pytest.raises(PyJWKClientError):
            jwks_client = PyJWKClient(url, lifespan=-1)
            assert jwks_client is None

    def test_get_jwt_set_timeout(self):
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"
        jwks_client = PyJWKClient(url, timeout=5)

        with pytest.raises(PyJWKClientError) as exc:
            with mocked_timeout():
                jwks_client.get_jwk_set()

        assert 'Fail to fetch data from the url, err: "timed out"' in str(exc.value)

    def test_get_jwt_set_sslcontext_default(self):
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"
        ssl_ctx = ssl.create_default_context()
        jwks_client = PyJWKClient(url, ssl_context=ssl_ctx)

        with mocked_success_response(RESPONSE_DATA_WITH_MATCHING_KID) as mock_request:
            jwk_set = jwks_client.get_jwk_set()
            request_call = mock_request.call_args
            assert request_call[1].get("context") is ssl_ctx

        assert jwk_set is not None

    def test_get_jwt_set_sslcontext_no_ca(self):
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"
        jwks_client = PyJWKClient(
            url, ssl_context=ssl.SSLContext(protocol=ssl.PROTOCOL_TLS_CLIENT)
        )

        with mock.patch("urllib.request.urlopen") as urlopen_mock:
            urlopen_mock.side_effect = URLError(
                ssl.SSLCertVerificationError("certificate verify failed")
            )
            with pytest.raises(PyJWKClientError):
                jwks_client.get_jwk_set()
