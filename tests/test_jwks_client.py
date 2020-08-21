import pytest
import requests_mock

import jwt
from jwt import PyJWKClient
from jwt.api_jwk import PyJWK
from jwt.exceptions import PyJWKClientError

from .test_algorithms import has_crypto


@pytest.fixture
def mocked_response():
    return {
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


@pytest.mark.skipif(
    not has_crypto, reason="Not supported without cryptography library"
)
class TestPyJWKClient:
    def test_get_jwk_set(self, mocked_response):
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"

        with requests_mock.mock() as m:
            m.get(url, json=mocked_response)
            jwks_client = PyJWKClient(url)
            jwk_set = jwks_client.get_jwk_set()

        assert len(jwk_set.keys) == 1

    def test_get_signing_keys(self, mocked_response):
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"

        with requests_mock.mock() as m:
            m.get(url, json=mocked_response)
            jwks_client = PyJWKClient(url)
            signing_keys = jwks_client.get_signing_keys()

        assert len(signing_keys) == 1
        assert isinstance(signing_keys[0], PyJWK)

    def test_get_signing_keys_raises_if_none_found(self, mocked_response):
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"

        with requests_mock.mock() as m:
            mocked_key = mocked_response["keys"][0].copy()
            mocked_key["use"] = "enc"
            response = {"keys": [mocked_key]}
            m.get(url, json=response)
            jwks_client = PyJWKClient(url)

            with pytest.raises(PyJWKClientError) as exc:
                jwks_client.get_signing_keys()

        assert "The JWKS endpoint did not contain any signing keys" in str(
            exc.value
        )

    def test_get_signing_key(self, mocked_response):
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"
        kid = "NEE1QURBOTM4MzI5RkFDNTYxOTU1MDg2ODgwQ0UzMTk1QjYyRkRFQw"

        with requests_mock.mock() as m:
            m.get(url, json=mocked_response)
            jwks_client = PyJWKClient(url)
            signing_key = jwks_client.get_signing_key(kid)

        assert isinstance(signing_key, PyJWK)
        assert signing_key.key_type == "RSA"
        assert signing_key.key_id == kid
        assert signing_key.public_key_use == "sig"

    def test_get_signing_key_from_jwt(self, mocked_response):
        token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik5FRTFRVVJCT1RNNE16STVSa0ZETlRZeE9UVTFNRGcyT0Rnd1EwVXpNVGsxUWpZeVJrUkZRdyJ9.eyJpc3MiOiJodHRwczovL2Rldi04N2V2eDlydS5hdXRoMC5jb20vIiwic3ViIjoiYVc0Q2NhNzl4UmVMV1V6MGFFMkg2a0QwTzNjWEJWdENAY2xpZW50cyIsImF1ZCI6Imh0dHBzOi8vZXhwZW5zZXMtYXBpIiwiaWF0IjoxNTcyMDA2OTU0LCJleHAiOjE1NzIwMDY5NjQsImF6cCI6ImFXNENjYTc5eFJlTFdVejBhRTJINmtEME8zY1hCVnRDIiwiZ3R5IjoiY2xpZW50LWNyZWRlbnRpYWxzIn0.PUxE7xn52aTCohGiWoSdMBZGiYAHwE5FYie0Y1qUT68IHSTXwXVd6hn02HTah6epvHHVKA2FqcFZ4GGv5VTHEvYpeggiiZMgbxFrmTEY0csL6VNkX1eaJGcuehwQCRBKRLL3zKmA5IKGy5GeUnIbpPHLHDxr-GXvgFzsdsyWlVQvPX2xjeaQ217r2PtxDeqjlf66UYl6oY6AqNS8DH3iryCvIfCcybRZkc_hdy-6ZMoKT6Piijvk_aXdm7-QQqKJFHLuEqrVSOuBqqiNfVrG27QzAPuPOxvfXTVLXL2jek5meH6n-VWgrBdoMFH93QEszEDowDAEhQPHVs0xj7SIzA"
        url = "https://dev-87evx9ru.auth0.com/.well-known/jwks.json"

        with requests_mock.mock() as m:
            m.get(url, json=mocked_response)
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
