import jwt


class TestES256:
    def test_jwt_encode(self):
        with open('tests/keys/testkey_rsa', 'r') as rsa_priv_file:
            priv_rsakey = rsa_priv_file.read()
            jwt_token = jwt.encode({
                'some': 'field',
            }, priv_rsakey, algorithm='ES256')
            assert jwt_token is not None