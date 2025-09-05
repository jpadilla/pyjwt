import json
import zlib

from jwt import PyJWT


class CompressedPyJWT(PyJWT):
    def _decode_payload(self, decoded):
        return json.loads(
            # wbits=-15 has zlib not worry about headers of crc's
            zlib.decompress(decoded["payload"], wbits=-15).decode("utf-8")
        )


def test_decodes_complete_valid_jwt_with_compressed_payload():
    # Test case from https://github.com/jpadilla/pyjwt/pull/753/files
    example_payload = {"hello": "world"}
    example_secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    # payload made with the pako (https://nodeca.github.io/pako/) library in Javascript:
    # Buffer.from(pako.deflateRaw('{"hello": "world"}')).toString('base64')
    example_jwt = (
        b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        b".q1bKSM3JyVeyUlAqzy_KSVGqBQA"
        b".vkKB9BEuLsUnHbA6GBhk2MlmBRZuzH8Fo2GmBqzFdgc"
    )
    decoded = CompressedPyJWT().decode_complete(
        example_jwt, example_secret, algorithms=["HS256"]
    )

    assert decoded == {
        "header": {"alg": "HS256", "typ": "JWT"},
        "payload": example_payload,
        "signature": (
            b"\xbeB\x81\xf4\x11..\xc5'\x1d\xb0:\x18\x18d\xd8\xc9f\x05\x16n"
            b"\xcc\x7f\x05\xa3a\xa6\x06\xac\xc5v\x07"
        ),
    }
