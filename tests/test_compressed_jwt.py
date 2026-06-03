import json
import zlib

from jwt import PyJWT


class CompressedPyJWT(PyJWT):
    def _decode_payload(self, decoded: dict[str, bytes]) -> dict[str, object]:
        payload = json.loads(
            # wbits=-15 has zlib not worry about headers of crc's
            zlib.decompress(decoded["payload"], wbits=-15).decode("utf-8")
        )
        assert isinstance(payload, dict)
        return payload


def test_decodes_complete_valid_jwt_with_compressed_payload() -> None:
    # Test case from https://github.com/jpadilla/pyjwt/pull/753/files
    example_payload = {"hello": "world"}
    example_secret = "secret"
    # payload made with the pako (https://nodeca.github.io/pako/) library in Javascript:
    # Buffer.from(pako.deflateRaw('{"hello": "world"}')).toString('base64url')
    example_jwt = (
        b"eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9"
        b".q1bKSM3JyVeyUlAqzy_KSVGqBQA"
        b".AAn1elCJC5MQCYFwTwa2tjjtyLgqLUVU-Y1vFBsU8jo"
    )
    decoded = CompressedPyJWT().decode_complete(
        example_jwt, example_secret, algorithms=["HS256"]
    )

    assert decoded == {
        "header": {"alg": "HS256", "typ": "JWT"},
        "payload": example_payload,
        "signature": (
            b"\x00\t\xf5zP\x89\x0b\x93\x10\t\x81pO\x06\xb6\xb6"
            b"8\xed\xc8\xb8*-ET\xf9\x8do\x14\x1b\x14\xf2:"
        ),
    }
