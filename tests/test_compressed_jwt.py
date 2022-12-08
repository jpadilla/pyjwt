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
    example_secret = "secret"
    # payload made with the pako (https://nodeca.github.io/pako/) library in Javascript:
    # Buffer.from(pako.deflateRaw('{"hello": "world"}')).toString('base64')
    example_jwt = (
        b"eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9"
        b".q1bKSM3JyVeyUlAqzy/KSVGqBQA="
        b".08wHYeuh1rJXmcBcMrz6NxmbxAnCQp2rGTKfRNIkxiw="
    )
    decoded = CompressedPyJWT().decode_complete(
        example_jwt, example_secret, algorithms=["HS256"]
    )

    assert decoded == {
        "header": {"alg": "HS256", "typ": "JWT"},
        "payload": example_payload,
        "signature": (
            b"\xd3\xcc\x07a\xeb\xa1\xd6\xb2W\x99\xc0\\2\xbc\xfa7"
            b"\x19\x9b\xc4\t\xc2B\x9d\xab\x192\x9fD\xd2$\xc6,"
        ),
    }
