
import json

from jwt import DecodeError
from jwt.__main__ import build_argparser, decode_payload, encode_payload, main

import pytest


@pytest.fixture
def token():
    return '%s.%s.%s' % ('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9',
                         'eyJuYW1lIjoiVmFkZXIiLCJqb2IiOiJTaXRoIn0',
                         'eS5n_fxbLSpzHNY19fcEXj4GCU7c4Pog4jv2qq-cKgo')


@pytest.fixture
def decode_args(token):
    return ['--key', '1234', 'decode', token]


class TestCli:

    def test_build_argparse(self):
        args = ['--key', '1234', 'encode', 'name=Vader']
        parser = build_argparser()
        parsed_args = parser.parse_args(args)

        assert parsed_args.key == '1234'

    def test_encode_payload(self, token):
        encode_args = ['--key', '1234', 'encode', 'name=Vader', 'job=Sith']
        parser = build_argparser()

        args = parser.parse_args(encode_args)

        assert encode_payload(args) == token

    def test_encode_payload_raises_value_error_key_is_required(self):
        encode_args = ['encode', 'name=Vader', 'job=Sith']
        parser = build_argparser()

        args = parser.parse_args(encode_args)

        with pytest.raises(ValueError) as excinfo:
            encode_payload(args)

        assert 'Key is required when encoding' in str(excinfo.value)

    def test_decode_payload(self, decode_args):
        parser = build_argparser()

        args = parser.parse_args(decode_args)

        assert decode_payload(args) == json.dumps({'name': 'Vader', 'job': 'Sith'})

    def test_decode_payload_raises_decoded_error(self):
        decode_args = ['--key', '1234', 'decode', 'wrong-token']
        parser = build_argparser()

        args = parser.parse_args(decode_args)

        with pytest.raises(DecodeError) as excinfo:
            decode_payload(args)

        assert 'There was an error decoding the token' in str(excinfo.value)

    def test_main_run(self, token):
        args = ['--key', '1234', 'encode', 'name=Vader', 'job=Sith']

        assert main(args) == token
