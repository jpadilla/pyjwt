
from __future__ import unicode_literals

import jwt
from jwt.__main__ import build_argparser, decode_payload, encode_payload, main

import pytest


class TestCli:

    def test_build_argparse(self):
        args = ['--key', '1234', 'encode', 'name=Vader']
        parser = build_argparser()
        parsed_args = parser.parse_args(args)

        assert parsed_args.key == '1234'

    def test_encode_payload_raises_value_error_key_is_required(self):
        encode_args = ['encode', 'name=Vader', 'job=Sith']
        parser = build_argparser()

        args = parser.parse_args(encode_args)

        with pytest.raises(ValueError) as excinfo:
            encode_payload(args)

        assert 'Key is required when encoding' in str(excinfo.value)

    def test_decode_payload_raises_decoded_error(self):
        decode_args = ['--key', '1234', 'decode', 'wrong-token']
        parser = build_argparser()

        args = parser.parse_args(decode_args)

        with pytest.raises(jwt.DecodeError) as excinfo:
            decode_payload(args)

        assert 'There was an error decoding the token' in str(excinfo.value)

    @pytest.mark.parametrize('key,name,job,exp,verify', [
        ('1234', 'Vader', 'Sith', None, None),
        ('4567', 'Anakin', 'Jedi', '+1', None),
        ('4321', 'Padme', 'Queen', '4070926800', 'true'),
    ])
    def test_main_run(self, key, name, job, exp, verify):
        args = [
            '--key', key,
            'encode',
            'name={0}'.format(name),
            'job={0}'.format(job),
        ]
        if exp:
            args.append('exp={0}'.format(exp))
        if verify:
            args.append('verify={0}'.format(verify))

        token = main(args)
        actual = jwt.decode(token, key)
        expected = {
            'job': job,
            'name': name,
        }

        assert actual['name'] == expected['name']
        assert actual['job'] == expected['job']
