
import argparse
import json
import sys

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

    def test_decode_payload_raises_decoded_error_isatty(self, monkeypatch):
        def patched_sys_stdin_read():
            raise jwt.DecodeError()

        decode_args = ['--key', '1234', 'decode', 'wrong-token']
        parser = build_argparser()

        args = parser.parse_args(decode_args)

        monkeypatch.setattr(sys.stdin, 'isatty', lambda: True)
        monkeypatch.setattr(sys.stdin, 'read', patched_sys_stdin_read)

        with pytest.raises(jwt.DecodeError) as excinfo:
            decode_payload(args)

        assert 'There was an error decoding the token' in str(excinfo.value)

    def test_decode_payload_terminal_tty(self, monkeypatch):
        encode_args = [
            '--key=secret-key',
            'encode',
            'name=hello-world',
        ]
        parser = build_argparser()
        parsed_encode_args = parser.parse_args(encode_args)
        token = encode_payload(parsed_encode_args)

        decode_args = ['--key=secret-key', 'decode']
        parsed_decode_args = parser.parse_args(decode_args)

        monkeypatch.setattr(sys.stdin, 'isatty', lambda: True)
        monkeypatch.setattr(sys.stdin, 'readline', lambda:  token)

        actual = json.loads(decode_payload(parsed_decode_args))
        assert actual['name'] == 'hello-world'

    def test_decode_payload_raises_terminal_not_a_tty(self, monkeypatch):
        decode_args = ['--key', '1234', 'decode']
        parser = build_argparser()
        args = parser.parse_args(decode_args)

        monkeypatch.setattr(sys.stdin, 'isatty', lambda: False)

        with pytest.raises(IOError) as excinfo:
            decode_payload(args)
            assert 'Cannot read from stdin: terminal not a TTY' \
                in str(excinfo.value)

    @pytest.mark.parametrize('key,name,job,exp,verify', [
        ('1234', 'Vader', 'Sith', None, None),
        ('4567', 'Anakin', 'Jedi', '+1', None),
        ('4321', 'Padme', 'Queen', '4070926800', 'true'),
    ])
    def test_encode_decode(self, key, name, job, exp, verify):
        encode_args = [
            '--key={0}'.format(key),
            'encode',
            'name={0}'.format(name),
            'job={0}'.format(job),
        ]
        if exp:
            encode_args.append('exp={0}'.format(exp))
        if verify:
            encode_args.append('verify={0}'.format(verify))

        parser = build_argparser()
        parsed_encode_args = parser.parse_args(encode_args)
        token = encode_payload(parsed_encode_args)
        assert token is not None
        assert token is not ''

        decode_args = [
            '--key={0}'.format(key),
            'decode',
            token
        ]
        parser = build_argparser()
        parsed_decode_args = parser.parse_args(decode_args)

        actual = json.loads(decode_payload(parsed_decode_args))
        expected = {
            'job': job,
            'name': name,
        }
        assert actual['name'] == expected['name']
        assert actual['job'] == expected['job']

    @pytest.mark.parametrize('key,name,job,exp,verify', [
        ('1234', 'Vader', 'Sith', None, None),
        ('4567', 'Anakin', 'Jedi', '+1', None),
        ('4321', 'Padme', 'Queen', '4070926800', 'true'),
    ])
    def test_main(self, monkeypatch, key, name, job, exp, verify):
        args = [
            'test_cli.py',
            '--key={0}'.format(key),
            'encode',
            'name={0}'.format(name),
            'job={0}'.format(job),
        ]
        if exp:
            args.append('exp={0}'.format(exp))
        if verify:
            args.append('verify={0}'.format(verify))
        monkeypatch.setattr(sys, 'argv', args)
        main()

    def test_main_throw_exception(self, monkeypatch, capsys):
        def patched_argparser_parse_args(self, args):
            raise Exception('NOOOOOOOOOOO!')

        monkeypatch.setattr(argparse.ArgumentParser, 'parse_args', patched_argparser_parse_args)
        main()
        out, _ = capsys.readouterr()

        assert 'NOOOOOOOOOOO!' in out
