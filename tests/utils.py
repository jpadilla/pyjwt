import os
import struct
from calendar import timegm
from datetime import datetime


def utc_timestamp():
    return timegm(datetime.utcnow().utctimetuple())


def key_path(key_name):
    return os.path.join(os.path.dirname(os.path.realpath(__file__)),
                        'keys', key_name)


# Borrowed from `cryptography`
if hasattr(int, "from_bytes"):
    int_from_bytes = int.from_bytes
else:
    def int_from_bytes(data, byteorder, signed=False):
        assert byteorder == 'big'
        assert not signed

        if len(data) % 4 != 0:
            data = (b'\x00' * (4 - (len(data) % 4))) + data

        result = 0

        while len(data) > 0:
            digit, = struct.unpack('>I', data[:4])
            result = (result << 32) + digit
            data = data[4:]

        return result
