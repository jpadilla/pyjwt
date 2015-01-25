from .compat import text_type


def ensure_bytes(key):
    if isinstance(key, text_type):
        key = key.encode('utf-8')

    return key


def ensure_unicode(key):
    if not isinstance(key, text_type):
        key = key.decode()

    return key
