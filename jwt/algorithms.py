import hashlib
import hmac

from .api import register_algorithm
from .compat import constant_time_compare, string_types, text_type

try:
    from cryptography.hazmat.primitives import interfaces, hashes
    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key, load_pem_public_key, load_ssh_public_key
    )
    from cryptography.hazmat.primitives.asymmetric import ec, padding
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidSignature

    has_crypto = True
except ImportError:
    has_crypto = False


def _register_default_algorithms():
    """
    Registers the algorithms that are implemented by the library.
    """
    register_algorithm('none', NoneAlgorithm())
    register_algorithm('HS256', HMACAlgorithm(hashlib.sha256))
    register_algorithm('HS384', HMACAlgorithm(hashlib.sha384))
    register_algorithm('HS512', HMACAlgorithm(hashlib.sha512))

    if has_crypto:
        register_algorithm('RS256', RSAAlgorithm(hashes.SHA256()))
        register_algorithm('RS384', RSAAlgorithm(hashes.SHA384()))
        register_algorithm('RS512', RSAAlgorithm(hashes.SHA512()))

        register_algorithm('ES256', ECAlgorithm(hashes.SHA256()))
        register_algorithm('ES384', ECAlgorithm(hashes.SHA384()))
        register_algorithm('ES512', ECAlgorithm(hashes.SHA512()))


class Algorithm(object):
    """
    The interface for an algorithm used to sign and verify tokens.
    """
    def prepare_key(self, key):
        """
        Performs necessary validation and conversions on the key and returns
        the key value in the proper format for sign() and verify().
        """
        raise NotImplementedError

    def sign(self, msg, key):
        """
        Returns a digital signature for the specified message
        using the specified key value.
        """
        raise NotImplementedError

    def verify(self, msg, key, sig):
        """
        Verifies that the specified digital signature is valid
        for the specified message and key values.
        """
        raise NotImplementedError


class NoneAlgorithm(Algorithm):
    """
    Placeholder for use when no signing or verification
    operations are required.
    """
    def prepare_key(self, key):
        return None

    def sign(self, msg, key):
        return b''

    def verify(self, msg, key, sig):
        return False


class HMACAlgorithm(Algorithm):
    """
    Performs signing and verification operations using HMAC
    and the specified hash function.
    """
    def __init__(self, hash_alg):
        self.hash_alg = hash_alg

    def prepare_key(self, key):
        if not isinstance(key, string_types) and not isinstance(key, bytes):
            raise TypeError('Expecting a string- or bytes-formatted key.')

        if isinstance(key, text_type):
            key = key.encode('utf-8')

        return key

    def sign(self, msg, key):
        return hmac.new(key, msg, self.hash_alg).digest()

    def verify(self, msg, key, sig):
        return constant_time_compare(sig, self.sign(msg, key))

if has_crypto:

    class RSAAlgorithm(Algorithm):
        """
        Performs signing and verification operations using
        RSASSA-PKCS-v1_5 and the specified hash function.
        """

        def __init__(self, hash_alg):
            self.hash_alg = hash_alg

        def prepare_key(self, key):
            if isinstance(key, interfaces.RSAPrivateKey) or \
               isinstance(key, interfaces.RSAPublicKey):
                return key

            if isinstance(key, string_types):
                if isinstance(key, text_type):
                    key = key.encode('utf-8')

                try:
                    if key.startswith(b'ssh-rsa'):
                        key = load_ssh_public_key(key, backend=default_backend())
                    else:
                        key = load_pem_private_key(key, password=None, backend=default_backend())
                except ValueError:
                    key = load_pem_public_key(key, backend=default_backend())
            else:
                raise TypeError('Expecting a PEM-formatted key.')

            return key

        def sign(self, msg, key):
            signer = key.signer(
                padding.PKCS1v15(),
                self.hash_alg
            )

            signer.update(msg)
            return signer.finalize()

        def verify(self, msg, key, sig):
            verifier = key.verifier(
                sig,
                padding.PKCS1v15(),
                self.hash_alg
            )

            verifier.update(msg)

            try:
                verifier.verify()
                return True
            except InvalidSignature:
                return False

    class ECAlgorithm(Algorithm):
        """
        Performs signing and verification operations using
        ECDSA and the specified hash function
        """
        def __init__(self, hash_alg):
            self.hash_alg = hash_alg

        def prepare_key(self, key):
            if isinstance(key, interfaces.EllipticCurvePrivateKey) or \
               isinstance(key, interfaces.EllipticCurvePublicKey):
                return key

            if isinstance(key, string_types):
                if isinstance(key, text_type):
                    key = key.encode('utf-8')

                # Attempt to load key. We don't know if it's
                # a Signing Key or a Verifying Key, so we try
                # the Verifying Key first.
                try:
                    key = load_pem_public_key(key, backend=default_backend())
                except ValueError:
                    key = load_pem_private_key(key, password=None, backend=default_backend())

            else:
                raise TypeError('Expecting a PEM-formatted key.')

            return key

        def sign(self, msg, key):
            signer = key.signer(ec.ECDSA(self.hash_alg))

            signer.update(msg)
            return signer.finalize()

        def verify(self, msg, key, sig):
            verifier = key.verifier(sig, ec.ECDSA(self.hash_alg))

            verifier.update(msg)

            try:
                verifier.verify()
                return True
            except InvalidSignature:
                return False
