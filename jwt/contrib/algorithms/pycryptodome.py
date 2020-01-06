import Cryptodome.Hash.SHA256
import Cryptodome.Hash.SHA384
import Cryptodome.Hash.SHA512
from Cryptodome.PublicKey import ECC, RSA
from Cryptodome.Signature import DSS, PKCS1_v1_5, pss

from jwt.algorithms import Algorithm
from jwt.compat import string_types, text_type


class RSAAlgorithm(Algorithm):
    """
    Performs signing and verification operations using
    RSASSA-PKCS-v1_5 and the specified hash function.

    This class requires PyCryptodome package to be installed.
    """

    SHA256 = Cryptodome.Hash.SHA256
    SHA384 = Cryptodome.Hash.SHA384
    SHA512 = Cryptodome.Hash.SHA512

    def __init__(self, hash_alg):
        self.hash_alg = hash_alg

    def prepare_key(self, key):

        if isinstance(key, RSA.RsaKey):
            return key

        if isinstance(key, string_types):
            if isinstance(key, text_type):
                key = key.encode("utf-8")

            key = RSA.importKey(key)
        else:
            raise TypeError("Expecting a PEM- or RSA-formatted key.")

        return key

    def sign(self, msg, key):
        return PKCS1_v1_5.new(key).sign(self.hash_alg.new(msg))

    def verify(self, msg, key, sig):
        return PKCS1_v1_5.new(key).verify(self.hash_alg.new(msg), sig)


class ECAlgorithm(Algorithm):
    """
    Performs signing and verification operations using
    ECDSA and the specified hash function

    This class requires the PyCryptodome package to be installed.
    """

    SHA256 = Cryptodome.Hash.SHA256
    SHA384 = Cryptodome.Hash.SHA384
    SHA512 = Cryptodome.Hash.SHA512

    def __init__(self, hash_alg):
        self.hash_alg = hash_alg

    def prepare_key(self, key):
        if isinstance(key, ECC.EccKey):
            return key

        if isinstance(key, string_types):
            if isinstance(key, text_type):
                key = key.encode("utf-8")
            key = ECC.import_key(key)
        else:
            raise TypeError("Expecting a PEM- or ECC-formatted key.")

        return key

    def sign(self, msg, key):
        signer = DSS.new(key, "fips-186-3")
        hash_obj = self.hash_alg.new(msg)
        return signer.sign(hash_obj)

    def verify(self, msg, key, sig):
        verifier = DSS.new(key, "fips-186-3")
        hash_obj = self.hash_alg.new(msg)

        try:
            verifier.verify(hash_obj, sig)
            return True
        except ValueError:
            return False


class RSAPSSAlgorithm(RSAAlgorithm):
    """
    Performs a signature using RSASSA-PSS with MGF1

    This class requires the PyCryptodome package to be installed.
    """

    def prepare_key(self, key):
        if isinstance(key, ECC.EccKey):
            return key

        if isinstance(key, string_types):
            if isinstance(key, text_type):
                key = key.encode("utf-8")
            key = RSA.import_key(key)
        else:
            raise TypeError("Expecting a PEM- or RSA-formatted key.")

        return key

    def sign(self, msg, key):
        signer = pss.new(key)
        hash_obj = self.hash_alg.new(msg)
        return signer.sign(hash_obj)

    def verify(self, msg, key, sig):
        hash_obj = self.hash_alg.new(msg)
        verifier = pss.new(key)

        try:
            verifier.verify(hash_obj, sig)
            return True
        except (ValueError, TypeError):
            return False
