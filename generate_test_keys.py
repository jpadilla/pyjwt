from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import os

# Create keys directory if it doesn't exist
os.makedirs("tests/keys", exist_ok=True)

# Generate keys for each curve
def generate_key(curve, priv_filename, pub_filename):
    # Generate private key
    private_key = ec.generate_private_key(curve)
    
    # Write private key
    with open(f"tests/keys/{priv_filename}", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    
    # Write public key
    with open(f"tests/keys/{pub_filename}", "wb") as f:
        f.write(
            private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

# Generate keys for all supported curves
generate_key(ec.SECP256R1(), "testkey_ec_secp256r1.priv", "testkey_ec_secp256r1.pub")
generate_key(ec.SECP256K1(), "testkey_ec_secp256k1.priv", "testkey_ec_secp256k1.pub")
generate_key(ec.SECP384R1(), "testkey_ec_secp384r1.priv", "testkey_ec_secp384r1.pub")
generate_key(ec.SECP521R1(), "testkey_ec_secp521r1.priv", "testkey_ec_secp521r1.pub")

print("Test keys generated successfully")
