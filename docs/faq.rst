Frequently Asked Questions
==========================

How can I extract a public / private key from a x509 certificate?
-----------------------------------------------------------------

The ``load_pem_x509_certificate()`` function from ``cryptography`` can be used to
extract the public or private keys from a x509 certificate in PEM format.

.. code-block:: python

    # Python 2
    from cryptography.x509 import load_pem_x509_certificate
    from cryptography.hazmat.backends import default_backend

    cert_str = "-----BEGIN CERTIFICATE-----MIIDETCCAfm..."
    cert_obj = load_pem_x509_certificate(cert_str, default_backend())
    public_key = cert_obj.public_key()
    private_key = cert_obj.private_key()

.. code-block:: python

    # Python 3
    from cryptography.x509 import load_pem_x509_certificate
    from cryptography.hazmat.backends import default_backend

    cert_str = "-----BEGIN CERTIFICATE-----MIIDETCCAfm...".encode()
    cert_obj = load_pem_x509_certificate(cert_str, default_backend())
    public_key = cert_obj.public_key()
    private_key = cert_obj.private_key()
