Installation
============

You can install ``PyJWT`` with ``pip``:

.. code-block:: console

    $ pip install pyjwt

Cryptographic Dependencies (Optional)
-------------------------------------

If you are planning on encoding or decoding tokens using certain digital
signature algorithms (like RSA or ECDSA), you will need to install the
cryptography_ library.

.. code-block:: console

    $ pip install cryptography

.. _legacy-deps:

Legacy Dependencies
-------------------

Some environments, most notably Google App Engine, do not allow the installation
of Python packages that require compilation of C extensions and therefore
cannot install ``cryptography``. If you can install ``cryptography``, you
should disregard this section.

If you are deploying an application to one of these environments, you may
need to use the legacy implementations of the  digital signature algorithms:

.. code-block:: console

    $ pip install pycrypto ecdsa

Once you have installed ``pycrypto`` and ``ecdcsa``, you can tell PyJWT to use
the legacy implementations with ``jwt.register_algorithm()``. The following
example code shows how to configure PyJWT to use the legacy implementations
for RSA with SHA256 and EC with SHA256 signatures.

.. code-block:: python

    import jwt
    from jwt.contrib.algorithms.pycrypto import RSAAlgorithm
    from jwt.contrib.algorithms.py_ecdsa import ECAlgorithm

    jwt.register_algorithm('RS256', RSAAlgorithm(RSAAlgorithm.SHA256))
    jwt.register_algorithm('ES256', ECAlgorithm(ECAlgorithm.SHA256))


.. _`cryptography`: https://cryptography.io
