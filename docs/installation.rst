Installation
============

You can install ``PyJWT`` with ``pip``:

.. code-block:: console

    $ pip install pyjwt


.. _installation_cryptography:

Cryptographic Dependencies (Optional)
-------------------------------------

If you are planning on encoding or decoding tokens using certain digital
signature algorithms (like RSA or ECDSA), you will need to install the
cryptography_ library. This can be installed explicitly, or as a required
extra in the ``pyjwt`` requirement:

.. code-block:: console

    $ pip install pyjwt[crypto]

The ``pyjwt[crypto]`` format is recommended in requirements files in
projects using ``PyJWT``, as a separate ``cryptography`` requirement line
may later be mistaken for an unused requirement and removed.


.. _`cryptography`: https://cryptography.io
