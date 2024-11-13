Welcome to ``PyJWT``
====================

``PyJWT`` is a Python library which allows you to encode and decode JSON Web
Tokens (JWT). JWT is an open, industry-standard (`RFC 7519`_) for representing
claims securely between two parties.

Sponsor
-------
.. |auth0-logo| image:: https://github.com/user-attachments/assets/ee98379e-ee76-4bcb-943a-e25c4ea6d174
   :width: 160px

+--------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| |auth0-logo| | If you want to quickly add secure token-based authentication to Python projects, feel free to check Auth0's Python SDK and free plan at `auth0.com/signup <https://auth0.com/signup?utm_source=external_sites&utm_medium=pyjwt&utm_campaign=devn_signup>`_. |
+--------------+-----------------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

Installation
------------
You can install ``pyjwt`` with ``pip``:

.. code-block:: console

    $ pip install pyjwt

See :doc:`Installation <installation>` for more information.

Example Usage
-------------

.. doctest::

    >>> import jwt
    >>> encoded_jwt = jwt.encode({"some": "payload"}, "secret", algorithm="HS256")
    >>> jwt.decode(encoded_jwt, "secret", algorithms=["HS256"])
    {'some': 'payload'}

See :doc:`Usage Examples <usage>` for more examples.

Index
-----

.. toctree::
    :maxdepth: 2

    installation
    usage
    faq
    algorithms
    api
    changelog

.. _`RFC 7519`: https://tools.ietf.org/html/rfc7519
