Welcome to ``PyJWT``
====================

``PyJWT`` is a Python library which allows you to encode and decode JSON Web
Tokens (JWT). JWT is an open, industry-standard (`RFC 7519`_) for representing
claims securely between two parties.

Sponsor
-------

+--------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| |auth0-logo| | If you want to quickly add secure token-based authentication to Python projects, feel free to check Auth0's Python SDK and free plan at `auth0.com/developers <https://auth0.com/developers?utm_source=GHsponsor&utm_medium=GHsponsor&utm_campaign=pyjwt&utm_content=auth>`_. |
+--------------+-----------------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

.. |auth0-logo| image:: https://user-images.githubusercontent.com/83319/31722733-de95bbde-b3ea-11e7-96bf-4f4e8f915588.png

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
    >>> print(encoded_jwt)
    eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lIjoicGF5bG9hZCJ9.Joh1R2dYzkRvDkqv3sygm5YyK8Gi4ShZqbhK2gxcs2U
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
