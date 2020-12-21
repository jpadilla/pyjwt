PyJWT
=====

.. image:: https://github.com/jpadilla/pyjwt/workflows/CI/badge.svg
   :target: https://github.com/jpadilla/pyjwt/actions?query=workflow%3ACI

.. image:: https://img.shields.io/pypi/v/pyjwt.svg
   :target: https://pypi.python.org/pypi/pyjwt

.. image:: https://codecov.io/gh/jpadilla/pyjwt/branch/master/graph/badge.svg
   :target: https://codecov.io/gh/jpadilla/pyjwt

.. image:: https://readthedocs.org/projects/pyjwt/badge/?version=stable
   :target: https://pyjwt.readthedocs.io/en/stable/

A Python implementation of `RFC 7519 <https://tools.ietf.org/html/rfc7519>`_. Original implementation was written by `@progrium <https://github.com/progrium>`_.

Sponsor
-------

+--------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| |auth0-logo| | If you want to quickly add secure token-based authentication to Python projects, feel free to check Auth0's Python SDK and free plan at `auth0.com/developers <https://auth0.com/developers?utm_source=GHsponsor&utm_medium=GHsponsor&utm_campaign=pyjwt&utm_content=auth>`_. |
+--------------+-----------------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

.. |auth0-logo| image:: https://user-images.githubusercontent.com/83319/31722733-de95bbde-b3ea-11e7-96bf-4f4e8f915588.png

Installing
----------

Install with **pip**:

.. code-block:: console

    $ pip install PyJWT


Usage
-----

.. code-block:: pycon

    >>> import jwt
    >>> encoded = jwt.encode({"some": "payload"}, "secret", algorithm="HS256")
    >>> print(encoded)
    eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lIjoicGF5bG9hZCJ9.Joh1R2dYzkRvDkqv3sygm5YyK8Gi4ShZqbhK2gxcs2U
    >>> jwt.decode(encoded, "secret", algorithms=["HS256"])
    {'some': 'payload'}

Documentation
-------------

View the full docs online at https://pyjwt.readthedocs.io/en/stable/


Tests
-----

You can run tests from the project root after cloning with:

.. code-block:: console

    $ tox
