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
    eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzb21lIjoicGF5bG9hZCJ9.4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZg
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
