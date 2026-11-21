Contributing to PyJWT
=====================

The source code, issue tracker and pull requests are hosted in the
`PyJWT GitHub repository <https://github.com/jpadilla/pyjwt>`_. Please follow
the project's `Code of Conduct
<https://github.com/jpadilla/pyjwt/blob/master/CODE_OF_CONDUCT.md>`_.

Reporting an issue
------------------

Search the `existing issues <https://github.com/jpadilla/pyjwt/issues>`_
before opening a report. For a bug, include a minimal reproducing example,
the expected and actual results, and system information from::

    python -m jwt.help

Use dummy keys and tokens in examples rather than credentials from a running
application. For suspected vulnerabilities, follow the `security policy
<https://github.com/jpadilla/pyjwt/blob/master/SECURITY.md>`_ and its private
reporting channel instead of opening a public issue.

Setting up a development environment
------------------------------------

Fork the repository on GitHub, clone your fork and create a branch for your
change. From the repository root, create and activate a virtual environment::

    python -m venv .venv
    source .venv/bin/activate

On Windows with PowerShell, activate it with ``.venv\Scripts\Activate.ps1``
instead. Install PyJWT in editable mode with the cryptographic dependencies
and the test runner::

    python -m pip install -e ".[crypto]" tox

Running checks
--------------

The environments in ``tox.ini`` define the checks used by CI. For example,
with Python 3.12 installed, run the tests with and without the optional
cryptographic dependency::

    python -m tox -e py312-crypto,py312-nocrypto

To run a specific test file, pass pytest arguments after ``--``::

    python -m tox -e py312-crypto -- tests/test_api_jwt.py

The documentation checks build HTML and run examples. This environment uses
Python 3.11 and writes the HTML to ``docs/_build/html``::

    python -m tox -e docs

Formatting and lint checks are configured in ``.pre-commit-config.yaml``.
Install and run them before submitting a change::

    python -m pip install pre-commit
    pre-commit run --all-files

Submitting a pull request
-------------------------

Open a pull request against ``master``. Explain the problem and the resulting
behavior, link any related issue, and describe the checks you ran. Include
regression tests for bug fixes and update documentation when the public API
changes. Add an entry under ``Unreleased`` in ``CHANGELOG.rst``; CI checks for
a changelog update unless a maintainer applies an exemption label.
