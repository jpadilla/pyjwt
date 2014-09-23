#!/usr/bin/env python
import os
from setuptools import setup


with open(os.path.join(os.path.dirname(__file__), 'README.md')) as readme:
    long_description = readme.read()


setup(
    name="PyJWT",
    version="0.2.2",
    author="Jeff Lindsay",
    author_email="progrium@gmail.com",
    description="JSON Web Token implementation in Python",
    license="MIT",
    keywords="jwt json web token security signing",
    url="http://github.com/progrium/pyjwt",
    packages=['jwt'],
    scripts=['bin/jwt'],
    long_description=long_description,
    classifiers=[
        "Development Status :: 3 - Alpha",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.2",
        "Programming Language :: Python :: 3.3",
        "Topic :: Utilities",
    ],
    test_suite='tests.test_jwt'
)
