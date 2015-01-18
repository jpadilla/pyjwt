#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys

from setuptools import setup

about = {}

with open(os.path.join("jwt", "__about__.py")) as f:
    exec(f.read(), about)

with open(os.path.join(os.path.dirname(__file__), 'README.md')) as readme:
    long_description = readme.read()


if sys.argv[-1] == 'publish':
    os.system("python setup.py sdist upload")
    os.system("python setup.py bdist_wheel upload")
    print("You probably want to also tag the version now:")
    print("  git tag -a %s -m 'version %s'" % (about['__version__'], about['__version__']))
    print("  git push --tags")
    sys.exit()


setup(
    name=about['__title__'],
    version=about['__version__'],
    author=about['__author__'],
    author_email=about['__email__'],
    description=about['__description__'],
    license=about['__license__'],
    keywords='jwt json web token security signing',
    url=about['__url__'],
    packages=['jwt'],
    scripts=['bin/jwt'],
    long_description=long_description,
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Topic :: Utilities',
    ],
    test_suite='tests.test_jwt'
)
