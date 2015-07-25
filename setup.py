#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os

from setuptools import find_packages, setup

with open(os.path.join(os.path.dirname(__file__), 'README.md')) as readme:
    long_description = readme.read()

tests_require = [
    'pytest',
    'pytest-cov',
    'pytest-runner',
]

setup(
    name='PyJWT',
    use_scm_version={
        'local_scheme': 'dirty-tag',
        'version_scheme': 'guess-next-dev',
        'write_to': 'jwt/_version.py'
    },
    author='José Padilla',
    author_email='hello@jpadilla.com',
    description='JSON Web Token implementation in Python',
    license='MIT',
    keywords='jwt json web token security signing',
    url='http://github.com/jpadilla/pyjwt',
    packages=find_packages(
        exclude=["*.tests", "*.tests.*", "tests.*", "tests"]
    ),
    long_description=long_description,
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Topic :: Utilities',
    ],
    test_suite='tests',
    setup_requires=['pytest-runner', 'setuptools-scm>1.5.4'],
    tests_require=tests_require,
    extras_require=dict(
        test=tests_require,
        crypto=['cryptography'],
        flake8=[
            'flake8',
            'flake8-import-order',
            'pep8-naming'
        ]
    ),
    entry_points={
        'console_scripts': [
            'jwt = jwt.__main__:main'
        ]
    }
)
