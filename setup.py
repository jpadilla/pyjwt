#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys

from setuptools import find_packages, setup

__version__ = None
with open('jwt/__init__.py') as fp:
    _locals = {}
    for line in fp:
        if line.startswith('__version__'):
            exec(line, None, _locals)
            __version__ = _locals['__version__']
            break

with open(os.path.join(os.path.dirname(__file__), 'README.md')) as readme:
    long_description = readme.read()

if sys.argv[-1] == 'publish':
    os.system('python setup.py sdist upload')
    os.system('python setup.py bdist_wheel upload')
    print('You probably want to also tag the version now:')
    print(" git tag -a {0} -m 'version {0}'".format(__version__))
    print(' git push --tags')
    sys.exit()

tests_require = [
    'pytest',
    'pytest-cov',
    'pytest-runner',
]

setup(
    name='PyJWT',
    version=__version__,
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
    # install_requires=['cryptography'],
    test_suite='tests',
    setup_requires=['pytest-runner'],
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
