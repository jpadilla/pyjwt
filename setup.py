#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import re
import sys

from setuptools import find_packages, setup


def get_version(package):
    """
    Return package version as listed in `__version__` in `init.py`.
    """
    with open(os.path.join(package, '__init__.py'), 'rb') as init_py:
        src = init_py.read().decode('utf-8')
        return re.search("__version__ = ['\"]([^'\"]+)['\"]", src).group(1)


version = get_version('jwt')

with open(os.path.join(os.path.dirname(__file__), 'README.rst')) as readme:
    long_description = readme.read()

if sys.argv[-1] == 'publish':
    if os.system("pip freeze | grep twine"):
        print("twine not installed.\nUse `pip install twine`.\nExiting.")
        sys.exit()
    os.system("python setup.py sdist bdist_wheel")
    os.system("twine upload dist/*")
    print('You probably want to also tag the version now:')
    print(" git tag -a {0} -m 'version {0}'".format(version))
    print(' git push --tags')
    sys.exit()

tests_require = [
    'pytest>=4.0.1,<5.0.0',
    'pytest-cov>=2.6.0,<3.0.0',
    'pytest-runner>=4.2,<5.0.0',
]

needs_pytest = set(('pytest', 'test', 'ptr')).intersection(sys.argv)
pytest_runner = ['pytest-runner'] if needs_pytest else []

setup(
    name='PyJWT',
    version=version,
    author='Jose Padilla',
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
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: Utilities',
    ],
    test_suite='tests',
    setup_requires=pytest_runner,
    tests_require=tests_require,
    extras_require=dict(
        test=tests_require,
        crypto=['cryptography >= 1.4'],
        flake8=[
            'flake8',
            'flake8-import-order',
            'pep8-naming'
        ]
    ),
    entry_points={
        'console_scripts': [
            'pyjwt = jwt.__main__:main'
        ]
    }
)
