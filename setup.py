import os
from setuptools import setup

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "PyJWT",
    version = "0.1.6",
    author = "Jeff Lindsay",
    author_email = "jeff.lindsay@twilio.com",
    description = ("JSON Web Token implementation in Python"),
    license = "MIT",
    keywords = "jwt json web token security signing",
    url = "http://github.com/progrium/pyjwt",
    packages=['jwt'],
    scripts=['bin/jwt'],
    long_description=read('README.md'),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Topic :: Utilities",
        "License :: OSI Approved :: MIT License",
    ],
)
