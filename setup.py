import codecs
import os
import re

from setuptools import find_packages, setup


###############################################################################

NAME = "PyJWT"
PACKAGES = find_packages(where="src")
META_PATH = os.path.join("src", "jwt", "__init__.py")
KEYWORDS = ["jwt", "json web token", "security", "signing"]
PROJECT_URLS = {
    "Documentation": "https://pyjwt.readthedocs.io",
    "Bug Tracker": "https://github.com/jpadilla/pyjwt/issues",
    "Source Code": "https://github.com/jpadilla/pyjwt",
}
CLASSIFIERS = [
    "Development Status :: 5 - Production/Stable",
    "Intended Audience :: Developers",
    "Natural Language :: English",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.5",
    "Programming Language :: Python :: 3.6",
    "Programming Language :: Python :: 3.7",
    "Programming Language :: Python :: 3.8",
    "Topic :: Utilities",
]
INSTALL_REQUIRES = []
EXTRAS_REQUIRE = {
    "jwks-client": ["requests"],
    "tests": [
        "pytest>=4.0.1,<5.0.0",
        "pytest-cov>=2.6.0,<3.0.0",
        "requests-mock>=1.7.0,<2.0.0",
    ],
    "cryptography": ["cryptography >= 1.4"],
}

EXTRAS_REQUIRE["dev"] = (
    EXTRAS_REQUIRE["tests"]
    + EXTRAS_REQUIRE["cryptography"]
    + EXTRAS_REQUIRE["jwks-client"]
    + ["mypy", "pre-commit"]
)

###############################################################################

HERE = os.path.abspath(os.path.dirname(__file__))


def read(*parts):
    """
    Build an absolute path from *parts* and and return the contents of the
    resulting file.  Assume UTF-8 encoding.
    """
    with codecs.open(os.path.join(HERE, *parts), "rb", "utf-8") as f:
        return f.read()


META_FILE = read(META_PATH)


def find_meta(meta):
    """
    Extract __*meta*__ from META_FILE.
    """
    meta_match = re.search(
        r"^__{meta}__ = ['\"]([^'\"]*)['\"]".format(meta=meta), META_FILE, re.M
    )
    if meta_match:
        return meta_match.group(1)
    raise RuntimeError("Unable to find __{meta}__ string.".format(meta=meta))


with open(os.path.join(HERE, "README.rst")) as readme:
    LONG = readme.read()


VERSION = find_meta("version")
URL = find_meta("url")


if __name__ == "__main__":
    setup(
        name=NAME,
        description=find_meta("description"),
        license=find_meta("license"),
        url=URL,
        project_urls=PROJECT_URLS,
        version=VERSION,
        author=find_meta("author"),
        author_email=find_meta("email"),
        maintainer=find_meta("author"),
        maintainer_email=find_meta("email"),
        keywords=KEYWORDS,
        long_description=LONG,
        long_description_content_type="text/x-rst",
        packages=PACKAGES,
        package_dir={"": "src"},
        python_requires=">=3, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*",
        zip_safe=False,
        classifiers=CLASSIFIERS,
        install_requires=INSTALL_REQUIRES,
        extras_require=EXTRAS_REQUIRE,
        include_package_data=True,
        options={"bdist_wheel": {"universal": "1"}},
    )
