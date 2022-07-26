import json
import platform
import sys
from typing import Dict

from . import __version__ as pyjwt_version

try:
    import cryptography
except ModuleNotFoundError:
    cryptography = None  # type: ignore


def info() -> Dict[str, Dict[str, str]]:
    """
    Generate information for a bug report.
    Based on the requests package help utility module.
    """
    try:
        platform_info = {
            "system": platform.system(),
            "release": platform.release(),
        }
    except OSError:
        platform_info = {"system": "Unknown", "release": "Unknown"}

    implementation = platform.python_implementation()

    if implementation == "CPython":
        implementation_version = platform.python_version()
    elif implementation == "PyPy":
        implementation_version = (
            f"{sys.pypy_version_info.major}."  # type: ignore[attr-defined]
            f"{sys.pypy_version_info.minor}."  # type: ignore[attr-defined]
            f"{sys.pypy_version_info.micro}"  # type: ignore[attr-defined]
        )
        if sys.pypy_version_info.releaselevel != "final":  # type: ignore[attr-defined]
            implementation_version = "".join(
                [implementation_version, sys.pypy_version_info.releaselevel]  # type: ignore[attr-defined]
            )
    else:
        implementation_version = "Unknown"

    return {
        "platform": platform_info,
        "implementation": {
            "name": implementation,
            "version": implementation_version,
        },
        "cryptography": {"version": getattr(cryptography, "__version__", "")},
        "pyjwt": {"version": pyjwt_version},
    }


def main() -> None:
    """Pretty-print the bug information as JSON."""
    print(json.dumps(info(), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
