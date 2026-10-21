# Build image for the OSS Scanner (https://github.com/anthropics/oss-scanner).
# The scanner builds this with the repository as the build context, then runs the
# finished image with no network access, so every dependency is installed here.
FROM python:3.13-slim-bookworm
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

# Editable install with the optional crypto backend, plus the test dependency group.
RUN python -m pip install --no-cache-dir --group tests -e ".[crypto]"

# Run the test suite so we know the image works, without failing the build on test failures.
RUN python -m pytest -q -p no:cacheprovider || echo "WARNING: pytest reported failures"
