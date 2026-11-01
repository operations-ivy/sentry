# Built and pushed by brick-cicd-config's build-image Jenkins job (a
# reproducible rootless BuildKit build on brick2000): IMAGE=whitepatrick/overwatch, REF=<full commit>, TAG=<version>.
#
# One image, three roles (k8s_config/): `scan`, `wifi` and `web`. The base image is
# pinned by digest and dependencies come from poetry.lock. Bump the base
# deliberately, with the digest from:
#   docker buildx imagetools inspect python:3.11-slim-bookworm
ARG PYTHON=python:3.11-slim-bookworm@sha256:a36c24f9cbdf4fd0f52d67f0823eeac19c2028c637cecc392d97f980d4fec56b

# Poetry installs the locked dependencies into /venv; only /venv is kept.
FROM ${PYTHON} AS deps
ARG POETRY_VERSION=2.1.2
ENV PIP_DEFAULT_TIMEOUT=120 POETRY_NO_INTERACTION=1 VIRTUAL_ENV=/venv PATH=/venv/bin:$PATH
# One package at a time: the parallel installer races on the umask (wigle-sync).
ENV POETRY_INSTALLER_PARALLEL=false
RUN pip install --no-cache-dir "poetry==${POETRY_VERSION}"
WORKDIR /code
COPY pyproject.toml poetry.lock /code/
# Poetry leaves its clone of a git dependency in /venv/src. The package itself is
# in site-packages, and the clone's .git/index changes every build, and so the digest.
RUN python -m venv --without-pip /venv && poetry install --no-root --only main && rm -rf /venv/src

FROM ${PYTHON}
# iw and ip for the Wi-Fi watch: monitor mode and channel hops on the dongle.
# iw and iproute2 for the Wi-Fi watch. Reproducible: apt reads a fixed
# snapshot.debian.org date (not the live mirrors, whose versions move), and the
# logs and caches apt and dpkg write (stamped with the build's clock) are
# removed. Bump SNAPSHOT deliberately to take Debian updates.
ARG SNAPSHOT=20261013T000000Z
RUN rm -f /etc/apt/sources.list.d/debian.sources \
    && echo "deb http://snapshot.debian.org/archive/debian/${SNAPSHOT} bookworm main" > /etc/apt/sources.list \
    && echo "deb http://snapshot.debian.org/archive/debian-security/${SNAPSHOT} bookworm-security main" >> /etc/apt/sources.list \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install -y --no-install-recommends iw iproute2 \
    && rm -rf /var/lib/apt/lists/* /var/log/* /var/cache/ldconfig/aux-cache /var/cache/debconf/*-old /var/lib/dpkg/*-old
COPY --from=deps /venv /venv
# Read-only root filesystem in the cluster, so no .pyc files.
ENV VIRTUAL_ENV=/venv PATH=/venv/bin:$PATH PYTHONPATH=/code PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /code
COPY overwatch/ /code/overwatch/

# Not root: BlueZ's D-Bus policy lets any user scan. It must be a uid the
# host knows, though: the system bus drops a connection from one with no
# passwd entry (65532 got "connection reset"), so this is nobody:nogroup.
# The Wi-Fi watch runs as root with only NET_ADMIN and NET_RAW (its DaemonSet).
USER 65534:65534
EXPOSE 8080
ENTRYPOINT ["python", "-m", "overwatch"]
