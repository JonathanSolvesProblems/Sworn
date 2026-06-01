# SWORN gateway container. Use this when you don't want to install on the
# SIFT VM directly. Mount /cases/ read-only and bring your own Ed25519 keys.
#
# Build:  docker build -t sworn:0.1.0 -f install/Dockerfile .
# Run:    docker run --rm -it \
#           -v /cases:/cases:ro \
#           -v $(pwd)/sworn-keys:/root/.sworn/keys \
#           sworn:0.1.0 gateway --case-id DEMO \
#             --evidence /cases/example/disk.E01

FROM ubuntu:22.04 AS base

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv \
        git curl ca-certificates \
        yara \
        sleuthkit \
        bulk-extractor \
        libregf-utils \
        libewf-utils \
        libvshadow-utils \
        libvslvm-utils \
        libvmdk-utils \
        plaso-tools \
    && rm -rf /var/lib/apt/lists/*

# Volatility 3 from PyPI (gives `vol` on PATH inside the SWORN venv).
# Eric Zimmerman tools, Hayabusa, RegRipper installed by the operator at
# image-build extension time or mounted from the host SIFT VM at run time.

WORKDIR /opt/sworn
COPY . /opt/sworn

RUN python3 -m venv /opt/sworn/venv \
 && /opt/sworn/venv/bin/pip install --upgrade pip wheel \
 && /opt/sworn/venv/bin/pip install -e /opt/sworn \
 && /opt/sworn/venv/bin/pip install volatility3 \
 && ln -s /opt/sworn/venv/bin/sworn /usr/local/bin/sworn \
 && ln -s /opt/sworn/venv/bin/vol /usr/local/bin/vol

# Keys volume.
VOLUME ["/root/.sworn/keys"]

# Evidence is mounted read-only by the operator at run time; the container
# does not bake in any.
VOLUME ["/cases"]

ENTRYPOINT ["sworn"]
CMD ["--help"]
