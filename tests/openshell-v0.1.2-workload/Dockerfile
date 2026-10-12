# SPDX-License-Identifier: Apache-2.0
#
# Test workload image for the OpenShell v0.1.2 sandbox middleware E2E.
#
# This image exists SOLELY to drive `openshell sandbox exec -- curl ...` from
# inside an OpenShell-managed sandbox, exercising the QueryKnight middleware
# through the real OpenShell supervisor/network path. It is not a QueryKnight
# production image, not an OpenShell runtime replacement, and not part of any
# user-facing deployment. Real users bring their own agent workload image.
#
# The supervisor (extracted from the upstream OpenShell supervisor image at
# runtime) is a glibc-linked binary, so the base image must provide glibc.
# debian:bookworm-slim is small, has glibc, and ships curl + ca-certificates.
#
# Contents: /bin/sh, /usr/bin/curl, /etc/ssl/certs/ca-certificates.crt, glibc
# User: nobody (UID 65534) so the workload does not need root.
# Entrypoint: empty; the supervisor-controlled command is whatever is passed to
# `openshell sandbox create -- ...` (e.g. `sleep infinity`).

FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /home/nobody \
 && chown 65534:65534 /home/nobody

USER 65534:65534
WORKDIR /home/nobody
ENTRYPOINT []
CMD ["sleep", "infinity"]
