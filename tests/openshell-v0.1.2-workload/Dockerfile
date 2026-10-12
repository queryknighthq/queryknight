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
# Contents: /bin/sh, /usr/bin/curl, /etc/ssl/certs/ca-certificates.crt,
# /usr/bin/psql (+ /usr/lib/postgresql/<ver>/bin/psql), glibc
# User: nobody (UID 65534) so the workload does not need root.
# Entrypoint: empty; the supervisor-controlled command is whatever is passed to
# `openshell sandbox create -- ...` (e.g. `sleep infinity`).
#
# `postgresql-client` is installed for the OpenShell + QueryKnight + PostgreSQL
# E2E, which drives a real `psql` from inside the sandbox. Note that Debian
# ships `/usr/bin/psql` as a symlink to `/usr/lib/postgresql/<version>/bin/psql`;
# OpenShell matches the kernel-resolved executable path, so the sandbox network
# policy must list `/usr/lib/postgresql/*/bin/psql`.
#
# `python3-psycopg` (psycopg 3) adds a libpq-based client that issues real
# Parse/Bind/Execute parameterized statements, so the E2E can exercise ExactV2
# approval identity (a literal-only Simple Query can only ever be ExactV1).
# `psql` 15 cannot bind parameters and psycopg2 interpolates client-side, hence
# psycopg 3.

FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      curl ca-certificates postgresql-client python3 python3-psycopg \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /home/nobody \
 && chown 65534:65534 /home/nobody

# Parameterized (Parse/Bind/Execute) approval flow used by the ExactV2 phases.
COPY --chown=0:0 qk-approval-flow.py /usr/local/bin/qk-approval-flow.py

USER 65534:65534
WORKDIR /home/nobody
ENTRYPOINT []
CMD ["sleep", "infinity"]