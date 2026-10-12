#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# Sandbox-side approval flow for the OpenShell + QueryKnight + PostgreSQL E2E.
#
# QueryKnight binds an approval to the trusted session scope, and the
# PostgreSQL proxy mints one session per frontend connection. A retry after
# approval therefore has to happen on the SAME connection, exactly as an
# interactive client would: the statement fails with "waiting for approval",
# the operator approves, and the client re-issues the statement without
# reconnecting.
#
# Statements are issued with real bound parameters, so they reach QueryKnight
# as Parse/Bind/Execute and produce ExactV2 request identity (SQL plus ordered
# bound values). `psql` 15 cannot bind parameters and psycopg2 interpolates
# client-side, so psycopg 3 is used here.
#
# The password is never an argument: libpq reads it from the file named by
# PGPASSFILE, which the harness writes into the sandbox out of band.
#
# Usage: qk-approval-flow.py <port>
#
# Prints one line per attempt:
#   ATTEMPT1 <result>   exact request, expects an approval block
#   ATTEMPT2 <result>   identical retry after the harness grants the approval
#   ATTEMPT3 <result>   changed bound value, must not reuse the grant

import os
import sys
import time

import psycopg

SQL = "DELETE FROM accounts WHERE id = %s"
GRANT_READY_FILE = "/tmp/qk-approval-ready"
GRANT_WAIT_SECONDS = 120


def primary_message(error: psycopg.Error) -> str:
    detail = ""
    if error.diag is not None:
        detail = error.diag.message_primary or ""
    if not detail:
        text = str(error).strip()
        detail = text.splitlines()[0] if text else "backend error"
    return detail


def attempt(connection: psycopg.Connection, account_id: int) -> str:
    try:
        with connection.cursor() as cursor:
            cursor.execute(SQL, (account_id,))
            return f"DELETED {cursor.rowcount}"
    except psycopg.Error as error:
        return f"ERROR {error.sqlstate or 'unknown'} {primary_message(error)}"


def main() -> int:
    port = int(sys.argv[1])
    conninfo = (
        f"host=host.docker.internal port={port} "
        f"user={os.environ.get('PGUSER', 'qk')} "
        f"dbname={os.environ.get('PGDATABASE', 'qk')} "
        "sslmode=disable"
    )
    with psycopg.connect(conninfo, autocommit=True) as connection:
        print("SESSION_OPEN", flush=True)
        print(f"ATTEMPT1 {attempt(connection, 42)}", flush=True)

        deadline = time.monotonic() + GRANT_WAIT_SECONDS
        while not os.path.exists(GRANT_READY_FILE):
            if time.monotonic() > deadline:
                print("GRANT_TIMEOUT", flush=True)
                return 3
            time.sleep(0.1)

        print(f"ATTEMPT2 {attempt(connection, 42)}", flush=True)
        print(f"ATTEMPT3 {attempt(connection, 43)}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
