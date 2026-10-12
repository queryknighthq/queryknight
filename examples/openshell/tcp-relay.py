#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# Test-harness TCP relay for the OpenShell + QueryKnight + PostgreSQL E2E.
#
# The QueryKnight PostgreSQL proxy binds loopback only, by design: it is a
# local, inspected frontend. An OpenShell sandbox is a separate network
# namespace, and the OpenShell compute driver points `host.docker.internal` at
# the gateway's host address (not at the host loopback), so the sandbox cannot
# reach a loopback listener directly.
#
# This relay is the harness-side bridge for that hop. It listens on the host's
# routable address and forwards byte-for-byte to the loopback proxy, so the
# sandbox's only reachable route to PostgreSQL is QueryKnight. It is
# deliberately dumb: no parsing, no inspection, no authorization. It is test
# plumbing, not a QueryKnight deployment component, and it does not exist in
# the product.
#
# The relay is unauthenticated and unencrypted, so bind it only for the
# duration of a test and only on a trusted network.

from __future__ import annotations

import argparse
import asyncio
import signal
import sys

BUFFER = 65536


async def pump(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            chunk = await reader.read(BUFFER)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    except (ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        try:
            writer.close()
        except ConnectionError:
            pass


async def handle(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    target_host: str,
    target_port: int,
) -> None:
    try:
        upstream_reader, upstream_writer = await asyncio.open_connection(target_host, target_port)
    except OSError:
        client_writer.close()
        return
    await asyncio.gather(
        pump(client_reader, upstream_writer),
        pump(upstream_reader, client_writer),
    )


async def serve(listen_host: str, listen_port: int, target_host: str, target_port: int) -> None:
    server = await asyncio.start_server(
        lambda r, w: handle(r, w, target_host, target_port), listen_host, listen_port
    )
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    print(f"tcp-relay {listen_host}:{listen_port} -> {target_host}:{target_port}", flush=True)
    async with server:
        await stop.wait()


def main() -> int:
    parser = argparse.ArgumentParser(description="Transparent TCP relay for the E2E harness.")
    parser.add_argument("--listen-host", required=True)
    parser.add_argument("--listen-port", type=int, required=True)
    parser.add_argument("--target-host", default="127.0.0.1")
    parser.add_argument("--target-port", type=int, required=True)
    args = parser.parse_args()
    try:
        asyncio.run(
            serve(args.listen_host, args.listen_port, args.target_host, args.target_port)
        )
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
