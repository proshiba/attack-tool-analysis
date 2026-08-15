#!/usr/bin/env python3
"""Serve one lab fixture directory over TLS on Kali's analysis interface."""

from __future__ import annotations

import argparse
import functools
import http.server
import ssl


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--directory", required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    args = parser.parse_args()

    handler = functools.partial(
        http.server.SimpleHTTPRequestHandler,
        directory=args.directory,
    )
    server = http.server.ThreadingHTTPServer((args.bind, args.port), handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
