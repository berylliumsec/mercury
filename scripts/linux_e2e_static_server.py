#!/usr/bin/env python3
import argparse
import functools
import http.server
import ssl


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--root", required=True)
    parser.add_argument("--certfile")
    parser.add_argument("--keyfile")
    args = parser.parse_args()

    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=args.root)
    server = http.server.ThreadingHTTPServer((args.bind, args.port), handler)

    if args.certfile and args.keyfile:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.certfile, args.keyfile)
        server.socket = context.wrap_socket(server.socket, server_side=True)

    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
