#!/usr/bin/env python3
"""Raw TCP echo server for HTTP smuggling differential tests.

Returns the exact bytes received from the proxy as a valid HTTP response,
base64-encoded in the body. This is ground truth: it shows exactly what
Squid forwarded without any HTTP parsing.

Listens on port 8888 by default (override with $ECHO_PORT).
"""
import base64
import os
import socket
import threading

PORT = int(os.environ.get("ECHO_PORT", "8888"))


def handle_client(conn, addr):
    try:
        conn.settimeout(2.0)
        chunks = []
        while True:
            try:
                data = conn.recv(65536)
                if not data:
                    break
                chunks.append(data)
                # Heuristic: if we've seen the end of headers and any expected
                # body, stop reading. For our test vectors this is sufficient.
                joined = b"".join(chunks)
                if b"\r\n\r\n" in joined:
                    # Give a short window for trailing body bytes
                    conn.settimeout(0.3)
            except socket.timeout:
                break

        raw = b"".join(chunks)
        encoded = base64.b64encode(raw).decode("ascii")
        body = (
            f'{{"raw_b64": "{encoded}", '
            f'"raw_len": {len(raw)}, '
            f'"raw_hex": "{raw.hex()}"}}'
        )
        response = (
            f"HTTP/1.1 200 OK\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"{body}"
        )
        conn.sendall(response.encode("ascii"))
    except Exception as e:
        print(f"[echo] error handling {addr}: {e}")
    finally:
        conn.close()


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PORT))
    srv.listen(32)
    print(f"[echo] listening on :{PORT}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
