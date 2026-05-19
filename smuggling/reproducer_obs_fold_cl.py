#!/usr/bin/env python3
"""
Minimal reproducer: Squid accepts obs-fold on Content-Length/Transfer-Encoding

Demonstrates that Squid unfolds and forwards obs-folded framing headers
in all relaxed_header_parser modes, contrary to RFC 9112 §5.1 which
declares such messages malformed.

Usage:
    # Start any Squid instance on port 3128 with a backend on port 80
    python3 reproducer_obs_fold_cl.py [squid_host:port]

    # Or with our Docker test harness:
    cd smuggling/ && docker compose up -d
    python3 reproducer_obs_fold_cl.py

Requirements: Python 3.6+, no external dependencies.
"""

import socket
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1:3128"
# Any HTTP backend that Squid can forward to.
# httpbin.org works for public testing; our echo server for local testing.
BACKEND = "echo-raw:8888"

HOST, PORT = TARGET.rsplit(":", 1)
PORT = int(PORT)


def send(payload: bytes) -> tuple[int, bytes]:
    """Send payload, return (status_code, raw_response)."""
    s = socket.create_connection((HOST, PORT), timeout=10)
    s.settimeout(5)
    s.sendall(payload)
    chunks = []
    while True:
        try:
            d = s.recv(65536)
            if not d:
                break
            chunks.append(d)
        except socket.timeout:
            break
    s.close()
    raw = b"".join(chunks)
    status = 0
    if raw.startswith(b"HTTP/"):
        try:
            status = int(raw.split(b" ", 2)[1])
        except (ValueError, IndexError):
            pass
    return status, raw


# --- Test 1: obs-fold on Content-Length ---
print("Test 1: obs-fold on Content-Length")
status, resp = send(
    b"POST http://" + BACKEND.encode() + b"/test1 HTTP/1.1\r\n"
    b"Host: " + BACKEND.encode() + b"\r\n"
    b"Content-Length:\r\n"
    b" 5\r\n"
    b"\r\n"
    b"hello"
)
if status == 200:
    print(f"  FAIL: Squid accepted obs-fold CL (HTTP {status})")
    print(f"        Expected: 400 (reject malformed framing header)")
elif status == 400:
    print(f"  PASS: Squid rejected obs-fold CL (HTTP {status})")
else:
    print(f"  UNKNOWN: HTTP {status}")

# --- Test 2: obs-fold on Transfer-Encoding ---
print("Test 2: obs-fold on Transfer-Encoding")
status, resp = send(
    b"POST http://" + BACKEND.encode() + b"/test2 HTTP/1.1\r\n"
    b"Host: " + BACKEND.encode() + b"\r\n"
    b"Transfer-Encoding:\r\n"
    b" chunked\r\n"
    b"\r\n"
    b"5\r\nhello\r\n0\r\n\r\n"
)
if status == 200:
    print(f"  FAIL: Squid accepted obs-fold TE (HTTP {status})")
    print(f"        Expected: 400 (reject malformed framing header)")
elif status == 400:
    print(f"  PASS: Squid rejected obs-fold TE (HTTP {status})")
else:
    print(f"  UNKNOWN: HTTP {status}")

# --- Test 3: obs-fold on non-framing header (should be accepted) ---
print("Test 3: obs-fold on non-framing header (control)")
status, resp = send(
    b"GET http://" + BACKEND.encode() + b"/test3 HTTP/1.1\r\n"
    b"Host: " + BACKEND.encode() + b"\r\n"
    b"X-Custom:\r\n"
    b" value\r\n"
    b"\r\n"
)
if status == 200:
    print(f"  OK:   Squid accepted obs-fold on non-framing header (HTTP {status})")
elif status == 400:
    print(f"  NOTE: Squid rejected obs-fold on non-framing header too (HTTP {status})")
else:
    print(f"  UNKNOWN: HTTP {status}")

# --- Test 4: bare CR on CL (should be rejected, tests the other code path) ---
print("Test 4: bare CR on Content-Length (control)")
status, resp = send(
    b"POST http://" + BACKEND.encode() + b"/test4 HTTP/1.1\r\n"
    b"Host: " + BACKEND.encode() + b"\r\n"
    b"Content-Length: \r5\r\n"
    b"\r\n"
    b"hello"
)
if status == 400:
    print(f"  OK:   Squid rejected bare CR on CL (HTTP {status})")
    print(f"        (HttpHeader.cc:590 'hasBareCr' path works)")
else:
    print(f"  NOTE: Squid accepted bare CR on CL (HTTP {status})")

print()
print("If tests 1-2 show FAIL, Squid is vulnerable to HTTP smuggling via")
print("obs-fold on framing headers. See RFC 9112 §5.1.")
