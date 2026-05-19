"""HTTP smuggling test vectors as raw byte payloads.

Each vector is a dict with:
  - name: short identifier
  - description: what the vector tests
  - payload: raw bytes to send through the proxy socket
  - check: what to look for in the backend responses
  - backends: which backends to target ("echo-raw", "echo-go", "nginx")

The payloads use absolute-form URIs (http://BACKEND_HOST:PORT/path)
which the test runner substitutes at runtime.
"""

# Placeholder host replaced at runtime by the test runner
HOST = "{BACKEND}"

VECTORS = [
    # 1. Dual Content-Length (conflicting values)
    {
        "name": "dual-cl-conflict",
        "description": "Two Content-Length headers with conflicting values",
        "payload": (
            b"POST http://" + HOST.encode() + b"/dual-cl-conflict HTTP/1.1\r\n"
            b"Host: " + HOST.encode() + b"\r\n"
            b"Content-Length: 1\r\n"
            b"Content-Length: 100\r\n"
            b"\r\n"
            b"X"
        ),
        "check": "squid_should_reject_400",
    },

    # 2. Dual Content-Length (identical values)
    {
        "name": "dual-cl-identical",
        "description": "Two Content-Length headers with identical values (relaxed: sanitize to one)",
        "payload": (
            b"POST http://" + HOST.encode() + b"/dual-cl-identical HTTP/1.1\r\n"
            b"Host: " + HOST.encode() + b"\r\n"
            b"Content-Length: 5\r\n"
            b"Content-Length: 5\r\n"
            b"\r\n"
            b"hello"
        ),
        "check": "backend_sees_single_cl",
    },

    # 3. Content-Length + Transfer-Encoding
    {
        "name": "cl-plus-te",
        "description": "Both CL and TE present; Squid should use TE and strip CL",
        "payload": (
            b"POST http://" + HOST.encode() + b"/cl-te HTTP/1.1\r\n"
            b"Host: " + HOST.encode() + b"\r\n"
            b"Content-Length: 0\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            b"5\r\nhello\r\n0\r\n\r\n"
        ),
        "check": "backend_uses_te_not_cl",
    },

    # 4. obs-fold on Content-Length
    {
        "name": "obs-fold-cl",
        "description": "Content-Length value on continuation line (obs-fold)",
        "payload": (
            b"POST http://" + HOST.encode() + b"/obs-fold-cl HTTP/1.1\r\n"
            b"Host: " + HOST.encode() + b"\r\n"
            b"Content-Length:\r\n"
            b" 100\r\n"
            b"\r\n"
            b"X" * 100
        ),
        "check": "squid_should_reject_400",
    },

    # 5. Bare CR injection
    {
        "name": "bare-cr-inject",
        "description": "Bare CR in header value; relaxed replaces with SP, strict rejects",
        "payload": (
            b"GET http://" + HOST.encode() + b"/bare-cr HTTP/1.1\r\n"
            b"Host: " + HOST.encode() + b"\r\n"
            b"X-Test: evil.com\rX-Smuggled: true\r\n"
            b"\r\n"
        ),
        "check": "cr_handling",
    },

    # 6. Null byte in URL
    {
        "name": "null-byte-url",
        "description": "Percent-encoded null in URL path; may truncate at NUL",
        "payload": (
            b"GET http://" + HOST.encode() + b"/allowed%00/blocked HTTP/1.1\r\n"
            b"Host: " + HOST.encode() + b"\r\n"
            b"\r\n"
        ),
        "check": "url_truncation",
    },

    # 7. Space in method
    {
        "name": "space-in-method",
        "description": "Space within the HTTP method token",
        "payload": (
            b"G ET http://" + HOST.encode() + b"/ HTTP/1.1\r\n"
            b"Host: " + HOST.encode() + b"\r\n"
            b"\r\n"
        ),
        "check": "squid_should_reject_400",
    },

    # 8. Chunk extension overflow
    {
        "name": "chunk-ext-overflow",
        "description": "Very long chunk extension to test parser state",
        "payload": (
            b"POST http://" + HOST.encode() + b"/chunk-ext HTTP/1.1\r\n"
            b"Host: " + HOST.encode() + b"\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            b"5;ext=" + b"A" * 4096 + b"\r\n"
            b"hello\r\n"
            b"0\r\n"
            b"\r\n"
        ),
        "check": "body_integrity",
    },

    # 9. Early response + pipeline (kick() window)
    # This sends a POST followed immediately by a pipelined GET in the same
    # TCP connection. If Squid's kick() fires before the POST body is consumed,
    # the pipelined GET could be executed prematurely.
    {
        "name": "pipeline-kick",
        "description": "POST with body + pipelined GET to test kick() smuggling window",
        "payload": (
            b"POST http://" + HOST.encode() + b"/pipeline-post HTTP/1.1\r\n"
            b"Host: " + HOST.encode() + b"\r\n"
            b"Content-Length: 10\r\n"
            b"\r\n"
            b"0123456789"
            b"GET http://" + HOST.encode() + b"/pipeline-smuggled HTTP/1.1\r\n"
            b"Host: " + HOST.encode() + b"\r\n"
            b"\r\n"
        ),
        "check": "pipeline_split",
    },
]


def get_vector(name: str) -> dict:
    """Look up a vector by name."""
    for v in VECTORS:
        if v["name"] == name:
            return v
    raise KeyError(f"Unknown vector: {name}")


def substitute_host(payload: bytes, backend_host: str) -> bytes:
    """Replace the {BACKEND} placeholder with an actual host:port."""
    return payload.replace(b"{BACKEND}", backend_host.encode())
