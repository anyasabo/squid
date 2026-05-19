# HTTP Smuggling Differential Test Findings

**Date**: 2026-05-19
**Squid Version**: 6.13 (ubuntu/squid Docker image)
**Test Matrix**: 9 vectors × 3 parser modes × 3 backends = 81 test cases

## Summary

| Finding | Severity | Modes Affected |
|---------|----------|----------------|
| obs-fold on Content-Length accepted | **High** | all (relaxed, strict, warn) |
| %00 in URL forwarded unsanitized | **Medium** | relaxed, warn |
| CL+TE: Squid de-chunks (normalizes correctly) | **Info** | all |
| Bare CR replaced with SP (relaxed/warn) | **Info** | relaxed, warn |
| Pipeline correctly separated | **Info** | all |

## Detailed Findings

### 1. obs-fold on Content-Length Accepted (HIGH)

**Vector**: `obs-fold-cl` — Content-Length value on a continuation line:
```
Content-Length:\r\n
 100\r\n
```

**Expected**: Squid rejects with 400 (obs-fold on framing headers is dangerous per RFC 9110 §5.5).

**Actual**: Squid unfolds the continuation line and forwards `Content-Length: 100` as a normal header. This happens in **all three modes** (relaxed, strict, and warn).

**Why it matters**: If Squid accepts obs-folded Content-Length but a downstream backend or CDN does not recognize the folded form, they will disagree on the body length. An attacker could use this to desynchronize message boundaries — the classic request smuggling primitive.

**Raw evidence** (what Squid forwarded to echo-raw):
```
POST /obs-fold-cl HTTP/1.1\r\n
Host: echo-raw:8888\r\n
Content-Length: 100\r\n
Cache-Control: max-age=259200\r\n
Connection: keep-alive\r\n
\r\n
XXXX...  (100 bytes)
```

**Recommendation**: Reject requests with obs-folded Content-Length or Transfer-Encoding headers, regardless of `relaxed_header_parser` setting. This is arguably a bug — even in relaxed mode, framing headers should not be accepted with obs-fold syntax.

### 2. %00 in URL Forwarded Unsanitized (MEDIUM)

**Vector**: `null-byte-url` — `GET /allowed%00/blocked HTTP/1.1`

**Expected**: Squid either rejects the request or strips/escapes the null byte.

**Actual**: Squid forwards the URL with `%00` intact. Backend behavior diverges:
- **echo-raw**: Sees `/allowed%00/blocked` (pass-through)
- **echo-go**: Sees `/allowed%00/blocked` (Go keeps it encoded)
- **nginx**: Rejects with 400 (nginx decodes %00 to NUL and refuses)

**Why it matters**: Backends that decode `%00` to a null byte may truncate the URL at that point, seeing only `/allowed`. If Squid's ACL checks the full path `/allowed%00/blocked` but the backend only sees `/allowed`, an attacker can bypass URL-based access controls.

**Modes affected**: relaxed, warn (strict also forwards %00 — no mode difference for URL parsing).

**Recommendation**: Reject or sanitize `%00` in URLs before forwarding. This is the same class of vulnerability as the `AnyP::Uri::DecodeOrDupe()` null-byte truncation documented in the ACL fail-open tests.

### 3. Dual Content-Length: Conflicting Values Correctly Rejected

**Vector**: `dual-cl-conflict` — two CL headers with different values.

**Result**: Squid correctly rejects with 400 in all modes. ✓

### 4. Dual Content-Length: Identical Values

**Vector**: `dual-cl-identical` — two CL headers with the same value.

**Result**:
- **relaxed/warn**: Squid sanitizes to single CL, forwards. Backends all see CL=5. ✓
- **strict**: Squid rejects with 400. ✓

### 5. CL + Transfer-Encoding: Correct Normalization

**Vector**: `cl-plus-te` — both headers present.

**Result**: Squid uses Transfer-Encoding (chunked), de-chunks the body, strips TE, and forwards with `Content-Length: 5`. All backends see the same normalized request. This is correct proxy behavior per RFC 9112 §6.1.

**Note**: Squid does NOT simply strip CL and forward TE — it fully de-chunks, which eliminates the CL/TE ambiguity entirely. This is better than just stripping CL.

### 6. Bare CR Injection: Handled Safely

**Vector**: `bare-cr-inject` — `X-Test: evil.com\rX-Smuggled: true`

**Result**:
- **relaxed/warn**: Bare CR replaced with SP. Forwarded as single header `X-Test: evil.com X-Smuggled: true`. No header splitting. ✓
- **strict**: Request rejected with 400. ✓

### 7. Space in Method: Correctly Rejected

**Vector**: `space-in-method` — `G ET / HTTP/1.1`

**Result**: Rejected with 400 in all modes. ✓

### 8. Chunk Extension Overflow: Handled Safely

**Vector**: `chunk-ext-overflow` — 4KB chunk extension.

**Result**: Squid correctly parses the chunked body, strips extensions, de-chunks, and forwards with CL=5. All backends see the correct body `hello`. ✓

### 9. Pipeline Kick() Window: Not Triggered

**Vector**: `pipeline-kick` — POST with body + pipelined GET.

**Result**: Squid correctly consumed the POST body (10 bytes) before processing the pipelined GET. The second request was forwarded as a separate backend request. No body/request boundary confusion.

**Note**: The kick() window (client_side.cc:907-918) was not triggered in this test because the POST body was fully available in the initial read. A more sophisticated test would need to split the POST body across TCP segments with precise timing to test the early-response path.

## Test Matrix Summary

| Vector | relaxed | strict | warn |
|--------|---------|--------|------|
| dual-cl-conflict | ✓ reject | ✓ reject | ✓ reject |
| dual-cl-identical | ✓ sanitize | ✓ reject | ✓ sanitize |
| cl-plus-te | ✓ dechunk | ✓ dechunk | ✓ dechunk |
| obs-fold-cl | **⚠ accepted** | **⚠ accepted** | **⚠ accepted** |
| bare-cr-inject | ✓ CR→SP | ✓ reject | ✓ CR→SP |
| null-byte-url | **⚠ forwarded** | **⚠ forwarded** | **⚠ forwarded** |
| space-in-method | ✓ reject | ✓ reject | ✓ reject |
| chunk-ext-overflow | ✓ safe | ✓ safe | ✓ safe |
| pipeline-kick | ✓ safe | ✓ safe | ✓ safe |

## Next Steps

1. **Report obs-fold-cl to Squid**: This should be fixed in all parser modes. File a Bugzilla bug with the reproducer.
2. **Report %00 URL forwarding**: File as a security-sensitive bug, linking to the ACL bypass implications.
3. **Enhance pipeline-kick test**: Use TCP segment splitting (e.g., `socket.send()` with delays) to test the early-response kick() window with partial body delivery.
4. **Add ssl_bump mode**: Test whether HTTPS-intercepted traffic has the same framing behavior.
5. **Add HTTP/2 downgrade vectors**: Test H2→H1.1 translation for smuggling via pseudo-headers.
