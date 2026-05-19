# HTTP Smuggling Differential Test Harness

Sends ambiguous HTTP/1.1 payloads through Squid to multiple backend servers
and compares how each participant interprets the request. Disagreements on
message boundaries, body length, or header semantics indicate potential
HTTP request smuggling vectors.

## Architecture

```
Test Runner (raw TCP) ─→ Squid proxy ─→ echo-raw  (raw TCP, ground truth)
                                      ─→ echo-go   (Go net/http, strict RFC parser)
                                      ─→ nginx      (OpenResty/Lua, production-grade)
```

## Quick start

```bash
# Build and run with default (relaxed) config
cd smuggling/
docker compose up -d --build

# Run the full test matrix (all vectors × all modes × all backends)
python tests/test_smuggling.py

# Run a single vector in strict mode
python tests/test_smuggling.py --vector dual-cl-conflict --mode strict

# Run with pytest (manages compose automatically)
pytest tests/test_smuggling.py -v

# JSON output for scripting
python tests/test_smuggling.py --json > results.json
```

## Test vectors

| # | Name | What it tests |
|---|------|---------------|
| 1 | `dual-cl-conflict` | Two Content-Length headers with conflicting values |
| 2 | `dual-cl-identical` | Two identical Content-Length headers (relaxed: sanitize) |
| 3 | `cl-plus-te` | Content-Length + Transfer-Encoding conflict |
| 4 | `obs-fold-cl` | obs-fold continuation line on Content-Length |
| 5 | `bare-cr-inject` | Bare CR in header value (header splitting) |
| 6 | `null-byte-url` | Percent-encoded null byte in URL path |
| 7 | `space-in-method` | Space within the HTTP method token |
| 8 | `chunk-ext-overflow` | Very long chunk extension |
| 9 | `pipeline-kick` | POST + pipelined GET (kick() window test) |

## Squid parser modes

Each vector is tested under three `relaxed_header_parser` settings:

- **relaxed** (`on`): default production behavior, most permissive
- **strict** (`off`): rejects ambiguous constructs
- **warn** (`warn`): accepts like relaxed but logs warnings

## Backends

- **echo-raw**: Raw TCP server returning base64-encoded bytes (ground truth)
- **echo-go**: Go `net/http` returning parsed request as JSON (strict RFC)
- **nginx**: OpenResty with Lua handler returning parsed request as JSON

## Disagreement detection

The test runner flags when backends disagree on:
- Body length (CL vs TE interpretation)
- Number of requests (pipeline split point)
- Header presence/absence after normalization
- URL interpretation (truncation, encoding)
- Method parsing
