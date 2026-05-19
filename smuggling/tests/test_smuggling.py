#!/usr/bin/env python3
"""HTTP smuggling differential test runner.

Sends crafted HTTP payloads through Squid to multiple backends and compares
how each participant interprets the request. Flags disagreements on message
boundaries, body length, header presence, and request count.

Can run standalone (without pytest) for quick manual testing:
    python test_smuggling.py [--proxy HOST:PORT] [--vector NAME] [--mode relaxed|strict|warn]
"""
import argparse
import base64
import json
import os
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

# Allow imports when run standalone
sys.path.insert(0, os.path.dirname(__file__))
from vectors import VECTORS, substitute_host

PROXY_HOST = os.environ.get("PROXY_HOST", "127.0.0.1")
PROXY_PORT = int(os.environ.get("PROXY_PORT", "3128"))

BACKENDS = {
    "echo-raw": "echo-raw:8888",
    "echo-go": "echo-go:8889",
    "nginx": "nginx:8890",
}

SQUID_CONFIGS = {
    "relaxed": "squid-relaxed.conf",
    "strict": "squid-strict.conf",
    "warn": "squid-warn.conf",
}


@dataclass
class ProxyResponse:
    """Parsed response from Squid."""
    status_code: int = 0
    status_line: str = ""
    headers: dict = field(default_factory=dict)
    body: bytes = b""
    raw: bytes = b""
    error: Optional[str] = None


@dataclass
class BackendInterpretation:
    """What a backend saw (parsed from its JSON echo response)."""
    backend: str = ""
    method: Optional[str] = None
    url: Optional[str] = None
    headers: dict = field(default_factory=dict)
    body: str = ""
    body_len: int = 0
    content_length: Optional[str] = None
    transfer_encoding: Optional[str] = None
    raw_bytes: Optional[bytes] = None
    raw_len: int = 0
    error: Optional[str] = None


@dataclass
class TestResult:
    """Result of one vector against one backend in one mode."""
    vector: str
    mode: str
    backend: str
    proxy_response: ProxyResponse
    backend_interpretation: Optional[BackendInterpretation]
    disagreements: list = field(default_factory=list)
    notes: list = field(default_factory=list)


def send_raw(host: str, port: int, payload: bytes, timeout: float = 5.0) -> list[ProxyResponse]:
    """Send raw bytes to a TCP socket and read the response(s).

    Returns a list because pipelined requests may produce multiple responses.
    """
    results = []
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
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

        raw_all = b"".join(chunks)
        # Split into individual HTTP responses
        for raw_resp in _split_http_responses(raw_all):
            result = ProxyResponse(raw=raw_resp)
            _parse_http_response(result)
            results.append(result)
    except Exception as e:
        results.append(ProxyResponse(error=str(e)))
    if not results:
        results.append(ProxyResponse(error="no response"))
    return results


def _split_http_responses(data: bytes) -> list[bytes]:
    """Split concatenated HTTP responses. Handles Content-Length and chunked."""
    responses = []
    pos = 0
    while pos < len(data):
        if not data[pos:].startswith(b"HTTP/"):
            break

        header_end = data.find(b"\r\n\r\n", pos)
        if header_end < 0:
            responses.append(data[pos:])
            break

        header_block = data[pos:header_end].decode("latin-1", errors="replace")
        body_start = header_end + 4

        # Determine body length
        te_chunked = False
        content_length = None
        for line in header_block.split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                k = k.strip().lower()
                if k == "transfer-encoding" and "chunked" in v.lower():
                    te_chunked = True
                elif k == "content-length":
                    try:
                        content_length = int(v.strip())
                    except ValueError:
                        pass

        if te_chunked:
            # Find end of chunked body: 0\r\n\r\n
            chunk_end = data.find(b"\r\n0\r\n\r\n", body_start)
            if chunk_end >= 0:
                resp_end = chunk_end + 7
            else:
                resp_end = len(data)
        elif content_length is not None:
            resp_end = body_start + content_length
        else:
            # No body indicator -- check if Connection: close or status suggests no body
            status_line = header_block.split("\r\n")[0]
            parts = status_line.split(" ", 2)
            status_code = int(parts[1]) if len(parts) >= 2 else 0
            if status_code in (204, 304) or 100 <= status_code < 200:
                resp_end = body_start
            else:
                # Assume rest is the body
                resp_end = len(data)

        responses.append(data[pos:min(resp_end, len(data))])
        pos = min(resp_end, len(data))

    if not responses and data:
        responses.append(data)
    return responses


def _parse_http_response(resp: ProxyResponse):
    """Parse an HTTP response from raw bytes, handling chunked TE."""
    try:
        header_end = resp.raw.find(b"\r\n\r\n")
        if header_end < 0:
            resp.error = "no header terminator"
            return

        header_block = resp.raw[:header_end].decode("latin-1")
        raw_body = resp.raw[header_end + 4:]

        lines = header_block.split("\r\n")
        resp.status_line = lines[0]
        parts = resp.status_line.split(" ", 2)
        if len(parts) >= 2:
            resp.status_code = int(parts[1])

        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                resp.headers[k.strip().lower()] = v.strip()

        # Decode chunked transfer encoding if present
        if resp.headers.get("transfer-encoding", "").lower() == "chunked":
            resp.body = _decode_chunked(raw_body)
        else:
            resp.body = raw_body
    except Exception as e:
        resp.error = f"parse error: {e}"


def _decode_chunked(data: bytes) -> bytes:
    """Decode a chunked transfer-encoded body."""
    result = b""
    pos = 0
    while pos < len(data):
        crlf = data.find(b"\r\n", pos)
        if crlf < 0:
            break
        size_str = data[pos:crlf].split(b";")[0].strip()
        try:
            chunk_size = int(size_str, 16)
        except ValueError:
            break
        if chunk_size == 0:
            break
        chunk_start = crlf + 2
        chunk_end = chunk_start + chunk_size
        if chunk_end > len(data):
            result += data[chunk_start:]
            break
        result += data[chunk_start:chunk_end]
        pos = chunk_end + 2  # skip trailing CRLF
    return result


def parse_echo_raw(resp: ProxyResponse) -> BackendInterpretation:
    """Parse the raw echo server's JSON response."""
    interp = BackendInterpretation(backend="echo-raw")
    try:
        data = json.loads(resp.body)
        raw = base64.b64decode(data.get("raw_b64", ""))
        interp.raw_bytes = raw
        interp.raw_len = data.get("raw_len", len(raw))

        # Try to parse the forwarded request from raw bytes
        if b"\r\n" in raw:
            req_line = raw.split(b"\r\n", 1)[0].decode("latin-1")
            parts = req_line.split(" ")
            if len(parts) >= 2:
                interp.method = parts[0]
                interp.url = parts[1]

            header_end = raw.find(b"\r\n\r\n")
            if header_end >= 0:
                header_block = raw[len(req_line) + 2:header_end].decode("latin-1")
                for line in header_block.split("\r\n"):
                    if ":" in line:
                        k, v = line.split(":", 1)
                        key = k.strip().lower()
                        interp.headers[key] = v.strip()
                        if key == "content-length":
                            interp.content_length = v.strip()
                        elif key == "transfer-encoding":
                            interp.transfer_encoding = v.strip()
                interp.body = raw[header_end + 4:].decode("latin-1", errors="replace")
                interp.body_len = len(raw[header_end + 4:])
    except Exception as e:
        interp.error = str(e)
    return interp


def parse_echo_go(resp: ProxyResponse) -> BackendInterpretation:
    """Parse the Go echo server's JSON response."""
    interp = BackendInterpretation(backend="echo-go")
    try:
        data = json.loads(resp.body)
        interp.method = data.get("method")
        interp.url = data.get("url")
        interp.headers = {k.lower(): (v[0] if isinstance(v, list) and len(v) == 1 else v)
                          for k, v in data.get("headers", {}).items()}
        interp.body = data.get("body", "")
        interp.body_len = data.get("body_len", 0)
        interp.content_length = str(data["content_length"]) if data.get("content_length") is not None and data["content_length"] >= 0 else None
        te = data.get("transfer_encoding")
        if te:
            interp.transfer_encoding = te[0] if isinstance(te, list) else te
    except Exception as e:
        interp.error = str(e)
    return interp


def parse_nginx(resp: ProxyResponse) -> BackendInterpretation:
    """Parse nginx's Lua echo JSON response."""
    interp = BackendInterpretation(backend="nginx")
    try:
        data = json.loads(resp.body)
        interp.method = data.get("method")
        interp.url = data.get("uri")
        interp.headers = {k.lower(): v for k, v in data.get("headers", {}).items()}
        interp.body = data.get("body", "")
        interp.body_len = data.get("body_len", 0)
        interp.content_length = data.get("content_length")
        interp.transfer_encoding = data.get("transfer_encoding")
    except Exception as e:
        interp.error = str(e)
    return interp


BACKEND_PARSERS = {
    "echo-raw": parse_echo_raw,
    "echo-go": parse_echo_go,
    "nginx": parse_nginx,
}


def detect_disagreements(
    vector: dict,
    proxy_resp: ProxyResponse,
    interpretations: dict[str, BackendInterpretation],
) -> list[str]:
    """Compare backend interpretations and flag disagreements."""
    issues = []
    check = vector["check"]

    # If Squid rejected (4xx), note it
    if proxy_resp.status_code >= 400:
        if check == "squid_should_reject_400":
            return []  # Expected rejection
        if check != "url_truncation":
            # For url_truncation, backend-specific 400s (e.g., nginx rejecting %00)
            # are expected and handled below
            issues.append(f"squid_rejected:{proxy_resp.status_code}")
            return issues

    # If we expected rejection but Squid forwarded, that's a finding
    if check == "squid_should_reject_400":
        issues.append("squid_should_have_rejected_but_forwarded")

    backends = list(interpretations.values())
    valid = [b for b in backends if b.error is None]

    if len(valid) < 2:
        return issues

    # Body length disagreement
    body_lens = {b.backend: b.body_len for b in valid}
    if len(set(body_lens.values())) > 1:
        issues.append(f"body_length_disagree:{body_lens}")

    # URL disagreement
    urls = {b.backend: b.url for b in valid if b.url}
    if len(set(urls.values())) > 1:
        issues.append(f"url_disagree:{urls}")

    # Method disagreement
    methods = {b.backend: b.method for b in valid if b.method}
    if len(set(methods.values())) > 1:
        issues.append(f"method_disagree:{methods}")

    # Content-Length presence/value disagreement
    cls = {b.backend: b.content_length for b in valid}
    cl_vals = {k: v for k, v in cls.items() if v is not None}
    if len(set(cl_vals.values())) > 1:
        issues.append(f"content_length_disagree:{cl_vals}")

    # Transfer-Encoding presence disagreement
    tes = {b.backend: b.transfer_encoding for b in valid}
    te_present = {k for k, v in tes.items() if v}
    te_absent = {k for k, v in tes.items() if not v}
    if te_present and te_absent:
        issues.append(f"transfer_encoding_disagree:{tes}")

    # Check-specific analysis
    if check == "cr_handling":
        for b in valid:
            if "x-smuggled" in b.headers:
                issues.append(f"smuggled_header_visible:{b.backend}:{b.headers.get('x-smuggled')}")
        # Check raw echo for how the bare CR was transformed
        raw_interp = interpretations.get("echo-raw")
        if raw_interp and raw_interp.raw_bytes:
            if b"\rX-Smuggled" in raw_interp.raw_bytes:
                issues.append("bare_cr_forwarded_unsanitized")
            elif b" X-Smuggled" in raw_interp.raw_bytes:
                pass  # CR replaced with SP (safe, expected in relaxed mode)

    if check == "url_truncation":
        # Check if any backend truncated the URL at the null byte
        for b in valid:
            if b.url and "/blocked" not in b.url:
                issues.append(f"url_truncated:{b.backend}:{b.url}")
        # Also flag if Squid forwarded %00 without sanitizing
        raw_interp = interpretations.get("echo-raw")
        if raw_interp and raw_interp.raw_bytes and b"%00" in raw_interp.raw_bytes:
            issues.append("squid_forwarded_null_byte_unsanitized")
        # Flag backend disagreement (some accept, some reject %00 URLs)
        rejected = [b.backend for b in backends if b.error or not b.url]
        accepted = [b.backend for b in valid if b.url]
        if rejected and accepted:
            issues.append(f"null_byte_disagree:accepted={accepted},rejected={rejected}")

    if check == "pipeline_split":
        raw_interp = interpretations.get("echo-raw")
        if raw_interp and raw_interp.raw_bytes:
            raw = raw_interp.raw_bytes
            if b"pipeline-smuggled" in raw:
                issues.append("pipeline_smuggled_request_visible_in_raw")
            if b"GET" in raw and b"POST" in raw:
                issues.append("both_methods_in_single_backend_request")

    if check == "backend_sees_single_cl":
        raw_interp = interpretations.get("echo-raw")
        if raw_interp and raw_interp.raw_bytes:
            cl_count = raw_interp.raw_bytes.lower().count(b"content-length")
            if cl_count > 1:
                issues.append(f"duplicate_cl_forwarded:{cl_count}")

    if check == "backend_uses_te_not_cl":
        # Squid de-chunks and forwards with CL -- this is correct proxy
        # normalization, not a smuggling risk. Only flag if backends disagree
        # with each other on body length (which would indicate the
        # normalization produced inconsistent results).
        pass

    return issues


def run_vector(vector: dict, proxy_host: str, proxy_port: int, backend_name: str, backend_addr: str, mode: str) -> TestResult:
    """Run a single test vector against one backend."""
    payload = substitute_host(vector["payload"], backend_addr)
    responses = send_raw(proxy_host, proxy_port, payload)

    # Use the first response as the primary proxy response
    proxy_resp = responses[0]

    interpretation = None
    if proxy_resp.status_code and proxy_resp.status_code < 400 and proxy_resp.body:
        parser = BACKEND_PARSERS.get(backend_name)
        if parser:
            interpretation = parser(proxy_resp)

    result = TestResult(
        vector=vector["name"],
        mode=mode,
        backend=backend_name,
        proxy_response=proxy_resp,
        backend_interpretation=interpretation,
    )

    # If there are extra responses (pipeline smuggling), note them
    if len(responses) > 1:
        result.notes.append(f"extra_responses:{len(responses) - 1}")
        for i, extra in enumerate(responses[1:], 1):
            result.notes.append(f"  response[{i}]: HTTP {extra.status_code} body_len={len(extra.body) if extra.body else 0}")

    return result


def run_full_matrix(proxy_host: str, proxy_port: int) -> list[TestResult]:
    """Run all vectors against all backends. Assumes the stack is already up."""
    results = []
    for vector in VECTORS:
        for backend_name, backend_addr in BACKENDS.items():
            result = run_vector(vector, proxy_host, proxy_port, backend_name, backend_addr, "current")
            results.append(result)
    return results


def detect_all_disagreements(results: list[TestResult]) -> list[TestResult]:
    """Group results by vector+mode and detect cross-backend disagreements."""
    from collections import defaultdict
    groups = defaultdict(dict)
    for r in results:
        groups[(r.vector, r.mode)][r.backend] = r

    for (vec_name, mode), backend_results in groups.items():
        interpretations = {}
        proxy_resp = None
        vector = None
        for name, r in backend_results.items():
            proxy_resp = r.proxy_response
            vector = next(v for v in VECTORS if v["name"] == vec_name)
            if r.backend_interpretation:
                interpretations[name] = r.backend_interpretation

        if vector and proxy_resp:
            issues = detect_disagreements(vector, proxy_resp, interpretations)
            for name, r in backend_results.items():
                r.disagreements = issues

    return results


def format_results(results: list[TestResult]) -> str:
    """Format results as a human-readable report."""
    lines = []
    lines.append("=" * 80)
    lines.append("HTTP SMUGGLING DIFFERENTIAL TEST RESULTS")
    lines.append("=" * 80)

    seen_vectors = {}
    for r in results:
        key = (r.vector, r.mode)
        if key not in seen_vectors:
            seen_vectors[key] = []
        seen_vectors[key].append(r)

    findings = []
    for (vec_name, mode), group in seen_vectors.items():
        lines.append(f"\n--- {vec_name} (mode={mode}) ---")
        disagreements = group[0].disagreements if group else []

        for r in group:
            status = f"  [{r.backend}]"
            if r.proxy_response.error:
                status += f" ERROR: {r.proxy_response.error}"
            elif r.proxy_response.status_code >= 400:
                status += f" REJECTED: HTTP {r.proxy_response.status_code}"
            elif r.backend_interpretation:
                bi = r.backend_interpretation
                if bi.error:
                    status += f" PARSE_ERROR: {bi.error}"
                else:
                    status += f" method={bi.method} url={bi.url} body_len={bi.body_len}"
                    if bi.content_length:
                        status += f" cl={bi.content_length}"
                    if bi.transfer_encoding:
                        status += f" te={bi.transfer_encoding}"
            else:
                status += f" HTTP {r.proxy_response.status_code} (no backend data)"
            lines.append(status)

        if disagreements:
            lines.append(f"  *** DISAGREEMENTS: {disagreements}")
            findings.append((vec_name, mode, disagreements))

    lines.append("\n" + "=" * 80)
    lines.append(f"SUMMARY: {len(findings)} vectors with disagreements out of {len(seen_vectors)} tested")
    if findings:
        lines.append("\nFINDINGS:")
        for vec, mode, issues in findings:
            for issue in issues:
                lines.append(f"  [{mode}] {vec}: {issue}")
    lines.append("=" * 80)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Pytest integration
# ---------------------------------------------------------------------------

def _mode_from_conf(conf_name: str) -> str:
    """Extract mode name from config filename."""
    return conf_name.replace("squid-", "").replace(".conf", "")


try:
    import pytest

    @pytest.mark.parametrize("vector", VECTORS, ids=[v["name"] for v in VECTORS])
    def test_smuggling_vector(vector, proxy_mode, proxy_addr, backend):
        """Pytest-parametrized test: one vector x one mode x one backend."""
        mode = _mode_from_conf(proxy_mode)
        backend_name, backend_addr = backend
        host, port = proxy_addr

        result = run_vector(vector, host, port, backend_name, backend_addr, mode)

        # For vectors that should be rejected, verify Squid rejects
        if vector["check"] == "squid_should_reject_400":
            if result.proxy_response.status_code < 400 and not result.proxy_response.error:
                pytest.fail(
                    f"[{mode}] {vector['name']} -> {backend_name}: "
                    f"Squid forwarded instead of rejecting "
                    f"(got HTTP {result.proxy_response.status_code})"
                )
            return

        # Collect interpretation for cross-backend comparison
        # (disagreement detection happens in the standalone runner;
        # pytest tests focus on individual vector correctness)
        if result.proxy_response.error:
            result.notes.append(f"connection error: {result.proxy_response.error}")
        elif result.proxy_response.status_code >= 400:
            result.notes.append(f"squid rejected: {result.proxy_response.status_code}")

except ImportError:
    pass


# ---------------------------------------------------------------------------
# Standalone runner
# ---------------------------------------------------------------------------

def _compose(*args, conf="squid-relaxed.conf"):
    compose_dir = os.path.join(os.path.dirname(__file__), "..")
    env = {**os.environ, "SQUID_CONF": conf}
    return subprocess.run(
        ["docker", "compose", *args],
        cwd=compose_dir, env=env,
        capture_output=True, text=True, timeout=300,
    )


def _wait_for_proxy(host, port, timeout=45):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.create_connection((host, port), timeout=2)
            s.close()
            return
        except OSError:
            time.sleep(1)
    raise TimeoutError(f"Proxy {host}:{port} not ready after {timeout}s")


def main():
    parser = argparse.ArgumentParser(description="HTTP smuggling differential tests")
    parser.add_argument("--proxy", default=f"{PROXY_HOST}:{PROXY_PORT}",
                        help="Squid proxy host:port")
    parser.add_argument("--vector", help="Run only this vector (by name)")
    parser.add_argument("--mode", choices=["relaxed", "strict", "warn", "all"], default="all",
                        help="Which Squid parser mode(s) to test")
    parser.add_argument("--no-compose", action="store_true",
                        help="Don't manage Docker Compose (assume stack is running)")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON")
    args = parser.parse_args()

    proxy_host, proxy_port = args.proxy.rsplit(":", 1)
    proxy_port = int(proxy_port)

    modes = list(SQUID_CONFIGS.keys()) if args.mode == "all" else [args.mode]
    vectors = VECTORS
    if args.vector:
        vectors = [v for v in VECTORS if v["name"] == args.vector]
        if not vectors:
            print(f"Unknown vector: {args.vector}", file=sys.stderr)
            print(f"Available: {[v['name'] for v in VECTORS]}", file=sys.stderr)
            sys.exit(1)

    all_results = []

    for mode in modes:
        conf = SQUID_CONFIGS[mode]
        print(f"\n{'='*60}")
        print(f"MODE: {mode} ({conf})")
        print(f"{'='*60}")

        if not args.no_compose:
            print("Starting stack...")
            _compose("down", "--remove-orphans", "--timeout", "5", conf=conf)
            up = _compose("up", "-d", conf=conf)
            if up.returncode != 0:
                print(f"docker compose up failed:\n{up.stderr}", file=sys.stderr)
                continue
            try:
                _wait_for_proxy(proxy_host, proxy_port)
            except TimeoutError as e:
                print(f"Proxy not ready: {e}", file=sys.stderr)
                logs = _compose("logs", conf=conf)
                print(logs.stdout, file=sys.stderr)
                continue
            # Give backends a moment to settle
            time.sleep(2)

        for vector in vectors:
            for backend_name, backend_addr in BACKENDS.items():
                result = run_vector(
                    vector, proxy_host, proxy_port,
                    backend_name, backend_addr, mode,
                )
                all_results.append(result)

        if not args.no_compose:
            _compose("down", "--remove-orphans", "--timeout", "5", conf=conf)

    all_results = detect_all_disagreements(all_results)

    if args.json:
        json_results = []
        for r in all_results:
            entry = {
                "vector": r.vector,
                "mode": r.mode,
                "backend": r.backend,
                "status_code": r.proxy_response.status_code,
                "disagreements": r.disagreements,
                "notes": r.notes,
            }
            if r.proxy_response.error:
                entry["proxy_error"] = r.proxy_response.error
            if r.backend_interpretation:
                bi = r.backend_interpretation
                entry["backend_interpretation"] = {
                    "method": bi.method,
                    "url": bi.url,
                    "body_len": bi.body_len,
                    "content_length": bi.content_length,
                    "transfer_encoding": bi.transfer_encoding,
                    "error": bi.error,
                }
            json_results.append(entry)
        print(json.dumps(json_results, indent=2))
    else:
        print(format_results(all_results))


if __name__ == "__main__":
    main()
