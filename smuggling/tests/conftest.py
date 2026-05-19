"""Pytest fixtures for the HTTP smuggling differential test harness.

Manages Docker Compose lifecycle and provides proxy/backend connection details.
"""
import os
import shutil
import socket
import subprocess
import time

import pytest

COMPOSE_DIR = os.path.join(os.path.dirname(__file__), "..")
SQUID_CONFIGS = ["squid-relaxed.conf", "squid-strict.conf", "squid-warn.conf"]
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 3128

BACKENDS = {
    "echo-raw": "echo-raw:8888",
    "echo-go": "echo-go:8889",
    "nginx": "nginx:8890",
}


def _wait_for_port(host, port, timeout=30):
    """Block until a TCP port is accepting connections."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.create_connection((host, port), timeout=2)
            s.close()
            return True
        except OSError:
            time.sleep(0.5)
    raise TimeoutError(f"{host}:{port} not ready after {timeout}s")


def _compose(*args, env=None):
    """Run docker compose in the smuggling directory."""
    cmd = ["docker", "compose", *args]
    merged_env = {**os.environ, **(env or {})}
    return subprocess.run(
        cmd, cwd=COMPOSE_DIR, env=merged_env,
        capture_output=True, text=True, timeout=300,
    )


@pytest.fixture(scope="session")
def compose_build():
    """Build all images once per session."""
    result = _compose("build")
    if result.returncode != 0:
        pytest.skip(f"docker compose build failed:\n{result.stderr}")


@pytest.fixture(params=SQUID_CONFIGS, scope="module")
def proxy_mode(request, compose_build):
    """Start the stack with each Squid config. Yields the config name."""
    conf = request.param
    env = {"SQUID_CONF": conf}

    _compose("down", "--remove-orphans", "--timeout", "5", env=env)
    result = _compose("up", "-d", "--wait", env=env)
    if result.returncode != 0:
        _compose("logs", env=env)
        pytest.skip(f"docker compose up failed for {conf}:\n{result.stderr}")

    try:
        _wait_for_port(PROXY_HOST, PROXY_PORT, timeout=45)
    except TimeoutError:
        logs = _compose("logs", env=env)
        pytest.skip(f"Squid not ready for {conf}:\n{logs.stdout}\n{logs.stderr}")

    yield conf

    _compose("down", "--remove-orphans", "--timeout", "5", env=env)


@pytest.fixture
def proxy_addr():
    """Return (host, port) for the Squid proxy."""
    return (PROXY_HOST, PROXY_PORT)


@pytest.fixture(params=list(BACKENDS.keys()))
def backend(request):
    """Yield backend name and its docker-internal host:port."""
    name = request.param
    return name, BACKENDS[name]
