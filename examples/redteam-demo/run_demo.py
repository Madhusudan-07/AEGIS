"""One command runs the whole demo: boots both builds, fires the red-team harness,
then cleans up.

    python examples/redteam-demo/run_demo.py

Uses real child processes (not shell background jobs) so shutdown is reliable on Windows
and Unix alike.
"""
from __future__ import annotations

import subprocess
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
PY = sys.executable


def _wait_up(url: str, timeout_s: int = 30) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=1)  # nosec B310 - fixed localhost target
            return True
        except Exception:
            time.sleep(0.5)
    return False


def main() -> int:
    vuln = subprocess.Popen([PY, str(HERE / "vulnerable_app.py")])
    secure = subprocess.Popen([PY, str(HERE / "secure_app.py")])
    try:
        if not (_wait_up("http://127.0.0.1:8000/") and _wait_up("http://127.0.0.1:8001/")):
            print("! servers failed to start")
            return 1
        return subprocess.call([PY, str(HERE / "redteam.py")])
    finally:
        for proc in (vuln, secure):
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())
