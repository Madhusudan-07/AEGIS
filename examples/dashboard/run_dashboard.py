"""One command: boot the AEGIS dashboard and open it in your browser.

    python examples/dashboard/run_dashboard.py

Then click "Run red-team" and watch every attack get blocked, live. Ctrl+C to stop.
"""
from __future__ import annotations

import subprocess
import sys
import time
import urllib.request
import webbrowser
from pathlib import Path

HERE = Path(__file__).resolve().parent
URL = "http://127.0.0.1:8008/_aegis/"


def _up(url: str) -> bool:
    try:
        urllib.request.urlopen(url, timeout=1)  # nosec B310 - fixed localhost target
        return True
    except Exception:
        return False


def main() -> int:
    srv = subprocess.Popen([sys.executable, str(HERE / "server.py")])
    try:
        for _ in range(60):
            if _up("http://127.0.0.1:8008/_aegis/stats"):
                break
            time.sleep(0.5)
        print(f"AEGIS dashboard: {URL}  (Ctrl+C to stop)")
        webbrowser.open(URL)
        srv.wait()
    except KeyboardInterrupt:
        pass
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=5)
        except Exception:
            srv.kill()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
