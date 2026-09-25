from __future__ import annotations
import os, sys, time, webbrowser, threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent
os.chdir(ROOT)

def main():
    try:
        import uvicorn
    except ImportError:
        print("Dependencies are missing. Run: python -m pip install -r requirements.txt")
        raise SystemExit(1)

    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "8000"))
    url = f"http://{host}:{port}"

    def open_browser():
        time.sleep(1.2)
        try:
            webbrowser.open(url)
        except Exception:
            pass

    print("=" * 64)
    print(" ThreatFlow AI — One-Way Passive Threat Detection v7")
    print("=" * 64)
    print(f" Dashboard: {url}")
    print(" AI/ML hybrid detection: ENABLED Built-in simulation: ENABLED")
    print(" PCAP offline flow reconstruction: ENABLED Threat intelligence: ENABLED")
    print(" Read-only detector: YES")
    print(" Return path: NO")
    print("=" * 64)

    threading.Thread(target=open_browser, daemon=True).start()
    uvicorn.run("backend.main:app", host=host, port=port, log_level="info")

if __name__ == "__main__":
    main()
