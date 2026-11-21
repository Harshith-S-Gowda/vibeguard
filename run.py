import sys
import webbrowser
import threading
import time
from pathlib import Path

# Ensure both current directory and parent directory are in path
CURRENT_DIR = Path(__file__).resolve().parent
PARENT_DIR = CURRENT_DIR.parent
sys.path.insert(0, str(CURRENT_DIR))
sys.path.insert(0, str(PARENT_DIR))

try:
    from vibeguard.server import run_server
except ImportError:
    from server import run_server

def open_browser(port):
    time.sleep(1.0)
    webbrowser.open(f"http://127.0.0.1:{port}")

if __name__ == "__main__":
    port = 8000
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass

    threading.Thread(target=open_browser, args=(port,), daemon=True).start()
    run_server(port=port)
