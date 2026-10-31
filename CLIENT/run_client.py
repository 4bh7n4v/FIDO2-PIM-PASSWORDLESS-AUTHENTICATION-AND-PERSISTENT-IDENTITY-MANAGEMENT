"""Starts the client agent on this PC.

  Real TPM (Administrator PowerShell):  python run_client.py --server http://192.168.1.10:8000
  Without a TPM (demo / testing):       python run_client.py --server http://localhost:8000 --tpm simulated --tpm-name PC-1 --port 8766
"""
import argparse
import sys
import webbrowser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import uvicorn  # noqa: E402

from client_agent import create_agent_app  # noqa: E402
from tpm_reader import TpmUnavailable, read_real_tpm, read_simulated_tpm  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description="FIDO2 PIM Chat client agent")
    parser.add_argument("--server", default="http://localhost:8000", help="URL of the PIM server")
    parser.add_argument("--port", type=int, default=8765, help="local port of the chat page (8765-8780)")
    parser.add_argument("--tpm", choices=["real", "simulated"], default="real")
    parser.add_argument("--tpm-name", default="PC", help="name of the simulated TPM (simulated mode only)")
    parser.add_argument("--no-browser", action="store_true", help="do not open the browser")
    arguments = parser.parse_args()

    try:
        info = read_real_tpm() if arguments.tpm == "real" else read_simulated_tpm(arguments.tpm_name)
    except TpmUnavailable as error:
        print(f"\nTPM ERROR: {error}\n\nFix the problem above, or try the demo mode with --tpm simulated.")
        sys.exit(1)

    url = f"http://localhost:{arguments.port}"
    print("=" * 66)
    print(" FIDO2 PIM Chat - CLIENT agent")
    print(f" TPM identity : {info['label']}")
    print(f" PIM server   : {arguments.server}")
    print(f" Chat page    : {url}   (use exactly this address, with 'localhost')")
    print("=" * 66, flush=True)
    if not arguments.no_browser:
        webbrowser.open(url)
    uvicorn.run(create_agent_app(arguments.server, info), host="127.0.0.1", port=arguments.port, log_level="warning")


if __name__ == "__main__":
    main()
