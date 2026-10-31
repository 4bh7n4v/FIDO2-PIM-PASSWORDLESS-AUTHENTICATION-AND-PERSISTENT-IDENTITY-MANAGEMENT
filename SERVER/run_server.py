"""Starts the PIM server:   python run_server.py --host 0.0.0.0 --port 8000"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import uvicorn  # noqa: E402

import settings  # noqa: E402
from app import create_app  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description="FIDO2 PIM Chat server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    arguments = parser.parse_args()
    print("=" * 66)
    print(" FIDO2 PIM Chat - SERVER (identity provider + Policy Engine)")
    print(f" database       : {settings.DATABASE_PATH}")
    print(f" simulated TPMs : {'ALLOWED (demo/testing)' if settings.ALLOW_SIMULATED_TPM else 'refused (real TPMs only)'}")
    print(f" admin view     : http://localhost:{arguments.port}/admin?token={settings.ADMIN_TOKEN}")
    print(" OTP codes      : printed in this window")
    print("=" * 66, flush=True)
    uvicorn.run(create_app(), host=arguments.host, port=arguments.port, log_level="warning")


if __name__ == "__main__":
    main()
