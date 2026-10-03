"""
Runs the Semantic Decompiler HTTP API on localhost.

    python serve.py [--port 8765]

Interactive API docs: http://127.0.0.1:8765/docs
"""

import argparse

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import uvicorn

from api.app import create_app


def main():
    parser = argparse.ArgumentParser(description="Semantic Decompiler API (localhost)")
    parser.add_argument("--host", default="127.0.0.1", help="interface to bind (default: localhost only)")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    print(f"Semantic Decompiler API on http://{args.host}:{args.port}  (docs: /docs)")
    uvicorn.run(create_app(), host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
