from pathlib import Path
import json
import os
import shutil
import subprocess
import urllib.error
import urllib.request


def _runtime_host() -> str:
    return os.environ.get("REPORT_RUNTIME_HOST") or os.environ.get(
        "OATS_HOST", "127.0.0.1"
    )


def _runtime_port() -> int:
    return int(
        os.environ.get("REPORT_RUNTIME_PORT") or os.environ.get("OATS_PORT", "8787")
    )


def _runtime_is_healthy() -> bool:
    url = f"http://{_runtime_host()}:{_runtime_port()}/api/health"
    try:
        with urllib.request.urlopen(url, timeout=1.0) as response:
            payload = json.loads(response.read().decode("utf-8"))
        return (
            payload.get("status") == "ok"
            and payload.get("service") == "report-tool-runtime"
        )
    except (OSError, ValueError, urllib.error.URLError, json.JSONDecodeError):
        return False


def main() -> int:
    project_root = Path(__file__).resolve().parent
    runtime_dir = project_root / "report_runtime"

    if _runtime_is_healthy():
        print(
            f"Report-tool runtime already running at http://{_runtime_host()}:{_runtime_port()}. Reusing existing server."
        )
        return 0

    node_bin = shutil.which("node")
    if not node_bin:
        print(
            "Node.js is required to run the report runtime. Install Node 18+ and retry."
        )
        return 1

    server_script = runtime_dir / "server.js"
    if not server_script.exists():
        print(f"Missing runtime script: {server_script}")
        return 1

    cmd = [node_bin, str(server_script)]
    completed = subprocess.run(cmd, cwd=project_root)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
