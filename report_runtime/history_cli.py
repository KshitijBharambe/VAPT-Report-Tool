import json
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from report_runtime import history_store


def _read_stdin_json() -> dict:
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    return json.loads(raw)


def main() -> int:
    try:
        payload = _read_stdin_json()
        action = str(payload.get("action") or "").strip().lower()

        if action == "list":
            result = {"ok": True, "history": history_store.list_entries()}
        elif action == "get":
            result = {
                "ok": True,
                "entry": history_store.get_entry(str(payload.get("id") or "").strip()),
            }
        elif action == "append":
            entry = payload.get("entry")
            if not isinstance(entry, dict):
                result = {"ok": False, "error": "entry is required"}
            else:
                history_store.append_entry(entry)
                result = {"ok": True}
        else:
            result = {"ok": False, "error": f"Unsupported action: {action}"}

        sys.stdout.write(json.dumps(result))
        return 0 if result.get("ok") else 1
    except Exception as exc:  # pragma: no cover - integration boundary
        sys.stdout.write(json.dumps({"ok": False, "error": str(exc)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
