from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AuditLog:
    """
    Hash-chained local audit log.

    This detects accidental edits and partial tampering in the recorded chain.
    It is not immutable storage: an attacker who can rewrite the entire file can
    recompute the chain. Production deployments need remote/WORM storage and
    independent signing or anchoring.
    """

    def __init__(self, file_path: str = "custos_audit.jsonl") -> None:
        self.file_path = Path(file_path)
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        if not self.verify():
            raise ValueError("Audit log is corrupted; refusing to append.")
        self.previous_hash = self._get_last_hash()

    @staticmethod
    def _canonical(entry: dict[str, Any]) -> bytes:
        return json.dumps(
            entry,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")

    def _get_last_hash(self) -> str:
        if not self.file_path.exists():
            return "GENESIS"

        last_hash = "GENESIS"
        with self.file_path.open("r", encoding="utf-8") as file:
            for line in file:
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    last_hash = entry["entry_hash"]
                except (json.JSONDecodeError, KeyError, TypeError) as exc:
                    raise ValueError("Audit log is corrupted.") from exc
        return last_hash

    def record(self, event: str, data: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(event, str) or not event.strip():
            raise ValueError("event must be a non-empty string.")
        if not isinstance(data, dict):
            raise ValueError("audit data must be a JSON object.")

        with self._lock:
            if not self.verify():
                raise ValueError("Audit log integrity check failed; refusing to append.")
            current_hash = self._get_last_hash()
            if current_hash != self.previous_hash:
                raise ValueError("Audit log changed outside this writer; refusing to append.")

            entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": event,
                "data": data,
                "previous_hash": self.previous_hash,
            }
            entry_hash = hashlib.sha256(self._canonical(entry)).hexdigest()
            entry["entry_hash"] = entry_hash

            with self.file_path.open("a", encoding="utf-8") as file:
                file.write(json.dumps(entry, ensure_ascii=False, sort_keys=True, allow_nan=False) + "\n")
                file.flush()
                os.fsync(file.fileno())

            self.previous_hash = entry_hash
            return entry

    def verify(self) -> bool:
        if not self.file_path.exists():
            return True

        previous_hash = "GENESIS"
        try:
            with self.file_path.open("r", encoding="utf-8") as file:
                for line in file:
                    if not line.strip():
                        continue
                    entry = json.loads(line)
                    if not isinstance(entry, dict):
                        return False
                    stored_hash = entry.get("entry_hash")
                    if not isinstance(stored_hash, str):
                        return False
                    if entry.get("previous_hash") != previous_hash:
                        return False

                    unsigned_entry = dict(entry)
                    del unsigned_entry["entry_hash"]
                    calculated_hash = hashlib.sha256(self._canonical(unsigned_entry)).hexdigest()
                    if not hmac.compare_digest(calculated_hash, stored_hash):
                        return False
                    previous_hash = stored_hash
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            return False
        return True


if __name__ == "__main__":
    log = AuditLog("custos_audit.jsonl")
    log.record(
        "EXAMPLE_EVENT",
        {"agent_id": "research_agent", "action": "read_database"},
    )
    print("Audit log integrity:", log.verify())
