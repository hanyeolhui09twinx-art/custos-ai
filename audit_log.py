from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AuditLog:
    """
    Tamper-evident audit log for Custos AI.

    Each event contains the hash of the previous event.
    If an old entry is modified, the hash chain no longer matches.
    """

    def __init__(self, file_path: str = "custos_audit.jsonl") -> None:
        self.file_path = Path(file_path)
        self.previous_hash = self._get_last_hash()

    def _get_last_hash(self) -> str:
        if not self.file_path.exists():
            return "GENESIS"

        last_line = None

        with self.file_path.open("r", encoding="utf-8") as file:
            for line in file:
                if line.strip():
                    last_line = line.strip()

        if last_line is None:
            return "GENESIS"

        try:
            last_entry = json.loads(last_line)
            return last_entry["entry_hash"]
        except (json.JSONDecodeError, KeyError):
            raise ValueError("Audit log is corrupted.")

    def record(
        self,
        event: str,
        data: dict[str, Any],
    ) -> dict[str, Any]:

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "data": data,
            "previous_hash": self.previous_hash,
        }

        canonical_entry = json.dumps(
            entry,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

        entry_hash = hashlib.sha256(
            canonical_entry.encode("utf-8")
        ).hexdigest()

        entry["entry_hash"] = entry_hash

        with self.file_path.open("a", encoding="utf-8") as file:
            file.write(
                json.dumps(
                    entry,
                    ensure_ascii=False,
                )
                + "\n"
            )

        self.previous_hash = entry_hash

        return entry

    def verify(self) -> bool:
        """
        Verify the entire hash chain.

        Returns False if any entry was changed or the chain is broken.
        """

        if not self.file_path.exists():
            return True

        previous_hash = "GENESIS"

        with self.file_path.open("r", encoding="utf-8") as file:

            for line in file:
                if not line.strip():
                    continue

                entry = json.loads(line)

                stored_hash = entry.get("entry_hash")
                stored_previous_hash = entry.get("previous_hash")

                if stored_previous_hash != previous_hash:
                    return False

                data_without_hash = dict(entry)
                del data_without_hash["entry_hash"]

                canonical_entry = json.dumps(
                    data_without_hash,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                )

                calculated_hash = hashlib.sha256(
                    canonical_entry.encode("utf-8")
                ).hexdigest()

                if calculated_hash != stored_hash:
                    return False

                previous_hash = stored_hash

        return True


if __name__ == "__main__":

    log = AuditLog("custos_audit.jsonl")

    log.record(
        "ACTION_REQUEST",
        {
            "agent_id": "research_agent",
            "action": "read_database",
            "resource": "research_db",
        },
    )

    log.record(
        "DECISION",
        {
            "decision": "ALLOW",
            "reason": "Policy checks passed.",
        },
    )

    log.record(
        "EXECUTION",
        {
            "executed": True,
        },
    )

    print("Audit log created.")
    print("Integrity check:", log.verify())
