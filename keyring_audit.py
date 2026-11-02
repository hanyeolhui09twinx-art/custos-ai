from __future__ import annotations

import re
import sqlite3
from pathlib import Path

from audit_log import AuditLog

_KEY_ID_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.:-]{0,127}$")
_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")


class KeyRingLifecycle:
    """Persist non-secret key-ring metadata and append lifecycle events to a hash-chained audit log.

    The database stores SHA-256 fingerprints only to detect replacement under an unchanged ID.
    Raw key bytes and fingerprints are never copied into audit events.
    """

    def __init__(self, db_path: str | Path, audit_log: AuditLog, component: str) -> None:
        if not isinstance(component, str) or not _KEY_ID_RE.fullmatch(component):
            raise ValueError("Key-ring component must be a valid identifier.")
        self.db_path = str(db_path)
        self.audit_log = audit_log
        self.component = component
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS dispatch_keyring_state (
                    component TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    is_active INTEGER NOT NULL CHECK(is_active IN (0,1)),
                    PRIMARY KEY(component, key_id)
                )"""
            )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def observe(self, key_fingerprints: dict[str, str], active_key_id: str) -> None:
        if not isinstance(key_fingerprints, dict) or not key_fingerprints:
            raise ValueError("Observed key-ring fingerprints must be a non-empty mapping.")
        if not isinstance(active_key_id, str) or not _KEY_ID_RE.fullmatch(active_key_id):
            raise ValueError("Observed active key ID is invalid.")
        for key_id, fingerprint in key_fingerprints.items():
            if not isinstance(key_id, str) or not _KEY_ID_RE.fullmatch(key_id):
                raise ValueError("Observed key-ring contains an invalid key ID.")
            if not isinstance(fingerprint, str) or not _FINGERPRINT_RE.fullmatch(fingerprint):
                raise ValueError("Observed key fingerprint must be a SHA-256 hexadecimal digest.")
        if active_key_id not in key_fingerprints:
            raise ValueError("Observed active key ID is not present in the key ring.")

        current = dict(key_fingerprints)
        current_ids = set(current)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                "SELECT key_id, fingerprint, is_active FROM dispatch_keyring_state WHERE component=?",
                (self.component,),
            ).fetchall()
            previous = {row["key_id"]: row["fingerprint"] for row in rows}
            previous_active = next((row["key_id"] for row in rows if row["is_active"]), None)
            events: list[tuple[str, dict[str, object]]] = []

            if not previous:
                events.append((
                    "DISPATCH_KEYRING_INITIALIZED",
                    {"component": self.component, "key_ids": sorted(current_ids), "active_key_id": active_key_id},
                ))
            else:
                for key_id in sorted(set(previous) - current_ids):
                    events.append((
                        "DISPATCH_KEY_REVOKED",
                        {"component": self.component, "key_id": key_id, "reason": "removed_from_configured_key_ring"},
                    ))
                for key_id in sorted(current_ids - set(previous)):
                    events.append((
                        "DISPATCH_KEY_REGISTERED",
                        {"component": self.component, "key_id": key_id},
                    ))
                for key_id in sorted(current_ids & set(previous)):
                    if previous[key_id] != current[key_id]:
                        events.append((
                            "DISPATCH_KEY_REPLACED",
                            {"component": self.component, "key_id": key_id, "same_id_material_changed": True},
                        ))
                if previous_active != active_key_id:
                    events.append((
                        "DISPATCH_KEY_ACTIVATED",
                        {"component": self.component, "previous_active_key_id": previous_active, "active_key_id": active_key_id},
                    ))

            events.append((
                "DISPATCH_KEYRING_LOADED",
                {"component": self.component, "key_ids": sorted(current_ids), "active_key_id": active_key_id},
            ))

            try:
                for event_name, event_data in events:
                    self.audit_log.record(event_name, event_data)
                conn.execute("DELETE FROM dispatch_keyring_state WHERE component=?", (self.component,))
                conn.executemany(
                    """INSERT INTO dispatch_keyring_state(component, key_id, fingerprint, is_active)
                       VALUES (?, ?, ?, ?)""",
                    [
                        (self.component, key_id, current[key_id], int(key_id == active_key_id))
                        for key_id in sorted(current_ids)
                    ],
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise
