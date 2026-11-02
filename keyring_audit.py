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


KEY_LIFECYCLE_EVENTS = frozenset({
    "DISPATCH_KEYRING_INITIALIZED",
    "DISPATCH_KEYRING_LOADED",
    "DISPATCH_KEY_REGISTERED",
    "DISPATCH_KEY_ACTIVATED",
    "DISPATCH_KEY_REVOKED",
    "DISPATCH_KEY_REPLACED",
})
MAX_AUDIT_VIEW_BYTES = 32 * 1024 * 1024
MAX_AUDIT_VIEW_LIMIT = 200


def _safe_key_event(entry: dict) -> dict | None:
    """Allowlist lifecycle fields; never expose arbitrary audit payloads or fingerprints."""
    event = entry.get("event")
    data = entry.get("data")
    if event not in KEY_LIFECYCLE_EVENTS or not isinstance(data, dict):
        return None
    component = data.get("component")
    if component not in {"gateway", "provider"}:
        return None
    safe = {
        "timestamp": entry.get("timestamp"),
        "event": event,
        "component": component,
    }
    if event in {"DISPATCH_KEYRING_INITIALIZED", "DISPATCH_KEYRING_LOADED"}:
        key_ids = data.get("key_ids")
        if isinstance(key_ids, list) and all(
            isinstance(key_id, str) and _KEY_ID_RE.fullmatch(key_id) for key_id in key_ids
        ):
            safe["key_ids"] = sorted(set(key_ids))
        active = data.get("active_key_id")
        if isinstance(active, str) and _KEY_ID_RE.fullmatch(active):
            safe["active_key_id"] = active
    elif event == "DISPATCH_KEY_ACTIVATED":
        for field in ("previous_active_key_id", "active_key_id"):
            value = data.get(field)
            if value is None or (isinstance(value, str) and _KEY_ID_RE.fullmatch(value)):
                safe[field] = value
    else:
        key_id = data.get("key_id")
        if not isinstance(key_id, str) or not _KEY_ID_RE.fullmatch(key_id):
            return None
        safe["key_id"] = key_id
        if event == "DISPATCH_KEY_REVOKED" and data.get("reason") == "removed_from_configured_key_ring":
            safe["reason"] = "removed_from_configured_key_ring"
        if event == "DISPATCH_KEY_REPLACED":
            safe["same_id_material_changed"] = data.get("same_id_material_changed") is True
    return safe


def read_keyring_observability(
    db_path: str | Path,
    audit_path: str | Path,
    component: str,
    *,
    event_filter: str | None = None,
    limit: int = 100,
) -> dict:
    """Read a sanitized key-ring snapshot and verified lifecycle events without mutating state."""
    if component not in {"gateway", "provider"}:
        raise ValueError("Unknown key-ring component.")
    if event_filter is not None and event_filter not in KEY_LIFECYCLE_EVENTS:
        raise ValueError("Unsupported key lifecycle event filter.")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_AUDIT_VIEW_LIMIT:
        raise ValueError(f"Audit event limit must be between 1 and {MAX_AUDIT_VIEW_LIMIT}.")

    active_key_id = None
    accepted_key_ids: list[str] = []
    tracked = False
    database = Path(db_path)
    if database.is_file():
        try:
            uri = "file:" + database.resolve().as_posix() + "?mode=ro"
            with sqlite3.connect(uri, uri=True, timeout=2) as conn:
                rows = conn.execute(
                    "SELECT key_id, is_active FROM dispatch_keyring_state WHERE component=? ORDER BY key_id",
                    (component,),
                ).fetchall()
            tracked = True
            accepted_key_ids = [row[0] for row in rows]
            active = [row[0] for row in rows if row[1] == 1]
            active_key_id = active[0] if len(active) == 1 else None
        except sqlite3.OperationalError as exc:
            if "no such table" not in str(exc).lower() and "unable to open database file" not in str(exc).lower():
                raise

    audit_file = Path(audit_path)
    integrity = "missing"
    event_count = 0
    filtered_events: list[dict] = []
    key_history: dict[str, str] = {}
    if audit_file.is_file():
        if audit_file.stat().st_size > MAX_AUDIT_VIEW_BYTES:
            integrity = "too_large"
        else:
            previous_hash = "GENESIS"
            valid = True
            try:
                with audit_file.open("r", encoding="utf-8") as handle:
                    for line in handle:
                        if not line.strip():
                            continue
                        entry = json.loads(line)
                        if not isinstance(entry, dict):
                            valid = False
                            break
                        stored_hash = entry.get("entry_hash")
                        if not isinstance(stored_hash, str) or entry.get("previous_hash") != previous_hash:
                            valid = False
                            break
                        unsigned = dict(entry)
                        del unsigned["entry_hash"]
                        calculated = hashlib.sha256(AuditLog._canonical(unsigned)).hexdigest()
                        if not hmac.compare_digest(calculated, stored_hash):
                            valid = False
                            break
                        previous_hash = stored_hash
                        safe = _safe_key_event(entry)
                        if safe is None or safe["component"] != component:
                            continue
                        event_count += 1
                        event_name = safe["event"]
                        if event_name == "DISPATCH_KEYRING_INITIALIZED":
                            for key_id in safe.get("key_ids", []):
                                key_history[key_id] = "accepted"
                        elif event_name == "DISPATCH_KEY_REGISTERED":
                            key_history[safe["key_id"]] = "accepted"
                        elif event_name == "DISPATCH_KEY_REVOKED":
                            key_history[safe["key_id"]] = "revoked"
                        elif event_name == "DISPATCH_KEY_REPLACED":
                            key_history[safe["key_id"]] = "accepted"
                        if event_filter is None or event_name == event_filter:
                            filtered_events.append(safe)
                integrity = "valid" if valid else "invalid"
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
                integrity = "invalid"
            if integrity != "valid":
                filtered_events = []
                key_history = {}
                event_count = 0

    current = set(accepted_key_ids)
    revoked_key_ids = sorted(
        key_id for key_id, state in key_history.items()
        if state == "revoked" and key_id not in current
    )
    filtered_events = list(reversed(filtered_events[-limit:]))
    return {
        "component": component,
        "status": "tracked" if tracked else "not_tracked",
        "active_key_id": active_key_id,
        "accepted_key_ids": accepted_key_ids,
        "revoked_key_ids": revoked_key_ids,
        "audit_integrity": integrity,
        "event_count": event_count,
        "events": filtered_events,
    }
