from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from audit_log import AuditLog
from keyring_audit import KeyRingLifecycle


class KeyRingLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db_path = self.root / "keyring.sqlite3"
        self.audit_path = self.root / "audit.jsonl"
        self.audit = AuditLog(str(self.audit_path))
        self.lifecycle = KeyRingLifecycle(self.db_path, self.audit, component="gateway")
        self.old_key = bytes.fromhex("11" * 32)
        self.new_key = bytes.fromhex("22" * 32)

    @staticmethod
    def fingerprint(key: bytes) -> str:
        return hashlib.sha256(key).hexdigest()

    def events(self) -> list[dict]:
        if not self.audit_path.exists():
            return []
        return [
            json.loads(line)
            for line in self.audit_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def test_initialization_records_key_ids_without_secret_material(self) -> None:
        self.lifecycle.observe({"legacy": self.fingerprint(self.old_key)}, "legacy")
        events = self.events()
        self.assertEqual(events[0]["event"], "DISPATCH_KEYRING_INITIALIZED")
        self.assertEqual(events[0]["data"]["key_ids"], ["legacy"])
        self.assertEqual(events[0]["data"]["active_key_id"], "legacy")
        content = self.audit_path.read_text(encoding="utf-8")
        self.assertNotIn(self.old_key.hex(), content)
        self.assertNotIn(self.fingerprint(self.old_key), content)
        self.assertTrue(self.audit.verify())

    def test_register_activate_and_revoke_are_audited(self) -> None:
        self.lifecycle.observe({"legacy": self.fingerprint(self.old_key)}, "legacy")
        self.lifecycle.observe({
            "legacy": self.fingerprint(self.old_key),
            "v2": self.fingerprint(self.new_key),
        }, "v2")
        self.lifecycle.observe({"v2": self.fingerprint(self.new_key)}, "v2")

        events = self.events()
        names = [entry["event"] for entry in events]
        self.assertIn("DISPATCH_KEY_REGISTERED", names)
        self.assertIn("DISPATCH_KEY_ACTIVATED", names)
        self.assertIn("DISPATCH_KEY_REVOKED", names)
        registered = next(entry for entry in events if entry["event"] == "DISPATCH_KEY_REGISTERED")
        self.assertEqual(registered["data"]["key_id"], "v2")
        activated = next(entry for entry in events if entry["event"] == "DISPATCH_KEY_ACTIVATED")
        self.assertEqual(activated["data"]["previous_active_key_id"], "legacy")
        self.assertEqual(activated["data"]["active_key_id"], "v2")
        revoked = next(entry for entry in events if entry["event"] == "DISPATCH_KEY_REVOKED")
        self.assertEqual(revoked["data"]["key_id"], "legacy")
        self.assertEqual(revoked["data"]["reason"], "removed_from_configured_key_ring")
        self.assertTrue(self.audit.verify())

    def test_replacing_material_without_changing_key_id_is_audited(self) -> None:
        self.lifecycle.observe({"active": self.fingerprint(self.old_key)}, "active")
        self.lifecycle.observe({"active": self.fingerprint(self.new_key)}, "active")
        replacement = next(
            entry for entry in self.events()
            if entry["event"] == "DISPATCH_KEY_REPLACED"
        )
        self.assertEqual(replacement["data"]["key_id"], "active")
        self.assertTrue(replacement["data"]["same_id_material_changed"])

    def test_unchanged_configuration_does_not_create_false_rotation_events(self) -> None:
        configuration = {"active": self.fingerprint(self.old_key)}
        self.lifecycle.observe(configuration, "active")
        self.lifecycle.observe(configuration, "active")
        names = [entry["event"] for entry in self.events()]
        self.assertEqual(names.count("DISPATCH_KEYRING_INITIALIZED"), 1)
        self.assertEqual(names.count("DISPATCH_KEYRING_LOADED"), 2)
        self.assertNotIn("DISPATCH_KEY_REVOKED", names)
        self.assertNotIn("DISPATCH_KEY_REGISTERED", names)

    def test_invalid_active_id_fails_before_audit_or_state_change(self) -> None:
        with self.assertRaises(ValueError):
            self.lifecycle.observe({"legacy": self.fingerprint(self.old_key)}, "missing")
        self.assertEqual(self.events(), [])
        self.lifecycle.observe({"legacy": self.fingerprint(self.old_key)}, "legacy")
        self.assertTrue(self.audit.verify())


if __name__ == "__main__":
    unittest.main()
