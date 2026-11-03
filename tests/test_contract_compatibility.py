from __future__ import annotations

import copy
import json
import re
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
BASELINE_PATH = ROOT / "contracts" / "compatibility" / "provider-tool-contracts.baseline.v1.0.0.json"
CURRENT_PATH = ROOT / "contracts" / "provider-tool-contracts.v1.0.0.json"
SEMVER_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


def _version(value: Any, label: str) -> tuple[int, int, int]:
    if not isinstance(value, str):
        raise AssertionError(f"{label} must be a semantic version string.")
    match = SEMVER_RE.fullmatch(value)
    if match is None:
        raise AssertionError(f"{label} must use semantic version notation.")
    return tuple(int(part) for part in match.groups())


def _binding_map(document: dict[str, Any]) -> dict[tuple[str, str, str], dict[str, Any]]:
    contracts = document.get("contracts")
    if not isinstance(contracts, list):
        raise AssertionError("Contract catalog must contain a contracts list.")
    result: dict[tuple[str, str, str], dict[str, Any]] = {}
    for entry in contracts:
        if not isinstance(entry, dict):
            raise AssertionError("Every contract entry must be an object.")
        binding = (entry.get("agent_id"), entry.get("action"), entry.get("resource"))
        if not all(isinstance(part, str) for part in binding):
            raise AssertionError("Every contract binding must contain string identifiers.")
        if binding in result:
            raise AssertionError("Contract catalog contains a duplicate binding.")
        result[binding] = entry
    return result


def _contract_shape(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "required_permit_mode": entry.get("required_permit_mode"),
        "input_kind": entry.get("input_kind"),
        "input_schema": entry.get("input_schema"),
        "output_schema": entry.get("output_schema"),
    }


def assert_catalog_compatible(previous: dict[str, Any], current: dict[str, Any]) -> None:
    """Require explicit contract/catalog version movement for structural changes."""
    old_catalog = _version(previous.get("catalog_version"), "Previous catalog version")
    new_catalog = _version(current.get("catalog_version"), "Current catalog version")
    if new_catalog < old_catalog:
        raise AssertionError("Catalog version cannot move backwards.")

    old_bindings = _binding_map(previous)
    new_bindings = _binding_map(current)
    removed = set(old_bindings) - set(new_bindings)
    added = set(new_bindings) - set(old_bindings)
    structural_change = bool(removed or added)

    if removed and new_catalog[0] <= old_catalog[0]:
        raise AssertionError("Removing a registered tool binding requires a catalog major-version bump.")
    if added and new_catalog[:2] <= old_catalog[:2]:
        raise AssertionError("Adding a tool binding requires a catalog minor- or major-version bump.")

    for binding in set(old_bindings) & set(new_bindings):
        old_entry = old_bindings[binding]
        new_entry = new_bindings[binding]
        old_contract = _version(old_entry.get("contract_version"), "Previous contract version")
        new_contract = _version(new_entry.get("contract_version"), "Current contract version")
        if new_contract < old_contract:
            raise AssertionError(f"Contract version cannot move backwards for {binding}.")
        changed = _contract_shape(old_entry) != _contract_shape(new_entry)
        if changed:
            structural_change = True
            if new_contract <= old_contract:
                raise AssertionError(f"Changing a tool contract requires a contract-version bump for {binding}.")
        elif new_contract > old_contract:
            structural_change = True

    if structural_change and new_catalog <= old_catalog:
        raise AssertionError("Any tool-contract change requires a catalog-version bump.")


class ProviderContractCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with BASELINE_PATH.open("r", encoding="utf-8") as handle:
            cls.baseline = json.load(handle)
        with CURRENT_PATH.open("r", encoding="utf-8") as handle:
            cls.current = json.load(handle)

    def test_current_catalog_matches_the_v1_0_0_compatibility_baseline(self) -> None:
        assert_catalog_compatible(self.baseline, self.current)
        self.assertEqual(self.baseline, self.current)

    def test_schema_change_requires_contract_and_catalog_version_bumps(self) -> None:
        changed = copy.deepcopy(self.current)
        entry = changed["contracts"][0]
        entry["input_schema"]["properties"]["query"]["maxLength"] = 120
        with self.assertRaisesRegex(AssertionError, "contract-version bump"):
            assert_catalog_compatible(self.baseline, changed)

        entry["contract_version"] = "2.0.0"
        changed["catalog_version"] = "2.0.0"
        assert_catalog_compatible(self.baseline, changed)

    def test_removing_a_tool_binding_requires_a_major_catalog_bump(self) -> None:
        changed = copy.deepcopy(self.current)
        changed["contracts"].pop()
        changed["catalog_version"] = "1.1.0"
        with self.assertRaisesRegex(AssertionError, "major-version bump"):
            assert_catalog_compatible(self.baseline, changed)

        changed["catalog_version"] = "2.0.0"
        assert_catalog_compatible(self.baseline, changed)

    def test_adding_a_tool_binding_requires_a_minor_catalog_bump(self) -> None:
        changed = copy.deepcopy(self.current)
        added = copy.deepcopy(changed["contracts"][0])
        added["agent_id"] = "archive_agent"
        added["action"] = "read_archive"
        added["resource"] = "archive_db"
        changed["contracts"].append(added)
        with self.assertRaisesRegex(AssertionError, "minor- or major-version bump"):
            assert_catalog_compatible(self.baseline, changed)

        changed["catalog_version"] = "1.1.0"
        assert_catalog_compatible(self.baseline, changed)

    def test_catalog_and_contract_versions_cannot_be_downgraded(self) -> None:
        changed = copy.deepcopy(self.current)
        changed["catalog_version"] = "0.9.0"
        with self.assertRaisesRegex(AssertionError, "move backwards"):
            assert_catalog_compatible(self.baseline, changed)

        changed = copy.deepcopy(self.current)
        changed["contracts"][0]["contract_version"] = "0.9.0"
        with self.assertRaisesRegex(AssertionError, "move backwards"):
            assert_catalog_compatible(self.baseline, changed)


if __name__ == "__main__":
    unittest.main()
