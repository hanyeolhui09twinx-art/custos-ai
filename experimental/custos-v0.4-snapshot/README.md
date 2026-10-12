# Custos AI v0.4 source snapshot — not yet runnable

This directory stages the supplied v0.4 package files and tests without modifying the existing root prototype.

## Contents
- `custos/`: supplied `__init__.py`, `client.py`, `mcp.py`, and `server.py`.
- `tests/`: supplied end-to-end and persistence tests.
- `security/red_team_round3_before_fix.txt`: the supplied pre-fix red-team findings.
- `pyproject.toml`: project metadata and the intended CLI entry point.

## Integration status
This is an **incomplete source snapshot**, not an installable release. Several modules imported by the supplied source/tests were absent from the uploaded archives: `canonical.py`, `crypto.py`, `models.py`, `access.py`, `control_plane.py`, `audit.py`, `gateway.py`, `workspace.py`, `governance.py`, `bootstrap.py`, and `cli.py`. As a result, the full test suite was not run and the `custos` command entry point is unresolved.

The included red-team report is explicitly named `before_fix`; its vulnerable findings remain unresolved in this snapshot. Do not treat the report as evidence that the issues are fixed.

## Checks performed
Python syntax checks passed for the supplied package files and end-to-end test. Syntax checks alone do not demonstrate that the modules integrate correctly or that the design is secure.

## Next step
Recover or implement the missing modules, align all interfaces, then run the full test suite and adversarial checks in an isolated environment before considering a merge.
