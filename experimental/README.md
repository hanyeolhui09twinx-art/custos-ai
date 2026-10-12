# Experimental source snapshots

The v0.4 code and tests supplied for integration are being kept separate from the current root prototype while their completeness is checked.

The intended packaged layout is provided in **custos-v0.4-snapshot.zip** in this directory. It contains the supplied `custos/` modules, tests, project metadata, a red-team report, and an integration-status note.

## Status: incomplete, not runnable

The supplied files import modules that were not included in the uploads: `canonical.py`, `crypto.py`, `models.py`, `access.py`, `control_plane.py`, `audit.py`, `gateway.py`, `workspace.py`, `governance.py`, `bootstrap.py`, and `cli.py`. Therefore, the test suite has **not** been run, and the configured `custos` command cannot resolve yet.

Python syntax checks passed for the supplied modules and end-to-end test. This is not evidence of integration correctness or production security.

The included `red_team_round3_before_fix.txt` is a pre-fix report with unresolved findings; it must not be read as proof that those findings were mitigated.