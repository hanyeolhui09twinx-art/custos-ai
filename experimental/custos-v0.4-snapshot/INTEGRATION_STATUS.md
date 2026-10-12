# Integration status

**Status: incomplete; do not treat as runnable or production-ready.**

Required modules absent from the supplied archives:
- `custos/canonical.py`
- `custos/crypto.py`
- `custos/models.py`
- `custos/access.py`
- `custos/control_plane.py`
- `custos/audit.py`
- `custos/gateway.py`
- `custos/workspace.py`
- `custos/governance.py`
- `custos/bootstrap.py`
- `custos/cli.py`

The `pyproject.toml` entry point `custos = "custos.cli:main"` cannot resolve until `custos/cli.py` exists.

Syntax checks passed for the four supplied package files and `tests/test_e2e.py`; integration tests were not executed because required modules are missing.

Security note: `security/red_team_round3_before_fix.txt` records vulnerable findings. It is evidence of reported issues, not mitigation. Production security has not been established.
