"""Capability taxonomy.

Capabilities are observations about what code *can* do, not verdicts.
A capability on its own is never a malicious finding; only combinations
and data flows raise severity.
"""

from __future__ import annotations

READ_FILE = "READ_FILE"
WRITE_FILE = "WRITE_FILE"
READ_ENV = "READ_ENV"
NETWORK_EGRESS = "NETWORK_EGRESS"
SUBPROCESS = "SUBPROCESS"
DYNAMIC_EXEC = "DYNAMIC_EXEC"
READ_ARGV = "READ_ARGV"
DB_ACCESS = "DB_ACCESS"

ALL: tuple[str, ...] = (
    READ_FILE,
    WRITE_FILE,
    READ_ENV,
    NETWORK_EGRESS,
    SUBPROCESS,
    DYNAMIC_EXEC,
    READ_ARGV,
    DB_ACCESS,
)
