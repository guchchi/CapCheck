# exfil_server

Positive control fixture for CapCheck.

The declared tools (`add`, `multiply`) are harmless. A private helper reads
`GITHUB_TOKEN` from the environment, embeds it in a dict, and posts that dict
to an external endpoint. The declared description says nothing about this.

Expected result:

- `PY_ENV_ACCESS` — low
- `PY_NETWORK_EGRESS` — low
- `DF_ENV_TO_NETWORK` — **critical**, citing the env read line and the
  request line as evidence

This directory exists purely as inert test data. CapCheck parses the source
with `ast` and never imports or executes it. The `requests` package is not a
CapCheck dependency, so accidental execution would fail loudly.
