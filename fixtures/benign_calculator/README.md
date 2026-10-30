# benign_calculator

Negative control fixture for CapCheck.

An MCP server that only does arithmetic. Expected result: **zero findings and
zero risk score**. If CapCheck reports anything here, the analyser has a false
positive and the false positive is the bug.

This directory exists purely as inert test data. CapCheck parses the source
with `ast` and never imports or executes it.
