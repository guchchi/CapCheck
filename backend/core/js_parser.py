"""Tree-sitter parser wrapper for JavaScript and TypeScript.

Why tree-sitter: a real grammar rather than regex. It survives JSX, TypeScript
generics, decorators and template literals, and it gives us byte-accurate
source spans so evidence line numbers are never guessed.

Cost model: ``Language`` objects are expensive to build and cheap to reuse, so
they are cached. ``Parser`` objects are single-use here because tree-sitter
parsers are not thread-safe and are cheap to construct.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

import tree_sitter_javascript as _javascript
import tree_sitter_typescript as _typescript
from tree_sitter import Language, Node, Parser, Tree


class UnsupportedGrammar(ValueError):
    """Raised when a caller asks for a grammar CapCheck does not ship."""


@lru_cache(maxsize=None)
def language(grammar: str) -> Language:
    if grammar == "javascript":
        return Language(_javascript.language())
    if grammar == "typescript":
        return Language(_typescript.language_typescript())
    if grammar == "tsx":
        return Language(_typescript.language_tsx())
    raise UnsupportedGrammar(f"unsupported grammar: {grammar}")


@dataclass
class ParsedSource:
    tree: Tree
    source: bytes
    lines: list[str]

    @property
    def has_error(self) -> bool:
        """True when tree-sitter recovered from a syntax error.

        We still analyse recoverable trees; the scan metadata records that the
        file was not perfectly parseable rather than pretending it was.
        """
        return self.tree.root_node.has_error

    def text(self, node: Node | None) -> str:
        if node is None:
            return ""
        return self.source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")

    def line(self, node: Node) -> int:
        return node.start_point[0] + 1

    def end_line(self, node: Node) -> int:
        return node.end_point[0] + 1


def parse(source: str, grammar: str) -> ParsedSource:
    """Parse source text. Never executes anything."""
    parser = Parser(language(grammar))
    data = source.encode("utf-8", errors="replace")
    tree = parser.parse(data)
    return ParsedSource(tree=tree, source=data, lines=source.splitlines())
