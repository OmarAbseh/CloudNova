"""Format parsers: pure text -> structured data.

These never touch the filesystem — the loader reads bytes and hands text in.
Keeping parsers I/O-free means they are unit-testable with string literals and
honour the "only the loader does I/O" invariant.
"""
