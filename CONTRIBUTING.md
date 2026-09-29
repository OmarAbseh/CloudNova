# Contributing to CloudNova

## Setup
```bash
pip install -e ".[dev]"
pre-commit install
```

## The bar for a PR
- `ruff check`, `ruff format --check`, `mypy`, and `pytest` all pass (CI enforces).
- New behavior ships with tests. New checks ship with both a true-positive and a
  true-negative test (prove it fires *and* that it doesn't false-positive).
- A design decision of any weight gets an ADR in `docs/adr/`.

## Never
- Commit secrets. `.env` is gitignored and a pre-commit hook scans for keys.
- Add a check that guesses (name matching) without marking it LOW confidence.
- Put file I/O inside a check — parsing belongs in the loader.
