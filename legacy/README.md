# Legacy prototype (archived)

This directory is the original University of Debrecen thesis version of
CloudNova — a Flask app with three detector functions and a DecisionTree model.
It is preserved for history and is **not maintained**.

Known issues that motivated the rebuild (all fixed in `src/cloudnova/`):
- The ML model collapsed to a single feature (`public_access`); every other
  input was ignored.
- The CloudTrail detector read a flat schema real CloudTrail never emits.
- S3 "public" detection matched the bucket *name*, not its ACL.
- The log analyzer emitted one card per line and never deduplicated by IP.
- Malformed uploads crashed routes with unhandled 500s.
- Upload filenames were not sanitized (arbitrary file write).
- A live API key was committed to the repo (since revoked).

The current engine lives at the repository root under `src/cloudnova/`.
