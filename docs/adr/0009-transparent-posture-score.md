# 0009 — A transparent posture score, not a black-box model

**Status:** Accepted

## Context
The original thesis surfaced an "AI risk score" from a DecisionTreeClassifier
that — as the rebuild's review proved — had collapsed to a single feature
(`public_access`), so the number was both wrong and unexplainable. A security
tool's headline number must be defensible.

## Decision
Replace it with a documented, deterministic formula (`cloudnova.scoring`): a
weighted sum of findings by severity (critical 40, high 20, medium 8, low 2) plus
a flat penalty per exploitable attack path (25), normalized to 0-100 (higher =
worse) and mapped to an A-F grade. Attack paths score via the penalty only, never
double-counted as their own CRITICAL finding. Every term is returned in a
`breakdown` so the score is fully auditable.

## Consequences
- **+** Explainable: anyone can see why the score is what it is, and reproduce it.
  The exact opposite of the thesis's black box — a strong thing to be able to say.
- **+** Stable and testable; no model file to drift or retrain.
- **+** Weights live in one place and are easy to tune with rationale.
- **−** It is a heuristic, not a probability — presented as a posture indicator,
  not a prediction. That honesty is the point.
- **−** An ML-learned score could capture interactions a linear formula can't;
  that's a deliberate future option, only worth it with real labelled data
  (e.g. from runs against known-vulnerable environments), never synthetic.
