---
trigger: always_on
---

# Security Bot Project Invariants & Context Rules

1. Primary Reference Files:
   - Before generating or editing code, always consult `PRD.md`, `ARCHITECTURE.md`, and `RULES.md`.
   - Adhere strictly to the Pydantic models defined in `src/models.py`.

2. Tech Stack & Dependency Boundary:
   - Runtime: Python 3.11+.
   - Permitted packages: `pydantic`, `requests`, `pytest`, `pytest-cov`, `ruff`.
   - Strictly forbidden: Do NOT introduce external databases (PostgreSQL, SQLite, Redis), heavyweight frameworks (FastAPI, Flask, Celery), or third-party AST wrappers (Bandit, Semgrep).

3. Invariant Metrics & Security:
   - Execution time must remain strictly < 4.8s per PR diff.
   - All secret scanning MUST run through `src/config.py::redact_secret` before emitting output.
   - Entropy threshold: Flag strings >= 20 chars with Shannon entropy > 4.5 bits/char.
   - AST SQL rules: Flag dynamic queries (f-strings, concatenation) in DB calls; allow parameterized tuples.
   - OSV queries must exclusively use the batch endpoint `POST /v1/querybatch`.
   - CI Gate: Return sys.exit(1) if CRITICAL or HIGH findings exist; sys.exit(0) otherwise.

4. State Tracking & Deliverables:
   - Never output placeholder code (# TODO, pass). Deliver complete, testable functions with pytest coverage.
   - After completing any task, instruct the user to check off the item in `TRACKER.md` and log key changes into `MEMORY.md`.