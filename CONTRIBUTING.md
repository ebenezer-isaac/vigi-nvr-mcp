# Contributing

Thanks for your interest in `vigi-nvr-mcp`. This project talks to a device that
locks you out after a few bad logins and that holds your camera footage, so it
holds a high bar for safety and correctness. Please read this before opening a PR.

## Getting set up

```sh
python -m venv .venv && . .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -e '.[dev]'
```

Python 3.11+. `ffmpeg`/`ffprobe` are only needed if you work on the media tools.

## The gate must pass before every commit

```sh
python scripts/gate.py
```

The gate runs, and must print **PASS**, for:

- `ruff` (lint + format check),
- `pytest` with coverage thresholds (**core ≥ 90%**, **package ≥ 80%**),
- the secret scan (`scripts/check_no_secrets.py`),
- a stub scan, and
- `--list-tools` (must succeed and list every expected tool).

All tests run against mocks — **nothing may contact a real device** in CI or in
the test suite.

## No stubs, no secrets

- **No stubs.** The following are forbidden in shipped code: `NotImplementedError`,
  `TODO`/`FIXME`/`XXX`, `pass  # stub`, bare `...` function bodies, tools
  registered without an implementation, and tests marked `skip`/`xfail` without a
  spec citation. If you cannot finish something, say so in the PR rather than
  stubbing it; the stub scan fails the gate.
- **No secrets, no real network data.** Public repo = zero secrets. Use RFC 5737
  documentation addresses (`192.0.2.x`) only — never a real IP, MAC, serial,
  hostname, or site/camera/person name, and never a captured device response.
  The secret scanner gates this; a single documented, non-secret test vector may
  be exempted with a `secret-scan: allow` marker and a justification.

## Tests are for finding faults

Tests exist to break the code, not to rubber-stamp it. For any non-trivial
module, cover the happy path briefly and then spend your effort on edge cases
(boundaries, null/NaN, type coercion, Unicode, whitespace), adversarial inputs
(injection, oversized/deep payloads, malformed device responses, a login page
returned instead of data), and state-machine cases (expired token mid-call,
breaker tripped, writes disabled). If a test fails, fix the code — never relax
the test to make it pass.

## The lockout breaker is sacred

Anything touching authentication must preserve the breaker invariants: never
auto-retry a failed login; one explicit login per call path; admit-and-record is
one atomic step under the cross-process lock; every store failure fails
**closed**. Adversarial changes to auth/breaker code should be accompanied by the
kind of review described in
[docs/specs/04-BREAKER-PROTOCOL.md](docs/specs/04-BREAKER-PROTOCOL.md), and must
keep the conformance suite (`tests/conformance/test_breaker_contract.py`) green.

## The core identity rule

`vigi_nvr_mcp/core/` is a device-agnostic template that is copied **verbatim**
into sibling projects. Do not edit `core/` to fit a one-off NVR need — device
specifics belong in the device modules (`auth.py`, `backend/`, `tools/`), never
in `core/`. When a change to `core/` is genuinely warranted:

1. Edit the canonical files **only here**, in `vigi_nvr_mcp/core/`.
2. Bump `core/VERSION` and regenerate its manifest
   (`python scripts/core_manifest.py`).
3. Keep `tests/test_core_identity.py` and the conformance suite green — they fail
   the gate if a copy drifts.
4. Sync the files verbatim into the sibling repos in a coordinated change.

## Commits and PRs

- Conventional commits: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`,
  `perf:`, `ci:`.
- Keep files roughly 200–400 lines (hard max 800); prefer new, immutable objects
  over mutating inputs; handle errors explicitly; validate at every boundary.
- Open a PR against `main` with a clear summary, the gate output, and a test plan.
- **Never push secrets** and never add a remote that would publish private data.

## Reporting bugs and security issues

File functional bugs as GitHub issues using the bug-report template (it asks for
your model, firmware, and redacted `--check-auth` output). For anything with
security impact, follow [SECURITY.md](SECURITY.md) instead of opening a public
issue.
