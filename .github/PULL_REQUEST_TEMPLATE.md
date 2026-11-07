# What this changes

<!-- One or two sentences: what changed and why. Link the issue if one exists. -->

## Checklist

Match these against `CONTRIBUTING.md` -- each item is an invariant with a test behind it, not a style preference.

- [ ] `make check` passes locally (lint + full suite + byte-compile + every script's `--help`).
- [ ] **Read-only rule:** no new AWS call that creates, modifies, or deletes state. If an API call was added, its IAM action is in `PERMISSIONS.md`'s policy (`tests/test_permissions.py` checks this).
- [ ] **HTML-escaping contract:** any AWS-sourced string interpolated into a section body or intro goes through `escape_text()` (tables via `findings_table()` are already covered).
- [ ] **Degrade, don't crash:** new collector calls wrap "service not enabled / permission missing" in `@ignore_access_denied` with a `default` matching the return type.
- [ ] Tests cover the layer changed (collector -> `test_collectors_*.py`, `build_report()` -> `test_skill_scripts.py`, argparse/save/JSON -> `test_script_main.py`, `collect()` wiring -> `test_script_collect.py`). A bug fix includes a regression test that fails against the old behaviour.
- [ ] Report prose changes pass the prose lint, and skill/template/reference changes were made together so they don't drift.
- [ ] Reference content asserting AWS facts was verified against current AWS docs and recorded in `SOURCES.md`.
- [ ] `CHANGELOG.md` has an entry under `[Unreleased]`.

## How it was verified

<!-- What you ran beyond the suite: against a real account (which checks), moto only, rendered a report and read it, etc. -->
