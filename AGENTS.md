# AGENTS.md

Directives for agents working in this repository. This file is the contract: follow
it over your own defaults.

## What this project is

`prune` is a single-file Python tool that finds stale development artifacts
(old virtualenvs, caches, build output) and removes **only** the ones the user
explicitly selects. Two files matter:

- `prune.py` — the tool. PEP 723 inline script metadata, standard library only.
- `test_prune.py` — the suite. Standard library `unittest` only.

## Mandatory: use uv for every Python execution

`uv` is the required runner for this project. Do not use a system interpreter, do
not create a venv by hand, do not `pip install` anything.

```bash
uv run prune.py --help                  # run the tool
uv run prune.py scan --root <path>      # read-only discovery
uv run --python 3.11 python -m unittest -v test_prune   # run the suite
```

Rules that follow from this:

- `prune.py` carries `# requires-python = ">=3.11"` and `dependencies = []`.
  uv honors that header; keep it accurate and keep it first in the file.
- Never introduce a manual `.venv/`, `requirements.txt`, `poetry.lock` or
  `Pipfile`. If a dependency is ever genuinely required, it goes into the PEP 723
  block (`# dependencies = [...]`) and that is a **product decision** to raise,
  not a refactor to slip in.
- If the project ever migrates to a `pyproject.toml`, then `uv.lock` **must** be
  committed. Today there is no `pyproject.toml`, so the script header is the only
  source of truth for interpreter and dependencies.
- If `uv` is unavailable, say so and stop. Do not silently fall back to an
  interpreter you found lying around, and never claim a suite passed when it
  could not run.

## Design invariants — do not weaken these

1. **`scan` is read-only and purely additive.** It can write a plan where every
   entry is unselected; it must never be able to mark one as selected. A bug in a
   scanner must never translate into a deletion.
2. **`apply` revalidates before deleting.** A plan is a snapshot; the filesystem
   moves underneath it. Recheck identity, mtime and every safety guard per entry.
3. **Every filesystem probe swallows `OSError`.** Dead symlinks, junctions,
   permission holes and vanished paths are normal; one of them must never abort a
   scan that already took minutes.
4. **Deletion is reversible by default.** Recycle bin unless `--hard` is passed.
   Never make the destructive path the default.
5. **Safety guards are not configurable.** `unsafe_reason` and `protected_paths`
   refuse the user home, `sys.prefix`, `sys.base_prefix`, drive roots,
   first-level directories, and any target that *contains* a protected path.
   Never add a flag that skips them, never relax one to make a test pass.
6. **Risk policy is ordered and conservative.** `cache` < `project` < `review`
   (`POLICY_ORDER`). `review` entries — build artifacts, application payloads,
   model weights — require `--include-risky`. When a new heuristic is genuinely
   ambiguous, pick the more conservative policy.
7. **Exit codes are a contract.** `0` success, `1` runtime error or cancellation,
   `2` bad usage, `130` interrupted. Do not renumber them.
8. **Bytecode caches below `MIN_BYTECODE_BYTES` (5 MiB) are not listed.** An
   entry that frees nothing is review noise.

## CLI surface

Subcommands: `scan`, `select`, `apply`, `show`.

- `scan`: `--root` (repeatable, bounds **all** scanners including known caches),
  `--max-depth`, `--min-age-days`, `--include-risky`, `--exclude`, `--plan`,
  `--json`.
- `select`: `--interactive`, `--select-all`, `--select-policy`,
  `--select-kind`, `--select-match`, `--deselect-match`, `--invert`.
- `apply`: `--hard`, `--yes`.
- `show`: `--selected`.

The plan file defaults to `prune-plan.json` (`DEFAULT_PLAN_NAME`), schema
`PLAN_VERSION = 1`.

## Code conventions

- **Zero third-party dependencies.** `dependencies = []` is a promise, not an
  accident.
- Keep `from __future__ import annotations` as the first statement after the
  module docstring.
- **Full type hints** on every parameter and return value. `self` and the bare
  `*` keyword-only marker are the only parameters that stay unannotated. Prefer
  the vocabulary already in use: `Path`, `Sequence`, `Iterator`, `Literal`,
  `TypedDict`, dataclasses.
- **Every module, class and function has a docstring.** Functions with more than
  one parameter document an `Args:` section; functions that return something
  meaningful document `Returns:`. Module docstrings state the design constraints,
  because that is where the next reader looks.
- Target 88 columns. The file already contains a handful of longer lines; do not
  add new ones, and do not reformat existing ones as part of an unrelated change.
- **English** for identifiers, comments, docstrings, commit messages and this
  file. **Spanish** for user-facing CLI output, help text and reason strings —
  `configure_stdout()` exists so accents survive a legacy Windows code page.
- Prefer explaining *why* in a comment over restating *what* the code does.

## Testing rules

- Standard library `unittest` only. No pytest, no fixtures plugins, no test
  utilities outside the standard library.
- Run with `uv run --python 3.11 python -m unittest -v test_prune`.
- Every test builds its own tree under `tempfile` via `FixtureCase`. Tests must
  never touch the real filesystem, never assume a path exists, and never depend
  on the machine's installed environments.
- Assert observable effects, not internals. For anything destructive, include the
  test that proves it does **not** delete when it should not: an empty selection,
  an unconfirmed prompt, an entry modified after the scan.
- Anything that can delete needs a guard test (refused) and an action test
  (performed) — one without the other is unverified behavior.
- Platform-specific cases use `@unittest.skipUnless(os.name == "nt", "...")`.
  Prefer junctions (`mklink /J`) over symlinks so no privileges are required.
- Fixture trees must clear the real thresholds: payload above the size filter,
  ages set with `set_age`. A fixture that is too small or too fresh proves nothing
  and passes for the wrong reason.

## Repository hygiene

- `prune-plan.json` is generated output. Never commit it, never treat it as
  source.
- `/Microsoft/` at the repository root is a PowerShell artifact: when
  `powershell.exe` runs without `LOCALAPPDATA`, its module analysis cache resolves
  relative to the working directory. It is ignored, it is regenerable, and it is
  **not** project data — do not "clean" it by deleting anything else.
- Do not commit, push or open a pull request unless the user asks explicitly.

## Workflow for agents

- Never run `apply` against real user paths while developing. Use `scan` and
  `show`, or fixture trees under `tempfile`.
- Verify before claiming. If the suite cannot run, report that as an unavailable
  proof — never present inspection as execution.
- Do not change behavior while "improving" documentation, types or formatting.
  Keep those changes separate and say which one you are making.
- When a change touches the safety guards, the risk policy, the plan schema or
  the exit codes, state that explicitly and get a decision first.
