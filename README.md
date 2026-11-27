# prune

Find stale development artifacts — abandoned virtualenvs, package caches, `node_modules`,
build output — and remove **only** the ones you explicitly pick.

`prune` is built around one idea: a cleaner should never be able to decide to delete
something on its own. So it separates discovery from destruction.

```
scan   ->  read-only. Writes a plan where every entry is UNSELECTED.
select ->  you toggle individual entries. Nothing is deleted here.
apply  ->  deletes ONLY the selected entries, after revalidating each one,
           and asks for a final confirmation.
```

## Requirements

- Python **3.11** or newer
- No third-party dependencies — standard library only

`prune.py` is a PEP 723 single-file script, so [uv](https://docs.astral.sh/uv/) runs it
with the correct interpreter and no environment setup:

```bash
uv run prune.py --help
```

Any CPython 3.11+ also works: `python prune.py --help`.

## Quick start

```bash
uv run prune.py scan                      # discover, write prune-plan.json
uv run prune.py show                      # read the plan, change nothing
uv run prune.py select --interactive      # pick what goes
uv run prune.py apply                     # delete only what you picked
```

`scan` never selects anything, and `apply` refuses to run with an empty selection.
`scan --json` prints the plan to stdout as JSON — it still writes the plan file.

## Commands

### `scan` — discover

| Flag | Meaning |
| --- | --- |
| `--root PATH` | Root to scan; repeatable. Bounds **every** scanner, including the known cache locations. |
| `--max-depth N` | Traversal depth (default `5`). |
| `--min-age-days N` | Ignore anything newer than N days (default `30`). |
| `--include-risky` | Also list review-policy entries (build output, app payloads, model weights). |
| `--exclude GLOB` | Skip paths matching a glob; repeatable. |
| `--plan PATH` | Plan file to write (default `prune-plan.json`). |
| `--json` | Print the plan to stdout as JSON. The plan file is still written. |

Without `--root` it scans your home directory, the common development folders that
exist inside it (`Desktop`, `Documents`, `Downloads`, `source`, `dev`, `projects`,
`code`), and the known tool caches.

### `select` — choose

| Flag | Meaning |
| --- | --- |
| `--interactive` | Toggle entries one by one. |
| `--select-all` | Select every entry in the plan. |
| `--select-policy LIST` | Select by policy: `cache`, `project`, `review`. |
| `--select-kind LIST` | Select by kind, e.g. `venv,node_modules,package-cache`. |
| `--select-match GLOB` | Select paths matching a glob; repeatable. |
| `--deselect-match GLOB` | Deselect paths matching a glob; repeatable. |
| `--invert` | Flip the current selection. |

### `apply` — delete

| Flag | Meaning |
| --- | --- |
| `--hard` | Delete permanently instead of sending to the recycle bin. |
| `--yes` | Skip the final confirmation prompt. |

Before deleting anything, each entry is revalidated against the filesystem: volume,
inode and modification time. An entry that changed after the scan is **skipped and
reported**, never deleted.

### `show` — inspect

| Flag | Meaning |
| --- | --- |
| `--selected` | Only the entries currently selected. |

## Risk policies

Every candidate is classified into one of three policies, ordered from safest to riskiest:

| Policy | Meaning | Listed by default |
| --- | --- | --- |
| `cache` | Regenerates itself; costs time, never data. | Yes |
| `project` | Project artifact rebuildable from a manifest (`venv`, `node_modules`). | Yes |
| `review` | Build output, application payloads, model weights. May hold something you only have here. | **No** — needs `--include-risky` |

Detected kinds: `venv`, `node_modules`, `package-cache`, `tool-env`,
`build-artifact`, `bytecode-cache`, `temp`.
Detected ecosystems: `python`, `node`, `uv`, `pre-commit`, `dotnet`, `generic`.

Two deliberate filters keep the report honest:

- Bytecode caches smaller than **5 MiB** are not listed — deleting them frees nothing.
- A classified directory is pruned, never descended into, so one tree can never show up
  as several overlapping entries.

## Safety guards

`apply` refuses, per entry, before touching a single byte. It will not delete:

- the user home directory,
- the interpreter running the script (`sys.prefix`, `sys.base_prefix`),
- a drive root or a first-level directory,
- any path that **contains** a protected path,
- a path that no longer exists.

These guards are not configurable and there is no flag to bypass them.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Runtime error, or cancellation |
| `2` | Bad usage |
| `130` | Interrupted (Ctrl-C) |

## The plan file

`prune-plan.json`, schema version `1`. It is a snapshot: paths, sizes, timestamps,
fingerprints and the selection state. Treat it as generated output — never commit it.

## Platform support

| Platform | Recycle bin |
| --- | --- |
| Windows | Real recycle bin via `SHFileOperationW`. |
| Linux | `XDG_DATA_HOME` (or `~/.local/share`) trash, per the freedesktop spec. |
| macOS | **Known limitation**: falls back to the Linux XDG path, not `~/.Trash`. Files are not lost, but they do not appear in Finder. Use `--hard`, or expect them under `~/.local/share/Trash`. |

## Development

```bash
uv run --python 3.11 python -m unittest -v test_prune   # 34 tests, stdlib unittest only
ty check .                                              # type check
ruff check . && ruff format --check .                   # lint and formatting
```

See [AGENTS.md](AGENTS.md) for the repository directives: design invariants, testing
rules, and the conventions this project expects from contributors.

## License

No license file yet. Until one is added, all rights are reserved by the author.
