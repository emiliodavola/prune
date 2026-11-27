#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""prune - find stale development artifacts and remove only the ones you pick.

Lifecycle (nothing is deleted without an explicit selection):

    scan     read-only discovery. Writes a JSON plan where EVERY entry is
             unselected. Never deletes anything.
    select   interactive review. You toggle individual entries on and off.
             Saves your choice into the plan file.
    apply    deletes ONLY the selected entries, after revalidating each one
             against the filesystem and asking for a final confirmation.

Design constraints worth knowing before editing:

* ``scan`` is purely additive: it can never mark an entry as selected, so a
  bug in the scanners cannot turn into a deleted directory.
* ``apply`` re-validates every entry (identity, mtime, safety guards) because
  a plan file is a snapshot and the filesystem moves underneath it.
* Every filesystem probe swallows ``OSError``. Real-world trees contain dead
  symlinks, junctions and permission holes; one of those must not abort a
  scan that already took minutes.
* Deletion goes to the recycle bin by default; ``--hard`` is opt-in.

Exit codes: 0 success, 1 runtime error or cancellation, 2 bad usage, 130
interrupted.
"""

from __future__ import annotations

import argparse
import ctypes
import fnmatch
import json
import os
import shutil
import stat
import sys
import time
from _ctypes import Array
from collections.abc import Iterator, Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, LiteralString, TypedDict
from urllib.parse import quote

PLAN_VERSION: int = 1
DEFAULT_MIN_AGE_DAYS: int = 30
DEFAULT_MAX_DEPTH: int = 5
DEFAULT_PLAN_NAME: str = "prune-plan.json"
MAX_FILES_PER_CANDIDATE: int = 500_000
PAGE_SIZE: int = 20

#: Bytecode caches below this size are noise: a hundred rows hiding a few MB.
#: They are counted in the summary instead of being listed one by one.
MIN_BYTECODE_BYTES: Literal[5242880] = 5 * 1024 * 1024

#: Directories that belong to an installed application, not to a project.
#: Dependency trees found underneath them are application payload: deleting one
#: breaks the application until it is reinstalled, so they never default-select.
APP_DATA_SEGMENTS: frozenset[str] = frozenset(
    {
        ".vscode",
        ".vscode-server",
        ".vscode-insiders",
        ".vscode-oss",
        ".positron",
        ".zed",
        ".cursor",
        ".windsurf",
        ".lmstudio",
        ".ollama",
        ".pi-lens",
        ".pi",
        ".opencode",
        ".cache",
        ".config",
        ".local",
        ".npm",
        ".nuget",
        ".gradle",
        ".m2",
        ".cargo",
    }
)

#: Deletion policy attached to every candidate.
#:
#: * ``cache``   - regenerable by re-downloading. Cheapest to lose.
#: * ``project`` - regenerable by reinstalling dependencies. Costs time, not work.
#: * ``review``  - may hold something produced by hand. Opt-in via ``--include-risky``.
Policy = Literal["cache", "project", "review"]

POLICY_CACHE: Policy = "cache"
POLICY_PROJECT: Policy = "project"
POLICY_REVIEW: Policy = "review"
POLICY_ORDER: tuple[Policy, ...] = (POLICY_CACHE, POLICY_PROJECT, POLICY_REVIEW)

#: A plan entry is a plain JSON object; keys mirror :class:`Candidate`.
PlanEntry = dict[str, Any]


class Fingerprint(TypedDict, total=False):
    """Identity of a filesystem object at scan time.

    Used to refuse deleting something that changed after the scan but before
    the delete: a different object now occupying the same path is exactly the
    case we must not touch.
    """

    dev: int
    ino: int
    mtime: float


# --- path helpers ---------------------------------------------------------


def real_user_home() -> Path:
    """Return the real user profile, ignoring a redirected ``$HOME``.

    Tool harnesses and some shells repoint ``HOME``/``HOMEDRIVE`` at a private
    sandbox. Scanning that sandbox instead of the actual profile silently
    reports nothing to clean, so on Windows the shell API is asked first and
    the environment only serves as a fallback.

    Returns:
        The user's home directory.
    """
    if os.name == "nt":
        try:
            buffer: Array[ctypes.c_wchar] = ctypes.create_unicode_buffer(init=260)
            csidl_profile: int = 40
            code = ctypes.windll.shell32.SHGetFolderPathW(
                None, csidl_profile, None, 0, buffer
            )
            if code == 0 and buffer.value:
                return Path(buffer.value)
        except (AttributeError, OSError):
            pass
        userprofile: str | None = os.environ.get("USERPROFILE")
        if userprofile:
            return Path(userprofile)
    return Path.home()


def norm(path: Path) -> str:
    """Return the path as an absolute, resolved, case-normalized string.

    Comparison in this module always goes through here, so ``C:\\Users\\X`` and
    ``c:/users/x/`` cannot be mistaken for different locations.

    Args:
        path: Path to normalize.

    Returns:
        Normalized string form, safe to compare with ``str.startswith``.
    """
    try:
        resolved: Path = path.resolve(strict=False)
    except OSError:
        resolved: Path = path
    return os.path.normcase(str(resolved))


def is_within(child: Path, parent: Path) -> bool:
    """Report whether ``child`` is ``parent`` or lives under it.

    Args:
        child: Candidate path.
        parent: Candidate ancestor.

    Returns:
        True when ``child`` is the same path as ``parent`` or nested in it.
    """
    child_key, parent_key = norm(path=child), norm(path=parent)
    if child_key == parent_key:
        return True
    return child_key.startswith(parent_key.rstrip(os.sep) + os.sep)


def is_reparse_point(path: Path) -> bool:
    """Report whether a path is a symlink, junction or other reparse point.

    These are never traversed: following one can walk out of the tree the user
    authorized.

    Args:
        path: Path to inspect. Missing paths are not reparse points.

    Returns:
        True for symlinks and Windows reparse points.
    """
    try:
        info: os.stat_result = path.lstat()
    except OSError:
        return False
    if stat.S_ISLNK(info.st_mode):
        return True
    attributes: Any | Literal[0] = getattr(info, "st_file_attributes", 0)
    return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


# Every filesystem probe goes through the three helpers below. A single
# unreadable object (dead symlink, junction to a removed target, WinError 1920)
# must never abort a walk that already ran for minutes.


def path_exists(path: Path) -> bool:
    """Report whether an entry exists, even as a dangling symlink or junction.

    Args:
        path: Path to probe.

    Returns:
        True when ``lstat`` succeeds.
    """
    try:
        os.lstat(path=path)
        return True
    except OSError:
        return False


def file_exists(path: Path) -> bool:
    """Report whether a path resolves to a regular file.

    A dangling link is *not* a file: callers use this to decide whether an
    interpreter is still usable.

    Args:
        path: Path to probe.

    Returns:
        True when ``stat`` succeeds and the target is a regular file.
    """
    try:
        return stat.S_ISREG(os.stat(path=path).st_mode)
    except OSError:
        return False


def dir_exists(path: Path) -> bool:
    """Report whether a path resolves to a directory.

    Args:
        path: Path to probe.

    Returns:
        True when ``stat`` succeeds and the target is a directory.
    """
    try:
        return stat.S_ISDIR(os.stat(path=path).st_mode)
    except OSError:
        return False


def extended_path(path: Path) -> str:
    """Return a Windows extended-length path so deep trees stay deletable.

    Args:
        path: Path that may exceed ``MAX_PATH``.

    Returns:
        The ``\\\\?\\``-prefixed form on Windows, otherwise the plain string.
    """
    text: str = str(object=path)
    if os.name == "nt" and not text.startswith("\\\\?\\"):
        return "\\\\?\\" + text
    return text


# --- formatting -----------------------------------------------------------


def human_bytes(size: float) -> str:
    """Format a byte count for humans.

    Args:
        size: Number of bytes.

    Returns:
        Short string such as ``191.1 MB``.
    """
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            if unit == "B":
                return f"{size:.0f} B"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def human_age(seconds: float) -> str:
    """Format an age for humans using the largest meaningful unit.

    Args:
        seconds: Age in seconds.

    Returns:
        Short string such as ``86d``, ``4m`` or ``2a``.
    """
    days: int = int(max(seconds, 0) // 86400)
    if days >= 365:
        return f"{days // 365}a"
    if days >= 30:
        return f"{days // 30}m"
    return f"{days}d"


# --- candidate model ------------------------------------------------------


@dataclass
class Candidate:
    """A single removable directory discovered by a scanner.

    Attributes:
        path: Absolute path as found on disk.
        ecosystem: Tool family the artifact belongs to (``python``, ``node``, ...).
        kind: Specific artifact type (``venv``, ``node_modules``, ``package-cache``).
        policy: Deletion policy; see :data:`Policy`.
        reason: Human explanation of why this is removable.
        size_bytes: Total bytes occupied by the tree.
        file_count: Number of files inside the tree.
        age_days: Complete days since the newest file inside changed.
        last_modified: ISO timestamp of the newest file inside, or ``""``.
        fingerprint: Identity captured at scan time, used to detect drift.
        selected: Whether the user chose to delete it. Scanners never set it.
    """

    path: str
    ecosystem: str
    kind: str
    policy: Policy
    reason: str
    size_bytes: int
    file_count: int
    age_days: int
    last_modified: str
    fingerprint: Fingerprint
    selected: bool = False

    def label(self) -> str:
        """Return the short ``ecosystem/kind`` form shown in tables."""
        return f"{self.ecosystem}/{self.kind}"


@dataclass
class ScanOptions:
    """Everything that bounds a scan.

    Attributes:
        roots: Directories to walk for project artifacts.
        max_depth: How many levels below each root may be walked.
        min_age_days: Ignore anything touched more recently than this.
        include_risky: Also report ``review`` policy artifacts.
        excludes: Glob patterns for paths to ignore.
        explicit_roots: True when the user passed ``--root``. Every scanner,
            including the known-cache table, is then bounded by those roots so
            nothing outside them can ever appear in a plan.
    """

    roots: list[str]
    max_depth: int = DEFAULT_MAX_DEPTH
    min_age_days: int = DEFAULT_MIN_AGE_DAYS
    include_risky: bool = False
    excludes: list[str] = field(default_factory=list)
    explicit_roots: bool = False


# --- measurement ----------------------------------------------------------


def measure_tree(path: Path) -> tuple[int, int, float]:
    """Measure a tree without following links.

    Reparse points are counted but never traversed, so a junction cannot pull
    unrelated volumes into the measurement. Measurement stops at
    :data:`MAX_FILES_PER_CANDIDATE` so one pathological directory cannot hang
    the whole scan.

    The newest timestamp is derived from files only. A directory's mtime is
    bookkeeping: it changes whenever an entry is added or removed, so counting
    it would make an old tree whose container was freshly created look new.

    Args:
        path: Directory to measure.

    Returns:
        Tuple of ``(total_bytes, file_count, newest_file_mtime)``.
    """
    total: int = 0
    count: int = 0
    newest: float = 0.0
    stack: list[Path] = [path]
    while stack:
        current = stack.pop()
        try:
            entries = os.scandir(path=current)
        except OSError:
            continue
        with entries:
            for entry in entries:
                if count >= MAX_FILES_PER_CANDIDATE:
                    return total, count, newest
                try:
                    info = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if entry.is_dir(follow_symlinks=False) and not is_reparse_point(
                    path=Path(entry.path)
                ):
                    stack.append(Path(entry.path))
                    continue
                newest = max(newest, info.st_mtime)
                total += info.st_size
                count += 1
    return total, count, newest


def fingerprint(path: Path) -> Fingerprint:
    """Capture the identity of a path for later drift detection.

    Args:
        path: Path to fingerprint. A vanished path yields an empty mapping,
            which :func:`revalidate` treats as "no longer deletable".

    Returns:
        Mapping with ``dev``, ``ino`` and ``mtime`` when available.
    """
    try:
        info = path.lstat()
    except OSError:
        return {}
    return {
        "dev": int(getattr(info, "st_dev", 0) or 0),
        "ino": int(getattr(info, "st_ino", 0) or 0),
        "mtime": round(number=info.st_mtime, ndigits=3),
    }


# --- safety guards --------------------------------------------------------


def protected_paths() -> list[Path]:
    """Return paths that must never be deleted nor contained by a target.

    Includes the user profile, this program's directory, the running
    interpreter and its base prefix, plus the Windows system directories.

    Returns:
        Deduplicated list of protected paths.
    """
    candidates: list[Path] = [real_user_home(), Path(__file__).resolve().parent]
    for value in (sys.prefix, sys.base_prefix):
        if value:
            candidates.append(Path(value))
    if os.name == "nt":
        for variable in (
            "SystemRoot",
            "ProgramFiles",
            "ProgramFiles(x86)",
            "ProgramData",
        ):
            setting = os.environ.get(variable)
            if setting:
                candidates.append(Path(setting))
    unique: list[Path] = []
    seen: set[str] = set()
    for path in candidates:
        key: str = norm(path=path)
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique


def unsafe_reason(path: Path) -> str | None:
    """Explain why a path must not be deleted, or confirm that it may be.

    The checks are ordered cheapest-and-most-decisive first: existence,
    reparse points, depth, then containment against every protected path.

    Args:
        path: Target under consideration.

    Returns:
        A human-readable refusal reason, or None when deletion is allowed.
    """
    if not path.is_absolute():
        return "la ruta no es absoluta"
    if not path_exists(path=path):
        return "ya no existe"
    if is_reparse_point(path=path):
        return "es un enlace o junction; no se sigue"

    key: str = norm(path=path)
    parts = [
        part
        for part in Path(key).parts
        if part not in (os.sep, os.altsep, "")
        and not (os.name == "nt" and part.endswith(":\\"))
    ]
    if not parts:
        return "es una raíz de volumen"
    if os.name == "nt" and len(parts) <= 1:
        return "es demasiado superficial (volumen o primer nivel)"

    for guarded in protected_paths():
        guarded_key: str = norm(path=guarded)
        if key == guarded_key:
            return f"es una ruta protegida ({guarded})"
        if guarded_key.startswith(key.rstrip(os.sep) + os.sep):
            return f"contiene una ruta protegida ({guarded})"
    return None


# --- scan: known cache locations -----------------------------------------


@dataclass(frozen=True)
class CacheLocation:
    """A well-known package or model cache that needs no walking to find.

    Attributes:
        path: Cache directory.
        ecosystem: Tool family owning the cache.
        kind: Artifact type reported in the plan.
        policy: Deletion policy; caches are usually ``cache``.
        reason: Human explanation of what the cache holds.
    """

    path: Path
    ecosystem: str
    kind: str
    policy: Policy
    reason: str


def cache_locations() -> list[CacheLocation]:
    """Return the known cache locations for the current platform.

    Only directories that a plain telltale path identifies are listed here;
    anything requiring a walk is handled by :func:`scan_tree` instead.

    Returns:
        Candidate cache directories, whether or not they currently exist.
    """
    home: Path = real_user_home()
    local = os.environ.get("LOCALAPPDATA")
    roaming = os.environ.get("APPDATA")
    local_root = Path(local) if local else home / "AppData" / "Local"
    roaming_root = Path(roaming) if roaming else home / "AppData" / "Roaming"

    found: list[CacheLocation] = []
    if os.name == "nt":
        found += [
            CacheLocation(
                path=local_root / "pip" / "Cache",
                ecosystem="python",
                kind="package-cache",
                policy=POLICY_CACHE,
                reason="wheel y sdists descargados por pip",
            ),
            CacheLocation(
                path=local_root / "uv" / "cache",
                ecosystem="python",
                kind="package-cache",
                policy=POLICY_CACHE,
                reason="caché de paquetes de uv",
            ),
            CacheLocation(
                path=local_root / "npm-cache",
                ecosystem="node",
                kind="package-cache",
                policy=POLICY_CACHE,
                reason="tarballs descargados por npm",
            ),
            CacheLocation(
                path=local_root / "pnpm" / "store",
                ecosystem="node",
                kind="package-cache",
                policy=POLICY_CACHE,
                reason="store global de pnpm",
            ),
            CacheLocation(
                path=local_root / "pnpm-store",
                ecosystem="node",
                kind="package-cache",
                policy=POLICY_CACHE,
                reason="store global de pnpm",
            ),
            CacheLocation(
                path=local_root / "Yarn" / "Cache",
                ecosystem="node",
                kind="package-cache",
                policy=POLICY_CACHE,
                reason="caché de Yarn classic",
            ),
            CacheLocation(
                path=roaming_root / "npm-cache",
                ecosystem="node",
                kind="package-cache",
                policy=POLICY_CACHE,
                reason="caché de npm",
            ),
            CacheLocation(
                path=home / ".cargo" / "registry",
                ecosystem="rust",
                kind="package-cache",
                policy=POLICY_CACHE,
                reason="crates descargados",
            ),
            CacheLocation(
                path=home / ".m2" / "repository",
                ecosystem="java",
                kind="package-cache",
                policy=POLICY_CACHE,
                reason="artefactos Maven",
            ),
            CacheLocation(
                path=home / ".gradle" / "caches",
                ecosystem="java",
                kind="package-cache",
                policy=POLICY_CACHE,
                reason="caché de Gradle",
            ),
            CacheLocation(
                path=home / ".nuget" / "packages",
                ecosystem="dotnet",
                kind="package-cache",
                policy=POLICY_CACHE,
                reason="paquetes NuGet globales",
            ),
            CacheLocation(
                path=home / "go" / "pkg" / "mod" / "cache" / "download",
                ecosystem="go",
                kind="package-cache",
                policy=POLICY_CACHE,
                reason="módulos Go descargados",
            ),
            CacheLocation(
                path=home / ".cache" / "huggingface",
                ecosystem="python",
                kind="model-cache",
                policy=POLICY_REVIEW,
                reason="pesos de modelos; re-descargarlos cuesta mucho",
            ),
            CacheLocation(
                path=local_root / "Temp",
                ecosystem="generic",
                kind="temp",
                policy=POLICY_REVIEW,
                reason="temporales del usuario; pueden tener archivos en uso",
            ),
        ]
    else:
        found += [
            CacheLocation(
                path=home / ".cache" / "pip",
                ecosystem="python",
                kind="package-cache",
                policy=POLICY_CACHE,
                reason="wheel y sdists descargados por pip",
            ),
            CacheLocation(
                path=home / ".cache" / "uv",
                ecosystem="python",
                kind="package-cache",
                policy=POLICY_CACHE,
                reason="caché de paquetes de uv",
            ),
            CacheLocation(
                path=home / ".npm" / "_cacache",
                ecosystem="node",
                kind="package-cache",
                policy=POLICY_CACHE,
                reason="tarballs descargados por npm",
            ),
            CacheLocation(
                path=home / ".cache" / "pnpm",
                ecosystem="node",
                kind="package-cache",
                policy=POLICY_CACHE,
                reason="store global de pnpm",
            ),
            CacheLocation(
                path=home / ".cache" / "yarn",
                ecosystem="node",
                kind="package-cache",
                policy=POLICY_CACHE,
                reason="caché de Yarn",
            ),
            CacheLocation(
                path=home / ".cargo" / "registry",
                ecosystem="rust",
                kind="package-cache",
                policy=POLICY_CACHE,
                reason="crates descargados",
            ),
            CacheLocation(
                path=home / ".m2" / "repository",
                ecosystem="java",
                kind="package-cache",
                policy=POLICY_CACHE,
                reason="artefactos Maven",
            ),
            CacheLocation(
                path=home / ".gradle" / "caches",
                ecosystem="java",
                kind="package-cache",
                policy=POLICY_CACHE,
                reason="caché de Gradle",
            ),
            CacheLocation(
                path=home / ".nuget" / "packages",
                ecosystem="dotnet",
                kind="package-cache",
                policy=POLICY_CACHE,
                reason="paquetes NuGet globales",
            ),
            CacheLocation(
                path=home / "go" / "pkg" / "mod" / "cache" / "download",
                ecosystem="go",
                kind="package-cache",
                policy=POLICY_CACHE,
                reason="módulos Go descargados",
            ),
            CacheLocation(
                path=home / ".cache" / "huggingface",
                ecosystem="python",
                kind="model-cache",
                policy=POLICY_REVIEW,
                reason="pesos de modelos; re-descargarlos cuesta mucho",
            ),
            CacheLocation(
                path=Path("/tmp"),
                ecosystem="generic",
                kind="temp",
                policy=POLICY_REVIEW,
                reason="temporales del sistema",
            ),
        ]
    return found


# --- scan: per-directory classification ----------------------------------

#: Never descended into: big, irrelevant to cleanup, or full of reparse points.
#: ``node_modules`` is absent on purpose: it is classified, and classification prunes it.
SKIP_DIR_NAMES: set[str] = {
    "windows",
    "$recycle.bin",
    "system volume information",
    ".git",
    "appdata",
    "library",
    ".hg",
    ".svn",
}

#: Directories recognizable by name as regenerable caches.
NAME_CACHE_DIRS: dict[str, tuple[str, str]] = {
    "__pycache__": ("python", "bytecode-cache"),
    ".pytest_cache": ("python", "tool-cache"),
    ".mypy_cache": ("python", "tool-cache"),
    ".ruff_cache": ("python", "tool-cache"),
    ".hypothesis": ("python", "tool-cache"),
    ".tox": ("python", "tool-env"),
    ".nox": ("python", "tool-env"),
    ".eggs": ("python", "build-artifact"),
    ".ipynb_checkpoints": ("generic", "editor-cache"),
    ".next": ("node", "build-cache"),
    ".turbo": ("node", "build-cache"),
    ".parcel-cache": ("node", "build-cache"),
    ".nuxt": ("node", "build-cache"),
    ".svelte-kit": ("node", "build-cache"),
}

#: Build outputs that may contain something hand-delivered: review policy.
RISKY_DIR_NAMES: dict[str, str] = {
    "build": "generic",
    "dist": "generic",
    "target": "generic",
}

#: Cache containers found directly under a cache directory. The container is the
#: unit to delete, never the environments unpacked inside it: uv and pre-commit
#: write a ``pyvenv.cfg`` into their extractions, which would otherwise be
#: misreported as project environments.
CACHE_CONTAINER_SEGMENTS: dict[str, tuple[str, str, Policy]] = {
    "uv": ("uv", "package-cache", POLICY_CACHE),
    "pre-commit": ("python", "tool-env", POLICY_CACHE),
    "pypoetry": ("python", "package-cache", POLICY_CACHE),
    "pip": ("python", "package-cache", POLICY_CACHE),
    "pnpm": ("node", "package-cache", POLICY_CACHE),
    "yarn": ("node", "package-cache", POLICY_CACHE),
    "deno": ("deno", "package-cache", POLICY_CACHE),
    "huggingface": ("python", "model-cache", POLICY_REVIEW),
    "torch": ("python", "model-cache", POLICY_REVIEW),
}

#: Directory names that make up a uv cache, in either layout.
UV_CACHE_PREFIXES = (
    "archive-v",
    "builds-v",
    "wheels-v",
    "sdists-v",
    "simple-v",
    "interpreter-v",
)

#: Parent directory names that mark a cache container.
CACHE_PARENT_NAMES = frozenset({".cache", "cache", "caches"})


def read_pyvenv_cfg(path: Path) -> dict[str, str] | None:
    """Parse an environment's ``pyvenv.cfg`` into lowercased keys.

    Args:
        path: Environment directory.

    Returns:
        Parsed key/value pairs, or None when the file cannot be read.
    """
    try:
        text = (path / "pyvenv.cfg").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    data: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            data[key.strip().lower()] = value.strip()
    return data


def venv_has_interpreter(path: Path) -> bool:
    """Report whether an environment has the expected interpreter slot.

    The slot counts even when the link behind it is dead: a broken interpreter
    is the strongest evidence that the environment is useless.

    Args:
        path: Environment directory.

    Returns:
        True when ``Scripts``/``bin`` holds a Python executable entry.
    """
    for dirname in ("Scripts", "bin"):
        directory = path / dirname
        if not dir_exists(path=directory):
            continue
        for executable in ("python.exe", "python"):
            if path_exists(path=directory / executable):
                return True
    return False


def venv_interpreter_alive(path: Path) -> bool:
    """Report whether the environment's own interpreter still resolves.

    Args:
        path: Environment directory.

    Returns:
        True when the interpreter entry points at a real file.
    """
    for dirname in ("Scripts", "bin"):
        directory = path / dirname
        if not dir_exists(path=directory):
            continue
        for executable in ("python.exe", "python"):
            if file_exists(path=directory / executable):
                return True
    return False


def classify_venv(path: Path) -> tuple[str, str, str] | None:
    """Identify a Python environment by its markers, never by its folder name.

    Args:
        path: Directory under consideration.

    Returns:
        ``(ecosystem, kind, reason)`` or None when the directory is not an
        environment.
    """
    if dir_exists(path=path / "conda-meta") and venv_has_interpreter(path=path):
        return ("python", "conda-env", "entorno conda; se recrea con conda env create")
    if not path_exists(path=path / "pyvenv.cfg"):
        return None
    if not venv_has_interpreter(path=path):
        return None
    if not venv_interpreter_alive(path=path):
        return ("python", "venv", "el intérprete del entorno está roto: enlace muerto")
    config: dict[str, str] | None = read_pyvenv_cfg(path=path)
    if config is None:
        return None
    home: str | None = config.get("home")
    if home:
        base: Path = Path(home)
        alive: bool = any(
            file_exists(path=base / executable)
            for executable in ("python.exe", "python")
        )
        if not alive:
            return (
                "python",
                "venv",
                "intérprete base ya no existe: el entorno está muerto",
            )
    return ("python", "venv", "entorno inactivo; se recrea con pip install -r")


def is_app_data_surface(path: Path) -> bool:
    """Report whether a path lives inside an installed application's data.

    Only ancestors between the path and the user profile are inspected, so a
    project stored somewhere else is never mistaken for application payload.

    Args:
        path: Path to test.

    Returns:
        True when any ancestor below the profile is an application directory.
    """
    home_key: str = norm(path=real_user_home())
    prefix = home_key.rstrip(os.sep) + os.sep
    for parent in path.parents:
        key: str = norm(path=parent)
        if key == home_key:
            break
        if not key.startswith(prefix):
            break
        if parent.name.lower() in APP_DATA_SEGMENTS:
            return True
        # A hidden directory sitting directly under the profile is tool state
        # (``~/.vscode``, ``~/.hf-cli``, ``~/.lmstudio``), not a project tree.
        # Projects under a profile are not hidden, so this generalizes without
        # listing every application that exists or will exist.
        if parent.name.startswith(".") and norm(path=parent.parent) == home_key:
            return True
    return False


def is_uv_cache_entry(path: Path) -> bool:
    """Report whether a directory is part of a uv cache.

    uv unpacks environments that carry a ``pyvenv.cfg``, so the shape alone is
    not enough to call them project environments.

    Args:
        path: Directory to test.

    Returns:
        True when the name and one of the two nearest ancestors match a uv cache.
    """
    if not path.name.lower().startswith(UV_CACHE_PREFIXES):
        return False
    return any(parent.name.lower() == "uv" for parent in list(path.parents)[:2])


def classify_dir(path: Path) -> tuple[str, str, Policy, str] | None:
    """Classify a directory as a whole-tree removal candidate.

    Cheapest signals run first, because this is called for every directory the
    walk visits.

    Args:
        path: Directory under consideration.

    Returns:
        ``(ecosystem, kind, policy, reason)`` or None when the directory is
        just a container to descend into.
    """
    name: str = path.name.lower()

    if name == "node_modules":
        if is_app_data_surface(path=path):
            return (
                "node",
                "node_modules",
                POLICY_REVIEW,
                (
                    "dependencias empaquetadas dentro de una aplicación; "
                    "se recuperan reinstalándola"
                ),
            )
        return (
            "node",
            "node_modules",
            POLICY_PROJECT,
            "dependencias Node reinstalables con npm install",
        )

    if name in NAME_CACHE_DIRS:
        ecosystem, kind = NAME_CACHE_DIRS[name]
        return (ecosystem, kind, POLICY_CACHE, "caché regenerable automáticamente")

    if name in RISKY_DIR_NAMES:
        ecosystem: str = RISKY_DIR_NAMES[name]
        return (
            ecosystem,
            "build-artifact",
            POLICY_REVIEW,
            "artefacto de build; puede contener algo que entregaste",
        )

    # Cache containers come before the venv check on purpose: uv and pre-commit
    # stamp a pyvenv.cfg into their extractions.
    container: tuple[str, str, Literal["cache", "project", "review"]] | None = (
        CACHE_CONTAINER_SEGMENTS.get(name)
    )
    if container is not None and path.parent.name.lower() in CACHE_PARENT_NAMES:
        ecosystem, kind, policy = container
        return (ecosystem, kind, policy, "caché de herramientas; se repuebla sola")

    if is_uv_cache_entry(path=path):
        return (
            "uv",
            "package-cache",
            POLICY_CACHE,
            "caché de entornos sin empaquetar de uv; se repuebla sola",
        )

    environment: tuple[str, str, str] | None = classify_venv(path=path)
    if environment is not None:
        ecosystem, kind, reason = environment
        if is_app_data_surface(path=path):
            return (
                ecosystem,
                "tool-env",
                POLICY_REVIEW,
                (
                    "entorno instalado dentro de una aplicación; "
                    "se recupera reinstalándola"
                ),
            )
        return (ecosystem, kind, POLICY_PROJECT, reason)

    return None


# --- scan: traversal ------------------------------------------------------


def make_candidate(
    path: Path,
    ecosystem: str,
    kind: str,
    policy: Policy,
    reason: str,
    *,
    min_age_days: int,
    now: float,
) -> Candidate | None:
    """Measure a directory and turn it into a candidate when it qualifies.

    Args:
        path: Directory classified as removable.
        ecosystem: Tool family owning the artifact.
        kind: Artifact type.
        policy: Deletion policy.
        reason: Human explanation.
        min_age_days: Skip anything newer than this. Zero disables the filter.
        now: Reference timestamp for the age computation.

    Returns:
        A candidate with ``selected`` left False, or None when the tree is
        empty, weighs nothing, or is too recent.
    """
    size, count, newest = measure_tree(path=path)
    if count == 0 or size == 0:
        return None
    age_seconds: float = (now - newest) if newest else 0.0
    age_days: int = int(age_seconds // 86400)
    if min_age_days > 0 and age_days < min_age_days:
        return None
    return Candidate(
        path=str(path),
        ecosystem=ecosystem,
        kind=kind,
        policy=policy,
        reason=reason,
        size_bytes=size,
        file_count=count,
        age_days=age_days,
        last_modified=(
            datetime.fromtimestamp(newest).isoformat(timespec="seconds")
            if newest
            else ""
        ),
        fingerprint=fingerprint(path=path),
    )


def excluded(path: Path, patterns: Sequence[str]) -> bool:
    """Report whether a path matches any user-supplied exclusion glob.

    Args:
        path: Path to test.
        patterns: Glob patterns, matched against the full path and the basename.

    Returns:
        True when the path must be ignored.
    """
    text: str = str(object=path)
    return any(
        fnmatch.fnmatch(name=text, pat=pattern)
        or fnmatch.fnmatch(name=path.name, pat=pattern)
        for pattern in patterns
    )


def scan_tree(
    root: Path,
    *,
    options: ScanOptions,
    now: float,
    blocked_roots: Sequence[Path],
    stats: dict[str, int] | None = None,
) -> Iterator[Candidate]:
    """Walk a root and yield every removable directory found inside it.

    A classified directory is pruned, never descended into, so a report can
    never describe a tree it is about to delete as several overlapping items.

    Best effort by contract: one unreadable object is skipped, never fatal.

    Args:
        root: Directory to walk.
        options: Bounds and filters for this scan.
        now: Reference timestamp for age filtering.
        blocked_roots: Directories the cache table already owns; skipped here
            so they cannot be reported twice.
        stats: Optional accumulator receiving the bytecode caches that were
            measured but left out of the plan.

    Yields:
        Candidates, each with ``selected`` set to False.
    """
    if not dir_exists(path=root):
        return
    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack:
        directory, depth = stack.pop()
        try:
            entries: list[os.DirEntry[str]] = list(os.scandir(path=directory))
        except OSError:
            continue
        for entry in entries:
            try:
                if not entry.is_dir(follow_symlinks=False):
                    continue
                child: Path = Path(entry.path)
                if is_reparse_point(path=child):
                    continue
                if child.name.lower() in SKIP_DIR_NAMES:
                    continue
                if excluded(path=child, patterns=options.excludes):
                    continue
                if any(
                    is_within(child=child, parent=blocked) for blocked in blocked_roots
                ):
                    continue

                classified: tuple[str, str, Policy, str] | None = classify_dir(
                    path=child
                )
                if classified is not None:
                    ecosystem, kind, policy, reason = classified
                    if policy == POLICY_REVIEW and not options.include_risky:
                        continue
                    candidate: Candidate | None = make_candidate(
                        path=child,
                        ecosystem=ecosystem,
                        kind=kind,
                        policy=policy,
                        reason=reason,
                        min_age_days=options.min_age_days,
                        now=now,
                    )
                    if candidate is not None:
                        if (
                            candidate.kind == "bytecode-cache"
                            and candidate.size_bytes < MIN_BYTECODE_BYTES
                        ):
                            if stats is not None:
                                stats["bytecode_skipped_count"] = (
                                    stats.get("bytecode_skipped_count", 0) + 1
                                )
                                stats["bytecode_skipped_bytes"] = (
                                    stats.get("bytecode_skipped_bytes", 0)
                                    + candidate.size_bytes
                                )
                            continue
                        yield candidate
                    continue

                if depth + 1 <= options.max_depth:
                    stack.append((child, depth + 1))
            except OSError:
                continue


def run_scan(options: ScanOptions) -> tuple[list[Candidate], dict[str, Any]]:
    """Run every scanner and return deduplicated candidates plus a summary.

    Args:
        options: Bounds and filters for this scan.

    Returns:
        Tuple of the candidate list (large to small, caches first) and a
        summary mapping with counts and reclaimed bytes.
    """
    now = time.time()
    every_location: list[CacheLocation] = cache_locations()

    if options.explicit_roots:
        roots = [Path(root_text).expanduser() for root_text in options.roots]
        locations = [
            location
            for location in every_location
            if any(is_within(child=location.path, parent=root) for root in roots)
        ]
    else:
        locations = every_location

    # Blocked regardless: the tree walk must not re-report a cache the table owns.
    known_cache_roots = [
        location.path for location in every_location if dir_exists(path=location.path)
    ]

    candidates: list[Candidate] = []
    seen: set[str] = set()
    stats: dict[str, int] = {"bytecode_skipped_count": 0, "bytecode_skipped_bytes": 0}

    def push(candidate: Candidate | None) -> None:
        """Add a candidate unless it is unsafe or already known."""
        if candidate is None:
            return
        key: str = norm(path=Path(candidate.path))
        if key in seen:
            return
        if unsafe_reason(path=Path(candidate.path)) is not None:
            return
        seen.add(key)
        candidates.append(candidate)

    # 1. Known cache locations, measured directly.
    for location in locations:
        if not dir_exists(path=location.path):
            continue
        if location.policy == POLICY_REVIEW and not options.include_risky:
            continue
        if excluded(path=location.path, patterns=options.excludes):
            continue
        push(
            make_candidate(
                path=location.path,
                ecosystem=location.ecosystem,
                kind=location.kind,
                policy=location.policy,
                reason=location.reason,
                min_age_days=options.min_age_days,
                now=now,
            )
        )

    # 2. Project artifacts found by walking the roots.
    for root_text in options.roots:
        root = Path(root_text).expanduser()
        if not dir_exists(path=root):
            continue
        try:
            for candidate in scan_tree(
                root=root,
                options=options,
                now=now,
                blocked_roots=known_cache_roots,
                stats=stats,
            ):
                push(candidate)
        except OSError:
            continue

    order = {policy: index for index, policy in enumerate(iterable=POLICY_ORDER)}
    candidates.sort(
        key=lambda item: (order.get(item.policy, 9), -item.size_bytes, item.path)
    )

    summary: dict[str, Any] = {
        "count": len(candidates),
        "bytes": sum(item.size_bytes for item in candidates),
        "by_policy": {
            policy: sum(1 for item in candidates if item.policy == policy)
            for policy in POLICY_ORDER
        },
        "bytecode_skipped_count": stats["bytecode_skipped_count"],
        "bytecode_skipped_bytes": stats["bytecode_skipped_bytes"],
    }
    return candidates, summary


# --- plan I/O -------------------------------------------------------------


def plan_to_dict(
    candidates: Sequence[Candidate], options: ScanOptions, summary: dict[str, Any]
) -> dict[str, Any]:
    """Build the serializable plan document.

    Args:
        candidates: Scanned candidates, none of them selected.
        options: The bounds this scan used, kept for auditing.
        summary: Totals produced by :func:`run_scan`.

    Returns:
        JSON-serializable plan mapping.
    """
    return {
        "version": PLAN_VERSION,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "options": asdict(obj=options),
        "summary": summary,
        "entries": [asdict(obj=candidate) for candidate in candidates],
    }


def load_plan(path: Path) -> dict[str, Any]:
    """Read and minimally validate a plan file.

    Args:
        path: Plan file location.

    Returns:
        The parsed plan.

    Raises:
        SystemExit: When the file is missing, not JSON, or not a plan.
    """
    try:
        data = json.loads(s=path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"No existe el plan: {path}")
    except json.JSONDecodeError as exc:
        raise SystemExit(f"El plan no es JSON válido ({path}): {exc}")
    if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
        raise SystemExit(f"El plan no tiene el formato esperado: {path}")
    return data


def save_plan(path: Path, plan: dict[str, Any]) -> None:
    """Write a plan as UTF-8 JSON with stable formatting.

    Args:
        path: Destination file.
        plan: Plan document to write.
    """
    path.write_text(
        data=json.dumps(obj=plan, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def plan_entries(plan: dict[str, Any]) -> list[PlanEntry]:
    """Return the well-formed entries of a plan.

    Args:
        plan: Parsed plan document.

    Returns:
        Entries that are JSON objects, in file order.
    """
    return [entry for entry in plan["entries"] if isinstance(entry, dict)]


def selection_summary(plan: dict[str, Any]) -> tuple[int, int]:
    """Count the selected entries and their total size.

    Args:
        plan: Parsed plan document.

    Returns:
        Tuple of ``(selected_count, selected_bytes)``.
    """
    chosen: list[dict[str, Any]] = [
        entry for entry in plan_entries(plan=plan) if entry.get("selected")
    ]
    return len(chosen), sum(int(entry.get("size_bytes", 0)) for entry in chosen)


# --- presentation ---------------------------------------------------------


def print_table(rows: Sequence[tuple[str, ...]], headers: Sequence[str]) -> None:
    """Print an aligned table.

    Args:
        rows: Body rows, each with the same width as ``headers``.
        headers: Column titles.
    """
    widths: list[int] = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(iterable=row):
            widths[index] = max(widths[index], len(cell))
    print(
        "  ".join(
            header.ljust(widths[index]) for index, header in enumerate(iterable=headers)
        ).rstrip()
    )
    print("  ".join("-" * widths[index] for index in range(len(headers))))
    for row in rows:
        print(
            "  ".join(
                cell.ljust(widths[index]) for index, cell in enumerate(iterable=row)
            ).rstrip()
        )


def print_plan_table(plan: dict[str, Any], *, only_selected: bool = False) -> None:
    """Print a plan as a table.

    Args:
        plan: Parsed plan document.
        only_selected: Show only the entries the user picked.
    """
    rows: list[tuple[str, ...]] = []
    for index, entry in enumerate(iterable=plan_entries(plan=plan), start=1):
        if only_selected and not entry.get("selected"):
            continue
        mark: Literal["[x]", "[ ]"] = "[x]" if entry.get("selected") else "[ ]"
        rows.append(
            (
                f"{index:>3} {mark}",
                human_bytes(size=float(entry.get("size_bytes", 0))),
                f"{int(entry.get('age_days', 0))}d",
                f"{entry.get('ecosystem', '?')}/{entry.get('kind', '?')}",
                entry.get("policy", "?"),
                entry.get("path", "?"),
            )
        )
    if not rows:
        print("(sin entradas)")
        return
    print_table(
        rows=rows, headers=("  #", "tamaño", "edad", "tipo", "política", "ruta")
    )


# --- selection ------------------------------------------------------------

SELECT_HELP: str = """\
Comandos:
  1 2 5-9     alternar (toggle) las entradas indicadas
  + 4 7       marcar como seleccionadas
  - 4 7       quitar de la selección
  a           seleccionar todas      n   no seleccionar ninguna
  i           invertir selección     d N ver detalle de la entrada N
  f TEXTO     marcar las rutas que contengan TEXTO
  p [N]       ir a la página N (o a la siguiente)
  b           página anterior
  w           guardar y salir        q   salir sin guardar
"""


def parse_indices(tokens: Sequence[str], count: int) -> list[int]:
    """Turn user tokens such as ``1 3 5-8`` into zero-based indices.

    Args:
        tokens: Raw tokens, each a number or an inclusive range.
        count: Number of entries, used to clamp and drop out-of-range values.

    Returns:
        Sorted, deduplicated, in-range indices.
    """
    picked: list[int] = []
    for token in tokens:
        token: str = token.strip().strip(",")
        if not token:
            continue
        if "-" in token[1:]:
            start_text, _, end_text = token.partition("-")
            try:
                start, end = int(start_text), int(end_text)
            except ValueError:
                continue
            if start > end:
                start, end = end, start
            picked.extend(range(start - 1, end))
        else:
            try:
                picked.append(int(token) - 1)
            except ValueError:
                continue
    return sorted({index for index in picked if 0 <= index < count})


def print_page(entries: Sequence[PlanEntry], page: int) -> int:
    """Print one page of entries.

    Args:
        entries: All plan entries.
        page: Requested page, clamped into range.

    Returns:
        The page actually printed.
    """
    total_pages: int = max(1, (len(entries) + PAGE_SIZE - 1) // PAGE_SIZE)
    page: int = max(0, min(page, total_pages - 1))
    start: int = page * PAGE_SIZE
    rows: list[tuple[str, str, str, str, Any]] = []
    for offset, entry in enumerate(iterable=entries[start : start + PAGE_SIZE]):
        mark: Literal["[x]", "[ ]"] = "[x]" if entry.get("selected") else "[ ]"
        rows.append(
            (
                f"{start + offset + 1:>3} {mark}",
                human_bytes(size=float(entry.get("size_bytes", 0))),
                f"{int(entry.get('age_days', 0))}d",
                f"{entry.get('ecosystem', '?')}/{entry.get('kind', '?')}",
                entry.get("path", "?"),
            )
        )
    print(f"\n--- página {page + 1}/{total_pages} ---")
    print_table(rows=rows, headers=("  #", "tamaño", "edad", "tipo", "ruta"))
    return page


def run_select(plan: dict[str, Any], plan_path: Path) -> int:
    """Run the interactive selector until the user saves or quits.

    Args:
        plan: Parsed plan document, mutated in place.
        plan_path: File to write when the user saves.

    Returns:
        0 when the selection was saved, 1 when there is nothing to select,
        130 when the user quit without saving.
    """
    entries: list[dict[str, Any]] = plan_entries(plan=plan)
    if not entries:
        print("El plan no tiene candidatos.")
        return 1

    page: int = 0
    dirty: bool = False
    while True:
        page: int = print_page(entries=entries, page=page)
        chosen, size = selection_summary(plan=plan)
        print(f"seleccionadas: {chosen}/{len(entries)}  ({human_bytes(size=size)})")
        try:
            raw = input("prune> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nSaliste sin guardar. La selección no se modificó.")
            return 130
        if not raw:
            continue

        command, _, rest = raw.partition(" ")
        command: str = command.lower()
        tokens: list[str] = rest.split()

        if command in ("w", "guardar", "save"):
            save_plan(path=plan_path, plan=plan)
            print(f"Selección guardada en {plan_path}")
            return 0
        if command in ("q", "salir", "quit"):
            if dirty:
                answer: str = (
                    input("Hay cambios sin guardar. ¿Salir igual? [s/N] ")
                    .strip()
                    .lower()
                )
                if answer not in ("s", "si", "sí", "y", "yes"):
                    continue
            print("Saliste sin guardar.")
            return 130
        if command in ("?", "h", "help", "ayuda"):
            print(SELECT_HELP)
            continue
        if command == "a":
            for entry in entries:
                entry["selected"] = True
            dirty = True
            continue
        if command == "n":
            for entry in entries:
                entry["selected"] = False
            dirty = True
            continue
        if command == "i":
            for entry in entries:
                entry["selected"] = not entry.get("selected")
            dirty = True
            continue
        if command == "p":
            if tokens and tokens[0].isdigit():
                page: int = int(tokens[0]) - 1
            else:
                page += 1
            continue
        if command == "b":
            page -= 1
            continue
        if command == "d":
            indices: list[int] = parse_indices(tokens=tokens, count=len(entries))
            if not indices:
                print("Uso: d N")
                continue
            print()
            for key, value in entries[indices[0]].items():
                print(f"  {key}: {value}")
            continue
        if command in ("f", "buscar", "find"):
            if not tokens:
                print("Uso: f TEXTO")
                continue
            needle = " ".join(tokens).lower()
            hits: int = 0
            for entry in entries:
                if needle in str(object=entry.get("path", "")).lower():
                    entry["selected"] = True
                    hits += 1
            dirty = True
            print(f"{hits} entradas marcadas.")
            continue

        force: bool | None = None
        if raw[0] in "+-":
            force = raw[0] == "+"
            tokens: list[str] = raw[1:].replace(",", " ").split()
        else:
            tokens: list[str] = raw.replace(",", " ").split()

        indices: list[int] = parse_indices(tokens=tokens, count=len(entries))
        if not indices:
            print("No entendí el comando. Escribí ? para ver la ayuda.")
            continue
        for index in indices:
            current: bool = bool(entries[index].get("selected"))
            entries[index]["selected"] = (not current) if force is None else force
        dirty = True


def run_select_bulk(plan: dict[str, Any], args: argparse.Namespace) -> int:
    """Apply non-interactive selection criteria, for scripting.

    Args:
        plan: Parsed plan document, mutated in place.
        args: Parsed CLI arguments carrying the selection criteria.

    Returns:
        0 when criteria were applied, 2 when no criterion was given.
    """
    entries: list[dict[str, Any]] = plan_entries(plan=plan)
    policies: list[Any | LiteralString] = [
        value.strip()
        for value in (args.select_policy or "").split(",")
        if value.strip()
    ]
    kinds: list[Any | LiteralString] = [
        value.strip() for value in (args.select_kind or "").split(",") if value.strip()
    ]
    if not any(
        [
            args.select_all,
            policies,
            kinds,
            args.select_match,
            args.deselect_match,
            args.invert,
        ]
    ):
        print("Nada que hacer: pasá --interactive o algún criterio de selección.")
        return 2
    for entry in entries:
        if args.select_all:
            entry["selected"] = True
        if policies and entry.get("policy") in policies:
            entry["selected"] = True
        if kinds and entry.get("kind") in kinds:
            entry["selected"] = True
        for pattern in args.select_match or []:
            if fnmatch.fnmatch(name=str(object=entry.get("path", "")), pat=pattern):
                entry["selected"] = True
        for pattern in args.deselect_match or []:
            if fnmatch.fnmatch(name=str(object=entry.get("path", "")), pat=pattern):
                entry["selected"] = False
    if args.invert:
        for entry in entries:
            entry["selected"] = not entry.get("selected")
    return 0


# --- deletion backends ----------------------------------------------------

#: ``SHFileOperationW`` constants used for recycle-bin deletion.
FO_DELETE: int = 3
FOF_SILENT: int = 0x0004
FOF_NOCONFIRMATION: int = 0x0010
FOF_ALLOWUNDO: int = 0x0040
FOF_NOERRORUI: int = 0x0400
FOF_WANTNUKEWARNING: int = 0x4000
MAX_PATH: int = 260


def windows_recycle(path: Path) -> None:
    """Move a path to the Windows recycle bin through the shell API.

    Args:
        path: Path to remove. Must be shorter than ``MAX_PATH``; the shell API
            has no extended-length form, so deeper paths need ``--hard``.

    Raises:
        OSError: When the shell refuses the operation.
    """
    from ctypes import wintypes

    class SHFILEOPSTRUCTW(ctypes.Structure):
        """Mirror of the Win32 ``SHFILEOPSTRUCTW`` layout."""

        _fields_ = [
            ("hwnd", wintypes.HWND),
            ("wFunc", wintypes.UINT),
            ("pFrom", wintypes.LPCWSTR),
            ("pTo", wintypes.LPCWSTR),
            ("fFlags", ctypes.c_uint16),
            ("fAnyOperationsAborted", wintypes.BOOL),
            ("hNameMappings", ctypes.c_void_p),
            ("lpszProgressTitle", wintypes.LPCWSTR),
        ]

    text: str = str(object=path)
    if len(text) >= MAX_PATH:
        raise OSError(
            "ruta de 260 caracteres o más: la Papelera no la acepta (usá --hard)"
        )

    operation = SHFILEOPSTRUCTW()
    operation.hwnd = None
    operation.wFunc = FO_DELETE
    operation.pFrom = text + "\0"
    operation.pTo = None
    operation.fFlags = (
        FOF_ALLOWUNDO
        | FOF_NOCONFIRMATION
        | FOF_SILENT
        | FOF_NOERRORUI
        | FOF_WANTNUKEWARNING
    )
    code: Any = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(operation))
    if code != 0:
        raise OSError(f"SHFileOperationW devolvió {code}")
    if operation.fAnyOperationsAborted:
        raise OSError("la operación fue abortada por el sistema")


def xdg_trash(path: Path) -> None:
    """Move a path to the XDG trash directory on POSIX systems.

    Args:
        path: Path to remove.
    """
    data_home: str | None = os.environ.get(key="XDG_DATA_HOME")
    base = Path(data_home) if data_home else real_user_home() / ".local" / "share"
    files_dir: Path = base / "Trash" / "files"
    info_dir: Path = base / "Trash" / "info"
    files_dir.mkdir(parents=True, exist_ok=True)
    info_dir.mkdir(parents=True, exist_ok=True)

    target: Path = files_dir / path.name
    suffix: int = 1
    while target.exists():
        target: Path = files_dir / f"{path.name}.{suffix}"
        suffix += 1
    shutil.move(src=str(object=path), dst=str(object=target))

    stamp: str = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    info: str = (
        f"[Trash Info]\nPath={quote(string=str(object=path))}\nDeletionDate={stamp}\n"
    )
    (info_dir / f"{target.name}.trashinfo").write_text(info, encoding="utf-8")


def hard_delete(path: Path) -> None:
    """Delete a tree outright, tolerating read-only files and deep paths.

    Args:
        path: File, link or directory to remove.

    Raises:
        OSError: The first error encountered while walking the tree.
    """
    if is_reparse_point(path=path) or path.is_file():
        try:
            os.unlink(path=path)
        except OSError:
            os.chmod(path, mode=stat.S_IWRITE)
            os.unlink(path=path)
        return

    root_text: str = extended_path(path=path)
    errors: list[OSError] = []

    def on_error(exc: OSError) -> None:
        """Collect walk errors instead of raising them immediately."""
        errors.append(exc)

    for directory, subdirs, files in os.walk(
        top=root_text, topdown=False, onerror=on_error
    ):
        for name in files:
            target: str = os.path.join(directory, name)
            try:
                os.unlink(path=target)
            except OSError:
                os.chmod(path=target, mode=stat.S_IWRITE)
                os.unlink(path=target)
        for name in subdirs:
            target: str = os.path.join(directory, name)
            try:
                os.rmdir(path=target)
            except OSError:
                try:
                    os.chmod(path=target, mode=stat.S_IWRITE)
                except OSError:
                    pass
                try:
                    os.rmdir(path=target)
                except OSError:
                    os.unlink(path=target)
    os.rmdir(path=root_text)
    if errors:
        raise errors[0]


def delete_path(path: Path, *, hard: bool) -> None:
    """Remove a path using the requested strategy.

    Args:
        path: Path to remove.
        hard: True for a definitive delete, False for the recycle bin.
    """
    if hard:
        hard_delete(path=path)
        return
    if os.name == "nt":
        windows_recycle(path=path)
    else:
        xdg_trash(path=path)


# --- apply ----------------------------------------------------------------


def drop_nested(entries: Sequence[PlanEntry]) -> list[PlanEntry]:
    """Drop entries whose ancestor is also planned.

    Args:
        entries: Planned entries.

    Returns:
        Entries without parent/child overlap, parents kept.
    """
    ordered: list[dict[str, Any]] = sorted(
        entries, key=lambda entry: len(str(object=entry.get("path", "")))
    )
    kept: list[PlanEntry] = []
    for entry in ordered:
        key: str = norm(path=Path(str(object=entry.get("path", ""))))
        if any(
            key.startswith(norm(path=Path(str(object=parent.get("path", "")))) + os.sep)
            for parent in kept
        ):
            continue
        kept.append(entry)
    return kept


def revalidate(entry: PlanEntry) -> str | None:
    """Check that a planned entry is still safe and unchanged.

    Args:
        entry: Plan entry captured at scan time.

    Returns:
        The reason the entry must be skipped, or None when it may be deleted.
    """
    path: Path = Path(str(object=entry.get("path", "")))
    reason: str | None = unsafe_reason(path=path)
    if reason is not None:
        return reason

    current: Fingerprint = fingerprint(path=path)
    planned = entry.get("fingerprint") or {}
    planned_dev = planned.get("dev") or 0
    planned_ino = planned.get("ino") or 0
    if planned_dev and current.get("dev") and planned_dev != current.get("dev"):
        return "cambió el volumen desde el escaneo"
    if planned_ino and current.get("ino") and planned_ino != current.get("ino"):
        return "la ruta ahora apunta a otro objeto"
    planned_mtime: Any | None = planned.get("mtime")
    if (
        isinstance(planned_mtime, (int, float))
        and abs(float(planned_mtime) - float(current.get("mtime", 0.0))) > 1.0
    ):
        return "se modificó después del escaneo; volvé a escanear"
    return None


def run_apply(plan: dict[str, Any], *, hard: bool, assume_yes: bool) -> int:
    """Delete the selected entries after confirmation and revalidation.

    Args:
        plan: Parsed plan document.
        hard: True to delete outright instead of using the recycle bin.
        assume_yes: Skip the final confirmation prompt.

    Returns:
        0 when every attempted deletion succeeded, 1 when there was nothing
        selected, the user cancelled, or a deletion failed, 130 when the prompt
        was interrupted.
    """
    chosen: list[dict[str, Any]] = [
        entry for entry in plan_entries(plan=plan) if entry.get("selected")
    ]
    if not chosen:
        print("No hay ninguna entrada seleccionada. Nada que borrar.")
        print("Usá 'select' para elegir qué borrar y qué conservar.")
        return 1

    chosen: list[dict[str, Any]] = drop_nested(entries=chosen)
    total = sum(int(entry.get("size_bytes", 0)) for entry in chosen)
    destination: Literal["borrado definitivo", "Papelera de reciclaje"] = (
        "borrado definitivo"
        if hard
        else ("Papelera de reciclaje" if os.name == "nt" else "Papelera XDG")
    )
    print(
        f"Se van a borrar {len(chosen)} entradas ({human_bytes(size=total)}) -> {destination}."
    )
    if not assume_yes:
        try:
            answer = input("¿Confirmás el borrado? [s/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nCancelado.")
            return 130
        if answer not in ("s", "si", "sí", "y", "yes"):
            print("Cancelado. No se borró nada.")
            return 1

    removed: int = 0
    freed: int = 0
    skipped: list[tuple[str, str]] = []
    failed: list[tuple[str, str]] = []

    for entry in chosen:
        path: Path = Path(str(object=entry.get("path", "")))
        problem: str | None = revalidate(entry=entry)
        if problem is not None:
            skipped.append((str(object=path), problem))
            continue
        try:
            delete_path(path=path, hard=hard)
        except OSError as exc:
            failed.append((str(object=path), str(object=exc)))
            continue
        removed += 1
        freed += int(entry.get("size_bytes", 0))
        print(f"  borrado: {path}")

    print()
    print(f"Borradas: {removed}  ({human_bytes(size=freed)})")
    if skipped:
        print(f"Omitidas por seguridad: {len(skipped)}")
        for path_text, reason in skipped:
            print(f"  - {path_text}: {reason}")
    if failed:
        print(f"Fallidas: {len(failed)}")
        for path_text, reason in failed:
            print(f"  - {path_text}: {reason}")
    return 0 if not failed else 1


# --- CLI ------------------------------------------------------------------


def default_roots() -> list[str]:
    """Return the roots scanned when the user passes no ``--root``.

    Returns:
        The user profile plus common development directories that exist.
    """
    home: Path = real_user_home()
    roots: list[str] = [str(object=home)]
    for name in (
        "Desktop",
        "Documents",
        "Downloads",
        "source",
        "dev",
        "projects",
        "code",
    ):
        candidate: Path = home / name
        if dir_exists(path=candidate):
            roots.append(str(object=candidate))
    return roots


def build_parser() -> argparse.ArgumentParser:
    """Build the command line parser.

    Returns:
        Configured parser with the ``scan``, ``select``, ``apply`` and ``show``
        subcommands.
    """
    parser = argparse.ArgumentParser(
        prog="prune",
        description="Encuentra entornos virtuales viejos, cachés y artefactos de build. "
        "Escanea, te deja elegir, y solo después borra lo elegido.",
    )
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser] = (
        parser.add_subparsers(dest="command", required=True)
    )

    scan: argparse.ArgumentParser = subparsers.add_parser(
        name="scan", help="solo lectura: descubre y escribe el plan"
    )
    scan.add_argument(
        "--root",
        action="append",
        default=[],
        help="raíz a escanear (repetible); acota TODOS los escáneres, "
        "incluidas las cachés conocidas",
    )
    scan.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH)
    scan.add_argument("--min-age-days", type=int, default=DEFAULT_MIN_AGE_DAYS)
    scan.add_argument(
        "--include-risky",
        action="store_true",
        help="incluye artefactos de build y temporales (política review)",
    )
    scan.add_argument(
        "--exclude", action="append", default=[], help="patrón glob a ignorar"
    )
    scan.add_argument("--plan", default=DEFAULT_PLAN_NAME)
    scan.add_argument("--json", action="store_true", help="imprime el plan por stdout")

    pick: argparse.ArgumentParser = subparsers.add_parser(
        name="select", help="elegir qué se borra y qué no"
    )
    pick.add_argument("--plan", default=DEFAULT_PLAN_NAME)
    pick.add_argument("--interactive", action="store_true", help="selector interactivo")
    pick.add_argument("--select-all", action="store_true")
    pick.add_argument("--select-policy", help="cache,project,review")
    pick.add_argument("--select-kind", help="venv,node_modules,package-cache,...")
    pick.add_argument("--select-match", action="append", default=[], metavar="GLOB")
    pick.add_argument("--deselect-match", action="append", default=[], metavar="GLOB")
    pick.add_argument("--invert", action="store_true")

    apply_command: argparse.ArgumentParser = subparsers.add_parser(
        name="apply", help="borrar solo lo seleccionado"
    )
    apply_command.add_argument("--plan", default=DEFAULT_PLAN_NAME)
    apply_command.add_argument(
        "--hard",
        action="store_true",
        help="borrado definitivo en vez de mandar a la Papelera",
    )
    apply_command.add_argument(
        "--yes", action="store_true", help="no pedir confirmación final"
    )

    show: argparse.ArgumentParser = subparsers.add_parser(
        name="show", help="imprimir un plan sin tocar nada"
    )
    show.add_argument("--plan", default=DEFAULT_PLAN_NAME)
    show.add_argument("--selected", action="store_true", help="solo lo seleccionado")
    return parser


def configure_stdout() -> None:
    """Force UTF-8 output so accents survive a legacy Windows code page."""
    for stream in (sys.stdout, sys.stderr):
        # ``reconfigure`` lives on TextIOWrapper, but a host application may
        # replace these streams with anything, so probe instead of assuming.
        reconfigure: Any | None = getattr(stream, "reconfigure", None)
        if not callable(reconfigure):
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except ValueError:
            pass


def main(argv: Sequence[str] | None = None) -> int:
    """Dispatch the command line.

    Args:
        argv: Argument list, defaulting to ``sys.argv[1:]``.

    Returns:
        Process exit code.
    """
    configure_stdout()
    parser: argparse.ArgumentParser = build_parser()
    args: argparse.Namespace = parser.parse_args(args=argv)

    if args.command == "scan":
        roots = args.root or default_roots()
        options = ScanOptions(
            roots=roots,
            max_depth=args.max_depth,
            min_age_days=args.min_age_days,
            include_risky=args.include_risky,
            excludes=args.exclude,
            explicit_roots=bool(args.root),
        )
        candidates, summary = run_scan(options=options)
        plan: dict[str, Any] = plan_to_dict(
            candidates=candidates, options=options, summary=summary
        )
        plan_path: Path = Path(args.plan)
        save_plan(path=plan_path, plan=plan)

        if args.json:
            print(json.dumps(obj=plan, indent=2, ensure_ascii=False))
        else:
            print_plan_table(plan=plan)
            print()
            print(
                f"Candidatos: {summary['count']}  ({human_bytes(size=summary['bytes'])})"
            )
            for policy in POLICY_ORDER:
                print(f"  {policy:<8} {summary['by_policy'][policy]:>4}")
            print(f"\nPlan escrito en {plan_path} (nada seleccionado, nada borrado).")
            print("Siguiente paso:  python prune.py select --interactive")
        return 0

    if args.command == "select":
        plan_path = Path(args.plan)
        plan: dict[str, Any] = load_plan(path=plan_path)
        if args.interactive:
            code: int = run_select(plan=plan, plan_path=plan_path)
            if code != 0:
                return code
        else:
            code: int = run_select_bulk(plan=plan, args=args)
            if code != 0:
                return code
            save_plan(path=plan_path, plan=plan)

        chosen, size = selection_summary(plan=plan)
        print(f"\nSeleccionadas: {chosen}  ({human_bytes(size=size)})")
        print("Siguiente paso:  python prune.py apply")
        return 0

    if args.command == "apply":
        plan: dict[str, Any] = load_plan(path=Path(args.plan))
        return run_apply(plan=plan, hard=args.hard, assume_yes=args.yes)

    if args.command == "show":
        plan: dict[str, Any] = load_plan(path=Path(args.plan))
        print_plan_table(plan=plan, only_selected=args.selected)
        chosen, size = selection_summary(plan=plan)
        print(
            f"\nSeleccionadas: {chosen} de {len(plan_entries(plan=plan))}  ({human_bytes(size=size)})"
        )
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrumpido.")
        sys.exit(130)
