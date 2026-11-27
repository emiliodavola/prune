"""Tests for prune. Stdlib only: python -m unittest -v test_prune"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from dataclasses import asdict
from pathlib import Path
from typing import Any
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import prune


def set_age(path: Path, days: int) -> None:
    """Backdate a tree so the scanner's age filter accepts it.

    Every descendant is stamped too: one fresh child would otherwise keep the
    whole tree younger than ``min_age_days`` in the scanner's eyes.
    """
    stamp = time.time() - days * 86400
    for target in [path, *path.rglob("*")]:
        try:
            os.utime(target, (stamp, stamp))
        except OSError:
            pass


def make_venv(root: Path, name: str, *, home: str) -> Path:
    """A venv is defined by pyvenv.cfg + an interpreter, never by its name."""
    venv = root / name
    scripts = venv / "Scripts"
    scripts.mkdir(parents=True)
    (scripts / "python.exe").write_bytes(b"\0")
    posix_bin = venv / "bin"
    posix_bin.mkdir()
    (posix_bin / "python").write_bytes(b"\0")
    (venv / "pyvenv.cfg").write_text(
        f"home = {home}\nversion = 3.12.0\n", encoding="utf-8"
    )
    lib = venv / "Lib" / "site-packages"
    lib.mkdir(parents=True)
    (lib / "pkg.py").write_bytes(b"x" * 200)
    return venv


def make_node_modules(root: Path, name: str = "node_modules") -> Path:
    """Build a Node project tree with real payload, so size filters accept it.

    Returns the modules directory itself, because that is the unit the scanner
    reports, not the project that contains it.
    """
    project = root / "proj"
    modules = project / name
    package = modules / "left-pad"
    package.mkdir(parents=True)
    (package / "index.js").write_bytes(b"y" * 300)
    (project / "package.json").write_text("{}", encoding="utf-8")
    return modules


def make_junction(link: Path, target: Path) -> bool:
    """Junctions need no privileges on Windows; symlinks do."""
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(target)],
        check=False,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


class FixtureCase(unittest.TestCase):
    """Give every test a throwaway tree plus a default way to scan it."""

    def setUp(self) -> None:
        """Create an isolated root, so no test can touch the real filesystem."""
        self.root = Path(tempfile.mkdtemp(prefix="prune-test-"))

    def tearDown(self) -> None:
        """Remove the tree even when the test failed halfway through."""
        shutil.rmtree(self.root, ignore_errors=True)

    def scan(
        self, *, min_age_days: int = 0, include_risky: bool = False
    ) -> list[prune.Candidate]:
        """Scan the fixture root and return fully materialized candidates.

        The generator is consumed here on purpose: a lazy scan would let a
        failure surface during an unrelated assertion, far from its cause.
        """
        options = prune.ScanOptions(
            roots=[str(self.root)],
            min_age_days=min_age_days,
            include_risky=include_risky,
        )
        return list(
            prune.scan_tree(
                self.root, options=options, now=time.time(), blocked_roots=[]
            )
        )


class DetectionTests(FixtureCase):
    """What the scanner is willing to call a removable artifact."""

    def test_detects_venv_by_marker_not_by_folder_name(self) -> None:
        """A misleading folder name must not decide detection; the markers do."""
        venv = make_venv(self.root, "entorno-raro", home="C:/no/existe")
        set_age(venv, 90)

        found = self.scan(min_age_days=30)

        self.assertEqual([candidate.kind for candidate in found], ["venv"])
        self.assertEqual(found[0].policy, prune.POLICY_PROJECT)
        self.assertIn("intérprete base ya no existe", found[0].reason)
        self.assertFalse(found[0].selected, "scan must never pre-select anything")
        self.assertGreater(found[0].size_bytes, 0)

    def test_folder_named_dot_venv_without_marker_is_not_a_venv(self) -> None:
        """A folder called .venv without pyvenv.cfg is user data, not an environment."""
        fake = self.root / ".venv"
        (fake / "lib").mkdir(parents=True)
        (fake / "lib" / "leftover.py").write_text("x", encoding="utf-8")
        set_age(fake, 90)

        found = self.scan(min_age_days=30)

        self.assertEqual([c for c in found if c.kind == "venv"], [])

    def test_detects_node_modules(self) -> None:
        """A project node_modules is a project artifact, never a review-only one."""
        modules = make_node_modules(self.root)
        set_age(modules, 90)

        found = self.scan(min_age_days=30)

        self.assertEqual([candidate.kind for candidate in found], ["node_modules"])
        self.assertEqual(found[0].ecosystem, "node")
        self.assertEqual(found[0].policy, prune.POLICY_PROJECT)

    def test_does_not_descend_into_a_classified_tree(self) -> None:
        """Pruning stops one report from listing a tree it already covers as a whole."""
        venv = make_venv(self.root, "venv-a", home="C:/no/existe")
        (venv / "node_modules").mkdir()
        set_age(venv, 90)

        found = self.scan(min_age_days=30)

        self.assertEqual([candidate.kind for candidate in found], ["venv"])

    def test_min_age_days_filters_recent_trees(self) -> None:
        """The age filter hides a fresh tree; scanning never deletes anything."""
        fresh = make_venv(self.root, "venv-fresh", home="C:/no/existe")

        self.assertEqual(self.scan(min_age_days=30), [])
        self.assertEqual(len(self.scan(min_age_days=0)), 1)
        self.assertTrue(fresh.exists(), "scanning must never delete")

    def test_build_artifacts_require_include_risky(self) -> None:
        """Build output stays hidden unless --include-risky is passed."""
        build = self.root / "proj" / "build"
        (build / "out").mkdir(parents=True)
        (build / "out" / "bundle.js").write_bytes(b"z" * 100)
        set_age(build, 90)

        self.assertEqual(self.scan(min_age_days=30), [])

        found = self.scan(min_age_days=30, include_risky=True)
        self.assertEqual([candidate.kind for candidate in found], ["build-artifact"])
        self.assertEqual(found[0].policy, prune.POLICY_REVIEW)


class SafetyTests(FixtureCase):
    """Guards that must refuse a deletion before a single byte is touched."""

    def test_refuses_protected_roots(self) -> None:
        """Home and the running interpreter are unrecoverable, so both are refused."""
        self.assertIsNotNone(prune.unsafe_reason(prune.real_user_home()))
        self.assertIsNotNone(prune.unsafe_reason(Path(sys.prefix)))
        self.assertIsNotNone(prune.unsafe_reason(Path(sys.base_prefix)))

    @unittest.skipUnless(os.name == "nt", "drive-letter top level is Windows-only")
    def test_refuses_top_level_directories(self) -> None:
        """A drive root or a first-level directory is never a valid deletion target."""
        home = prune.real_user_home()
        first_level = Path(*home.parts[:2])
        self.assertIsNotNone(prune.unsafe_reason(first_level))

    def test_allows_a_normal_project_tree(self) -> None:
        """A normal project directory must stay allowed, or the tool is useless."""
        victim = self.root / "victim"
        victim.mkdir()
        self.assertIsNone(prune.unsafe_reason(victim))

    def test_refuses_a_target_that_contains_a_protected_path(self) -> None:
        """Containing a protected path makes the parent unsafe, not only being one."""
        container = self.root / "container"
        container.mkdir()
        guarded = container / "kept"
        guarded.mkdir()

        with mock.patch.object(prune, "protected_paths", lambda: [guarded]):
            self.assertIsNotNone(prune.unsafe_reason(container))

    def test_refuses_missing_path(self) -> None:
        """A path that vanished after the scan must fail closed, never raise."""
        self.assertIsNotNone(prune.unsafe_reason(self.root / "nope"))


class SelectionTests(FixtureCase):
    """Turning user input into the exact set of entries that will be deleted."""

    def test_parse_indices_supports_ranges_and_ignores_garbage(self) -> None:
        """A range, a reversed range and junk share one parser; all three pin it."""
        self.assertEqual(prune.parse_indices(["1", "3-5"], 10), [0, 2, 3, 4])
        self.assertEqual(prune.parse_indices(["9-2"], 10), [1, 2, 3, 4, 5, 6, 7, 8])
        self.assertEqual(prune.parse_indices(["99", "x"], 10), [])

    def test_show_and_selection_summary(self) -> None:
        """The summary counts only selected entries and sums only their bytes."""
        plan = {
            "entries": [
                {"path": "a", "size_bytes": 100, "selected": True},
                {"path": "b", "size_bytes": 50, "selected": False},
            ]
        }
        chosen, size = prune.selection_summary(plan)
        self.assertEqual((chosen, size), (1, 100))

    def test_drop_nested_keeps_the_parent_only(self) -> None:
        """Keeping a child of a selected parent would count the same bytes twice."""
        parent = self.root / "parent"
        child = parent / "child"
        child.mkdir(parents=True)
        entries = [{"path": str(child)}, {"path": str(parent)}]

        kept = prune.drop_nested(entries)

        self.assertEqual([entry["path"] for entry in kept], [str(parent)])


class ApplyTests(FixtureCase):
    """The only destructive step: delete exactly what was selected, nothing more."""

    def make_entry(self, path: Path, *, selected: bool) -> dict[str, Any]:
        """Build a plan entry from a real directory, optionally marked for deletion."""
        candidate = prune.make_candidate(
            path,
            "python",
            "venv",
            prune.POLICY_PROJECT,
            "prueba",
            min_age_days=0,
            now=time.time(),
        )
        assert candidate is not None
        entry = asdict(candidate)
        entry["selected"] = selected
        return entry

    def test_apply_deletes_nothing_without_a_selection(self) -> None:
        """An empty selection is a cancel, never an all-clear."""
        victim = make_venv(self.root, "venv-a", home="C:/no/existe")
        plan = {"entries": [self.make_entry(victim, selected=False)]}

        code = prune.run_apply(plan, hard=True, assume_yes=True)

        self.assertEqual(code, 1)
        self.assertTrue(victim.exists())

    def test_apply_deletes_only_the_selected_entries(self) -> None:
        """Selection is per entry: the unselected sibling must survive the apply."""
        doomed = make_venv(self.root, "venv-doomed", home="C:/no/existe")
        kept = make_venv(self.root, "venv-kept", home="C:/no/existe")
        plan = {
            "entries": [
                self.make_entry(doomed, selected=True),
                self.make_entry(kept, selected=False),
            ]
        }

        code = prune.run_apply(plan, hard=True, assume_yes=True)

        self.assertEqual(code, 0)
        self.assertFalse(doomed.exists(), "selected entry must be gone")
        self.assertTrue(kept.exists(), "unselected entry must survive")

    def test_apply_requires_confirmation_without_yes(self) -> None:
        """An empty answer at the confirmation prompt cancels the whole deletion."""
        victim = make_venv(self.root, "venv-a", home="C:/no/existe")
        plan = {"entries": [self.make_entry(victim, selected=True)]}

        with mock.patch("builtins.input", lambda *args, **kwargs: ""):
            code = prune.run_apply(plan, hard=True, assume_yes=False)

        self.assertEqual(code, 1)
        self.assertTrue(victim.exists(), "an empty answer must cancel the deletion")

    def test_revalidate_rejects_entries_modified_after_the_scan(self) -> None:
        """A plan is a snapshot; a changed mtime invalidates the entry describing it."""
        victim = make_venv(self.root, "venv-a", home="C:/no/existe")
        entry = self.make_entry(victim, selected=True)

        shifted = time.time() + 100
        os.utime(victim, (shifted, shifted))

        self.assertEqual(
            prune.revalidate(entry),
            "se modificó después del escaneo; volvé a escanear",
        )

    def test_apply_skips_modified_entries_and_reports_them(self) -> None:
        """A skipped entry is reported, never deleted and never silently dropped."""
        victim = make_venv(self.root, "venv-a", home="C:/no/existe")
        plan = {"entries": [self.make_entry(victim, selected=True)]}
        shifted = time.time() + 100
        os.utime(victim, (shifted, shifted))

        code = prune.run_apply(plan, hard=True, assume_yes=True)

        self.assertEqual(code, 0)
        self.assertTrue(victim.exists(), "a changed entry must be skipped, not deleted")

    def test_hard_delete_removes_read_only_files(self) -> None:
        """Windows refuses read-only files; the hard path must clear that bit first."""
        victim = self.root / "victim"
        victim.mkdir()
        locked = victim / "locked.txt"
        locked.write_text("x", encoding="utf-8")
        os.chmod(locked, stat.S_IREAD)

        prune.hard_delete(victim)

        self.assertFalse(victim.exists())


class RootScopeTests(FixtureCase):
    """An explicit --root bounds every scanner, including the AppData ones."""

    def test_explicit_root_never_reports_entries_outside_it(self) -> None:
        """A cache found outside the requested root must never reach the plan."""
        inside = self.root / "cache-inside"
        inside.mkdir()
        (inside / "payload.bin").write_bytes(b"p" * 50)
        set_age(inside, 90)

        outside = Path(tempfile.mkdtemp(prefix="prune-outside-"))
        self.addCleanup(shutil.rmtree, outside, True)
        (outside / "payload.bin").write_bytes(b"p" * 50)
        set_age(outside, 90)

        locations = [
            prune.CacheLocation(
                inside, "python", "package-cache", prune.POLICY_CACHE, "dentro"
            ),
            prune.CacheLocation(
                outside, "python", "package-cache", prune.POLICY_CACHE, "fuera"
            ),
        ]
        options = prune.ScanOptions(
            roots=[str(self.root)], min_age_days=30, explicit_roots=True
        )
        with mock.patch.object(prune, "cache_locations", lambda: locations):
            candidates, _ = prune.run_scan(options)

        paths = [candidate.path for candidate in candidates]
        self.assertIn(str(inside), paths)
        self.assertNotIn(
            str(outside), paths, "an explicit --root must bound every scanner"
        )


class HostileFilesystemTests(FixtureCase):
    """Deliberately broken filesystems: dead junctions and unreadable paths."""

    def test_scan_survives_a_dangling_junction_inside_a_venv(self) -> None:
        """uv-created venvs use symlinks; a dead one must not abort the whole scan."""
        venv = self.root / "venv-junction"
        venv.mkdir()
        (venv / "pyvenv.cfg").write_text("home = C:/no/existe\n", encoding="utf-8")
        bin_dir = venv / "bin"
        bin_dir.mkdir()

        target = self.root / "gone"
        target.mkdir()
        (target / "payload").write_bytes(b"\0")
        interpreter = bin_dir / "python"
        if not make_junction(interpreter, target):
            self.skipTest("no se pudo crear el junction")
        shutil.rmtree(target, ignore_errors=True)

        # The exact call that aborted the real scan.
        with self.assertRaises(OSError):
            os.stat(interpreter)

        found = self.scan(min_age_days=0)

        self.assertEqual([candidate.kind for candidate in found], ["venv"])

    def test_classify_never_raises_on_an_unreadable_path(self) -> None:
        """An unreadable path is unclassified, not an exception through the scan."""
        victim = self.root / "victim"
        (victim / "pyvenv.cfg").mkdir(parents=True)
        (victim / "Scripts").mkdir()

        self.assertIsNone(prune.classify_dir(victim))


class ClassificationTests(FixtureCase):
    """Which policy a found tree receives: project artifact, cache, or review-only."""

    def test_uv_cache_entries_are_caches_not_venvs(self) -> None:
        """uv stamps pyvenv.cfg into its extractions; that must not read as a project env."""
        entry = self.root / ".cache" / "uv" / "archive-v0" / "abcdef"
        (entry / "bin").mkdir(parents=True)
        (entry / "bin" / "python").write_bytes(b"\0")
        (entry / "pyvenv.cfg").write_text("home = C:/no/existe\n", encoding="utf-8")
        set_age(entry, 90)

        found = self.scan(min_age_days=30)

        self.assertEqual([candidate.kind for candidate in found], ["package-cache"])
        self.assertEqual(found[0].ecosystem, "uv")
        self.assertEqual(found[0].policy, prune.POLICY_CACHE)

    def test_pre_commit_env_is_a_cache(self) -> None:
        """pre-commit venvs are pure cache: rebuildable, never project data."""
        env = self.root / ".cache" / "pre-commit" / "repoabc" / "py_env-python3.11"
        (env / "bin").mkdir(parents=True)
        (env / "bin" / "python").write_bytes(b"\0")
        (env / "pyvenv.cfg").write_text("home = C:/no/existe\n", encoding="utf-8")
        set_age(env, 90)

        found = self.scan(min_age_days=30)

        self.assertEqual([candidate.kind for candidate in found], ["tool-env"])
        self.assertEqual(found[0].policy, prune.POLICY_CACHE)

    def test_node_modules_inside_an_application_is_review_policy(self) -> None:
        """Editor payload is not project data, so it never gets default-selected."""
        modules = self.root / ".vscode" / "extensions" / "ms-python.1" / "node_modules"
        (modules / "pkg").mkdir(parents=True)
        (modules / "pkg" / "index.js").write_bytes(b"j" * 200)
        set_age(modules, 90)

        self.assertEqual(
            self.scan(min_age_days=30), [], "never default-select an app payload"
        )

        found = self.scan(min_age_days=30, include_risky=True)
        self.assertEqual(
            [candidate.policy for candidate in found], [prune.POLICY_REVIEW]
        )
        self.assertIn("aplicación", found[0].reason)

    def test_project_node_modules_stays_a_project_artifact(self) -> None:
        """Same folder name, different location: the location decides the policy."""
        modules = make_node_modules(self.root)
        set_age(modules, 90)

        found = self.scan(min_age_days=30)

        self.assertEqual(
            [candidate.policy for candidate in found], [prune.POLICY_PROJECT]
        )

    def test_venv_installed_inside_an_application_is_review_policy(self) -> None:
        """A uv tool environment lives under .local; deleting it breaks the tool."""
        tool = self.root / ".local" / "share" / "uv-tools" / "kaggle"
        (tool / "bin").mkdir(parents=True)
        (tool / "bin" / "python").write_bytes(b"\0")
        (tool / "pyvenv.cfg").write_text("home = C:/no/existe\n", encoding="utf-8")
        set_age(tool, 90)

        self.assertEqual(self.scan(min_age_days=30), [])

        found = self.scan(min_age_days=30, include_risky=True)
        self.assertEqual(
            [candidate.policy for candidate in found], [prune.POLICY_REVIEW]
        )
        self.assertEqual(found[0].kind, "tool-env")

    def test_node_modules_in_positron_extensions_is_review_policy(self) -> None:
        """A second editor vendor must follow the same application-surface rule."""
        modules = (
            self.root
            / ".positron"
            / "extensions"
            / "posit.shinyuieditor-0.5.0"
            / "node_modules"
        )
        (modules / "pkg").mkdir(parents=True)
        (modules / "pkg" / "index.js").write_bytes(b"j" * 100)
        set_age(modules, 90)

        self.assertEqual(self.scan(min_age_days=30), [])

    def test_tool_venv_under_a_hidden_profile_directory_is_review_policy(self) -> None:
        """Generalizes the app-surface rule: ~/.hf-cli/venv is the CLI's own env."""
        tool = self.root / ".hf-cli" / "venv"
        (tool / "bin").mkdir(parents=True)
        (tool / "bin" / "python").write_bytes(b"\0")
        (tool / "pyvenv.cfg").write_text("home = C:/no/existe\n", encoding="utf-8")
        set_age(tool, 90)

        with mock.patch.object(prune, "real_user_home", lambda: self.root):
            self.assertEqual(self.scan(min_age_days=30), [])
            found = self.scan(min_age_days=30, include_risky=True)

        self.assertEqual(
            [candidate.policy for candidate in found], [prune.POLICY_REVIEW]
        )

    def test_zero_byte_caches_are_not_reported(self) -> None:
        """An empty cache frees nothing; listing it would only add review noise."""
        empty = self.root / "proj" / ".ruff_cache"
        empty.mkdir(parents=True)
        (empty / "stamp").write_bytes(b"")
        set_age(empty, 90)

        self.assertEqual(self.scan(min_age_days=30), [])

    def test_tiny_bytecode_caches_are_not_listed(self) -> None:
        """Below MIN_BYTECODE_BYTES the entry is noise, so it stays out of the plan."""
        small = self.root / "proj" / "__pycache__"
        small.mkdir(parents=True)
        (small / "a.pyc").write_bytes(b"x" * 100)
        set_age(small, 90)

        self.assertEqual(self.scan(min_age_days=30), [])

    def test_large_bytecode_cache_is_listed(self) -> None:
        """The very same folder one byte over the threshold must be listed."""
        big = self.root / "proj" / "__pycache__"
        big.mkdir(parents=True)
        (big / "a.pyc").write_bytes(b"x" * (prune.MIN_BYTECODE_BYTES + 1))
        set_age(big, 90)

        found = self.scan(min_age_days=30)

        self.assertEqual([candidate.kind for candidate in found], ["bytecode-cache"])


class PlanTests(FixtureCase):
    """The plan file is the contract between scan, select and apply."""

    def test_plan_round_trip_preserves_selection(self) -> None:
        """A selection must survive the save/load cycle, or select is pointless."""
        plan_path = self.root / "plan.json"
        plan = {
            "version": prune.PLAN_VERSION,
            "generated_at": "2024-01-01T00:00:00",
            "options": {},
            "summary": {},
            "entries": [{"path": "x", "selected": True, "size_bytes": 10}],
        }

        prune.save_plan(plan_path, plan)
        loaded = prune.load_plan(plan_path)

        self.assertTrue(loaded["entries"][0]["selected"])
        self.assertEqual(prune.selection_summary(loaded), (1, 10))


if __name__ == "__main__":
    unittest.main()
