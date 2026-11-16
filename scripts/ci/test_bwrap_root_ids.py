import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).with_name("bwrap-root-ids.py")
SPEC = importlib.util.spec_from_file_location("bwrap_root_ids", SCRIPT)
ids = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ids)


class RootIdFixtures(unittest.TestCase):
    def test_selects_independent_nonconflicting_ranges(self):
        records = ids.allocations("user:100000:65536\n")
        self.assertEqual(ids.free_range(records, {0, 1000}, 100000, 500000), 165536)
        self.assertEqual(ids.free_range(records, {170000}, 100000, 500000), 170001)
        with self.assertRaises(ValueError):
            ids.free_range(records, set(), 100000, 200000)

    def test_reuses_only_a_safe_existing_root_allocation(self):
        records = ids.allocations("user:100000:65536\nroot:300000:65536\n")
        self.assertEqual(ids.existing_range(records, {1000}, {"root"}), 300000)
        for records, occupied in (
            (ids.allocations("root:100000:65536\nuser:165535:65536\n"), set()),
            (ids.allocations("root:100000:65536\n"), {101000}),
            (ids.allocations("0:100000:65536\nroot:100000:65536\n"), set()),
        ):
            with self.assertRaises(ValueError):
                ids.existing_range(records, occupied, {"root"})

    def test_validates_both_account_databases_and_the_pool(self):
        names, uids, gids = ids.accounts("root:x:0:0::/:/bin/sh\nu:x:1000:300000::/:/bin/sh\n",
                                       "root:x:0:\ng:x:400000:\n")
        self.assertEqual(names, {"root"})
        self.assertEqual(uids, {0, 1000})
        self.assertEqual(gids, {0, 300000, 400000})
        self.assertFalse(ids.is_root("1000", {"1000"}))
        for text in ("", "SUB_UID_MIN 100000\nSUB_UID_MAX 100001\n",
                     "SUB_UID_MIN 100000\nSUB_UID_MIN 200000\nSUB_UID_MAX 500000\n"):
            with self.assertRaises(ValueError):
                ids.pool_limits(text, "subuid")
        for text in ("root:0:65536", "root:4294960000:65536", "root:1:-1",
                     "root:100000:65536\nbroken"):
            with self.assertRaises(ValueError):
                ids.allocations(text)

    def test_configuration_restores_contents_modes_and_original_absence(self):
        with tempfile.TemporaryDirectory(prefix="mxc-bwrap-ci-ids-") as directory:
            root = Path(directory)
            etc, backup = root / "etc", root / "backup"
            etc.mkdir()
            original = b"# existing reservation\nuser:100000:65536"
            (etc / "subuid").write_bytes(original)
            (etc / "subuid").chmod(0o640)
            (etc / "login.defs").write_text(
                "SUB_UID_MIN 100000\nSUB_UID_MAX 500000\n"
                "SUB_GID_MIN 300000\nSUB_GID_MAX 500000\n"
            )
            with mock.patch.object(ids, "require_root_file"):
                ids.configure(etc, backup, ({"root"}, {0, 1000}, {0, 300000}))
            self.assertEqual((etc / "subuid").read_text(), original.decode() + "\n0:165536:65536\n")
            self.assertEqual((etc / "subgid").read_text(), "0:300001:65536\n")
            ids.restore(etc, backup)
            self.assertEqual((etc / "subuid").read_bytes(), original)
            self.assertEqual((etc / "subuid").stat().st_mode & 0o777, 0o640)
            self.assertFalse((etc / "subgid").exists())
            self.assertFalse(backup.exists())

    def test_partial_setup_failure_restores_both_files(self):
        with tempfile.TemporaryDirectory(prefix="mxc-bwrap-ci-ids-") as directory:
            root = Path(directory)
            etc, backup = root / "etc", root / "backup"
            etc.mkdir()
            for kind in ids.KINDS:
                (etc / kind).write_text("# original\n")
            (etc / "login.defs").write_text(
                "SUB_UID_MIN 100000\nSUB_UID_MAX 500000\n"
                "SUB_GID_MIN 300000\nSUB_GID_MAX 500000\n"
            )
            real_open = os.open

            def failing_open(path, flags, mode=0o777, **kwargs):
                if Path(path) == etc / "subgid" and flags & os.O_TRUNC:
                    raise OSError("fixture: second allocation write failed")
                return real_open(path, flags, mode, **kwargs)

            with mock.patch.object(ids, "require_root_file"), \
                    mock.patch.object(ids.os, "open", side_effect=failing_open):
                with self.assertRaisesRegex(OSError, "second allocation"):
                    ids.configure(etc, backup, ({"root"}, {0}, {0}))
            for kind in ids.KINDS:
                self.assertEqual((etc / kind).read_text(), "# original\n")
            self.assertFalse(backup.exists())

    def test_existing_root_ranges_need_no_new_allocation_or_pool_defaults(self):
        with tempfile.TemporaryDirectory(prefix="mxc-bwrap-ci-ids-") as directory:
            root = Path(directory)
            etc, backup = root / "etc", root / "backup"
            etc.mkdir()
            for kind, base in zip(ids.KINDS, (200000, 400000)):
                (etc / kind).write_text(f"root:{base}:65536\n")
            with mock.patch.object(ids, "require_root_file"):
                ids.configure(etc, backup, ({"root"}, {0, 1000}, {0, 1000}))
            for kind, base in zip(ids.KINDS, (200000, 400000)):
                self.assertEqual((etc / kind).read_text(), f"root:{base}:65536\n")
            ids.restore(etc, backup)

    def test_interruption_before_the_manifest_does_not_change_live_configuration(self):
        with tempfile.TemporaryDirectory(prefix="mxc-bwrap-ci-ids-") as directory:
            root = Path(directory)
            etc, backup = root / "etc", root / "backup"
            etc.mkdir()
            backup.mkdir(mode=0o700)
            (etc / "subuid").write_text("unchanged")
            (backup / "subuid").write_text("snapshot")
            (backup / "originals.pending.json").write_text('{"subuid":')
            ids.restore(etc, backup)
            self.assertEqual((etc / "subuid").read_text(), "unchanged")
            self.assertFalse(backup.exists())

    def test_cleanup_after_an_interrupted_setup_keeps_recovery_evidence_on_failure(self):
        with tempfile.TemporaryDirectory(prefix="mxc-bwrap-ci-ids-") as directory:
            root = Path(directory)
            etc, backup = root / "etc", root / "backup"
            etc.mkdir()
            backup.mkdir(mode=0o700)
            (etc / "subuid").write_text("changed")
            (backup / "subuid").write_text("original")
            (backup / "originals.json").write_text(json.dumps({"subuid": True, "subgid": False}))
            with mock.patch.object(ids.subprocess, "run", side_effect=OSError("restore failed")):
                with self.assertRaisesRegex(RuntimeError, "backups retained"):
                    ids.restore(etc, backup)
            self.assertTrue((backup / "subuid").exists())
            ids.restore(etc, backup)
            self.assertEqual((etc / "subuid").read_text(), "original")

    def test_command_refuses_a_non_ci_host_before_touching_files(self):
        with tempfile.TemporaryDirectory(prefix="mxc-bwrap-ci-ids-") as directory:
            backup = Path(directory) / "backup"
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "setup", "--disposable-ci-host",
                 "--backup-directory", str(backup)],
                env={**os.environ, "GITHUB_ACTIONS": "false"},
                capture_output=True, text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("only for explicitly designated disposable", result.stderr)
            self.assertFalse(backup.exists())


if __name__ == "__main__":
    unittest.main()
