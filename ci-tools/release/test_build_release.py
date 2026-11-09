# Licensed under the Apache-2.0 license

"""Check packaging selection with stub build tools and real RTL hashing."""

import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import textwrap
import unittest
import zipfile


SCRIPT = Path(__file__).with_name("build_release.sh").resolve()
WORKFLOW = SCRIPT.parents[2] / ".github/workflows/nightly-release.yml"

CARGO = """#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
profile = os.environ["CALIPTRA_HW_REV"]
with Path("cargo-calls.jsonl").open("a") as f:
    f.write(json.dumps({"profile": profile, "args": args}) + "\\n")
fake = "--fake-rom" in args
for flag in ("--rom-no-log", "--rom-with-log", "--fw", "--fake-rom", "--fake-fw"):
    if flag in args:
        p = Path(args[args.index(flag) + 1])
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(f"{profile}:{flag}\\n")
target = Path("target/riscv32imc-unknown-none-elf/firmware")
target.mkdir(parents=True, exist_ok=True)
for name in ("caliptra-rom", "caliptra-fmc", "caliptra-runtime"):
    (target / name).write_text(f"{profile}:{fake}:{name}\\n")
"""

GIT = """#!/usr/bin/env python3
import sys
args = sys.argv[1:]
if args == ["rev-parse", "HEAD"]:
    print("3" * 40)
elif args == ["-C", "hw/rev-2_1/caliptra-ss", "rev-parse", "HEAD:third_party/caliptra-rtl"]:
    print("1" * 40)
elif args == ["-C", "hw/latest/caliptra-ss", "rev-parse", "HEAD:third_party/caliptra-rtl"]:
    print("2" * 40)
else:
    raise SystemExit(f"Unexpected git invocation: {args}")
"""

ZIP = """#!/usr/bin/env python3
import sys, zipfile
from pathlib import Path
if len(sys.argv) < 4 or sys.argv[1] not in ("-r", "-qr"):
    raise SystemExit(f"Unexpected zip invocation: {sys.argv[1:]}")
with zipfile.ZipFile(sys.argv[2], "w", zipfile.ZIP_DEFLATED) as archive:
    for argument in sys.argv[3:]:
        path = Path(argument)
        if path.is_file():
            archive.write(path, path.as_posix())
        else:
            for child in sorted(path.rglob("*")):
                if child.is_file():
                    archive.write(child, child.as_posix())
"""


class PackagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="caliptra-nightly21-check-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        tools = self.root / "tools"
        tools.mkdir()
        for name, contents in (("cargo", CARGO), ("git", GIT), ("zip", ZIP)):
            path = tools / name
            path.write_text(contents)
            path.chmod(0o755)
        self.env = os.environ.copy()
        self.env["PATH"] = str(tools) + os.pathsep + self.env["PATH"]
        self.env.pop("CALIPTRA_HW_REV", None)
        self.env.pop("CARGO_TARGET_DIR", None)
        for profile, directory in (("2.1", "rev-2_1"), ("latest", "latest")):
            rtl = self.root / "hw" / directory / "caliptra-ss/third_party/caliptra-rtl"
            (rtl / "src").mkdir(parents=True)
            (rtl / "docs").mkdir()
            for name in ("exclude1.sv", "exclude2.sv", "keep.sv"):
                (rtl / "src" / name).write_text(f"{profile}:{name}\n")
            (rtl / "docs/CaliptraIntegrationSpecification.md").write_text(
                "# Integration\n"
                "## Caliptra integrator custom RTL file list\n"
                "| [one](../src/exclude1.sv) | customizable |\n"
                "| [two](../src/exclude2.sv) | customizable |\n"
                "# Next\n"
            )
        for directory in ("libcaliptra", "hw/fpga", "release"):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        (self.root / "release/sentinel").write_text("keep until inputs are validated")
        (self.root / "libcaliptra/library.txt").write_text("library")
        (self.root / "hw/fpga/board.txt").write_text("board")

    def invoke(self, profile=None, args=("smoke-test",)):
        if profile is not None:
            self.env["CALIPTRA_HW_REV"] = profile
        return subprocess.run(
            ["bash", str(SCRIPT), *args],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
        )

    def check_package(self, profile):
        expected = profile if profile is not None else "latest"
        result = self.invoke(profile)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = [
            json.loads(line)
            for line in (self.root / "cargo-calls.jsonl").read_text().splitlines()
        ]
        self.assertEqual(len(calls), 5)
        self.assertTrue(all(call["profile"] == expected for call in calls))
        with zipfile.ZipFile(self.root / "release/release.zip") as archive:
            notes = archive.read("release_notes.txt").decode()
            self.assertIn(f"Caliptra-HW Target: {expected}\n", notes)
            rtl_revision = ("1" if expected == "2.1" else "2") * 40
            self.assertIn(f"Caliptra-RTL Rev: {rtl_revision}\n", notes)
            contents = f"{expected}:keep.sv\n".encode()
            self.assertEqual(archive.read("caliptra-rtl/src/keep.sv"), contents)
            digest = hashlib.sha384(contents).hexdigest()
            self.assertIn(f"RTL hash (see rtl_hash.sh): {digest}\n", notes)
            self.assertEqual(archive.read("rtl_hash_file_list.txt"), b"keep.sv\n")
            for name in ("caliptra-rom.elf", "caliptra-fmc.elf", "caliptra-runtime.elf"):
                self.assertTrue(archive.read(name).startswith(f"{expected}:False:".encode()))
            self.assertNotIn("sentinel", archive.namelist())

    def test_pinned_21(self):
        self.check_package("2.1")

    def test_explicit_latest(self):
        self.check_package("latest")

    def test_unset_preserves_latest_default(self):
        self.check_package(None)

    def test_invalid_profiles_fail_before_deleting_output(self):
        for profile in ("2.0", "2.2", "", "invalid"):
            with self.subTest(profile=profile):
                result = self.invoke(profile)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Unsupported CALIPTRA_HW_REV", result.stderr)
                self.assertTrue((self.root / "release/sentinel").exists())
                self.assertFalse((self.root / "cargo-calls.jsonl").exists())

    def test_missing_rtl_fails_before_deleting_output(self):
        shutil.rmtree(self.root / "hw/rev-2_1/caliptra-ss/third_party/caliptra-rtl/src")
        result = self.invoke("2.1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Missing RTL", result.stderr)
        self.assertTrue((self.root / "release/sentinel").exists())
        self.assertFalse((self.root / "cargo-calls.jsonl").exists())

    def test_missing_tag_fails_before_deleting_output(self):
        result = self.invoke("2.1", args=())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Usage:", result.stdout)
        self.assertTrue((self.root / "release/sentinel").exists())


def workflow_run_step(name):
    lines = WORKFLOW.read_text().splitlines()
    start = lines.index(f"      - name: {name}") + 1
    while lines[start] != "        run: |":
        if lines[start] and not lines[start].startswith("        "):
            raise AssertionError(f"Missing run block for {name}")
        start += 1
    script = []
    for line in lines[start + 1:]:
        if line and not line.startswith("          "):
            break
        script.append(line)
    return textwrap.dedent("\n".join(script)) + "\n"


class NightlyTagTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="caliptra-nightly-tag-check-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        tools = self.root / "tools"
        tools.mkdir()
        date = tools / "date"
        date.write_text(
            "#!/bin/sh\n"
            '[ "$#" = 1 ] && [ "$1" = "+%Y%m%d" ] || exit 1\n'
            "echo 20261110\n"
        )
        date.chmod(0o755)
        zip_tool = tools / "zip"
        zip_tool.write_text(ZIP)
        zip_tool.chmod(0o755)
        self.env = os.environ.copy()
        for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
            self.env.pop(key, None)
        self.env["PATH"] = str(tools) + os.pathsep + self.env["PATH"]
        self.env["GITHUB_OUTPUT"] = str(self.root / "github-output")
        self.env["GITHUB_WORKSPACE"] = str(self.repo)
        self.git("init", "--quiet", "-b", "main")
        self.commit()

    def git(self, *args):
        result = subprocess.run(
            ["git", *args], cwd=self.repo, env=self.env,
            text=True, capture_output=True, check=True,
        )
        return result.stdout.strip()

    def commit(self):
        self.git(
            "-c", "user.name=Nightly Test", "-c", "user.email=test@example.com",
            "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
            "commit", "--quiet", "--allow-empty", "-m", "Nightly fixture",
            "-m", "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>",
        )

    def run_script(self, script):
        result = subprocess.run(
            ["bash", "-e", "-o", "pipefail", "-c", script],
            cwd=self.repo, env=self.env, text=True, capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def find_release(self):
        output = Path(self.env["GITHUB_OUTPUT"])
        output.write_text("")
        refs_before = self.git("for-each-ref", "--format=%(refname) %(objectname)")
        self.run_script(workflow_run_step("Find latest release"))
        self.assertEqual(
            self.git("for-each-ref", "--format=%(refname) %(objectname)"), refs_before
        )
        values = dict(line.split("=", 1) for line in output.read_text().splitlines())
        self.assertEqual(values["release_ref"], self.git("rev-parse", "HEAD"))
        return values

    def test_new_namespace_ignores_other_release_families(self):
        for tag in ("release_v20261109_0", "release_v20261109_0-2.0",
                    "release_v20261109_0-2.2"):
            self.git("tag", tag)
        values = self.find_release()
        self.assertEqual(values["new_release_tag"], "release_v20261110_0-2.1")
        self.assertEqual(values["create_release"], "true")

    def test_falls_back_to_legacy_2x(self):
        self.git("tag", "release_v20261107_0-2.x")
        values = self.find_release()
        self.assertEqual(values["create_release"], "false")
        self.commit()
        self.git("tag", "release_v20261109_0-2.2")
        self.assertEqual(self.find_release()["create_release"], "true")

    def test_prefers_21_over_newer_legacy_tags(self):
        self.git("tag", "release_v20261108_0-2.1")
        self.commit()
        self.git("tag", "release_v20261109_0-2.x")
        self.assertEqual(self.find_release()["create_release"], "true")

    def test_latest_21_tag_uses_numeric_index_order(self):
        self.git("tag", "release_v20261109_9-2.1")
        self.commit()
        self.git("tag", "release_v20261109_10-2.1")
        self.assertEqual(self.find_release()["create_release"], "false")

    def test_collision_check_matches_only_exact_21_tag(self):
        for tag in ("release_v20261110_0-2.1", "release_v20261110_1-2.1",
                    "release_v20261110_2-2.x", "release_v20261110_2-2a1",
                    "release_v20261110_2-2.10"):
            self.git("tag", tag)
        self.assertEqual(
            self.find_release()["new_release_tag"], "release_v20261110_2-2.1"
        )

    def test_unchanged_21_commit_reports_no_new_release(self):
        self.git("tag", "release_v20261109_0-2.1")
        self.assertEqual(self.find_release()["create_release"], "false")

    def test_generated_tag_is_used_for_zip_names_and_metadata(self):
        tag = self.find_release()["new_release_tag"]
        expression = "${{ needs.find-latest-release-2-x.outputs.new_release_tag }}"
        release = self.repo / "release"
        release.mkdir()
        (release / "release.zip").write_bytes(b"release fixture")
        moves = [
            line for line in workflow_run_step("Generate release zip").splitlines()
            if line.startswith("mv ")
        ]
        self.assertEqual(len(moves), 1)
        self.run_script(moves[0].replace(expression, tag))
        self.assertTrue((release / f"caliptra_{tag}.zip").exists())

        artifacts = self.root / "artifacts"
        (artifacts / "suite").mkdir(parents=True)
        (artifacts / "suite/results.txt").write_text("test results")
        script = workflow_run_step("Package test artifacts per artifact directory")
        self.assertIn("cd /tmp/artifacts", script)
        script = script.replace(expression, tag).replace(
            "cd /tmp/artifacts", f"cd {shlex.quote(str(artifacts))}"
        )
        self.run_script(script)
        with zipfile.ZipFile(release / f"test_artifacts_{tag}_suite.zip") as archive:
            self.assertEqual(archive.read("suite/results.txt"), b"test results")

        metadata = self.root / "release-info"
        script = workflow_run_step("Write artifact to workflow with release info")
        self.assertIn("/tmp/release-info-2-1", script)
        script = script.replace(expression, tag).replace(
            "/tmp/release-info-2-1", shlex.quote(str(metadata))
        )
        self.run_script(script)
        self.assertEqual((metadata / "tag-name").read_text(), tag + "\n")
        self.assertEqual(
            (metadata / "zip-file-name").read_text(), f"caliptra_{tag}.zip\n"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
