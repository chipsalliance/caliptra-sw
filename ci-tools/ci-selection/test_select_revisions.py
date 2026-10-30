# Licensed under the Apache-2.0 license

import unittest

from select_revisions import select_revisions


class TestRevisionSelection(unittest.TestCase):

    def test_only_21(self):
        self.assertEqual(
            select_revisions(["hw/rev-2_1/registers/src/lib.rs"]),
            ["2.1"],
        )

    def test_only_latest(self):
        self.assertEqual(
            select_revisions(["hw/latest/registers/src/lib.rs"]),
            ["latest"],
        )

    def test_both_hardware_revisions(self):
        self.assertEqual(
            select_revisions([
                "hw/rev-2_1/registers/src/lib.rs",
                "hw/latest/registers/src/lib.rs",
            ]),
            ["latest", "2.1"],
        )

    def test_shared_firmware(self):
        self.assertEqual(
            select_revisions(["rom/dev/src/main.rs"]),
            ["latest", "2.1"],
        )

    def test_ci_configuration(self):
        self.assertEqual(
            select_revisions([".github/workflows/build-test.yml"]),
            ["latest", "2.1"],
        )

    def test_unknown_path(self):
        self.assertEqual(
            select_revisions(["new-component/src/lib.rs"]),
            ["latest", "2.1"],
        )

    def test_empty_changes(self):
        self.assertEqual(
            select_revisions([]),
            ["latest", "2.1"],
        )
    def test_mixed_revision_and_shared_changes(self):
        self.assertEqual(
            select_revisions([
                "hw/rev-2_1/registers/src/lib.rs",
                "drivers/src/lib.rs",
            ]),
            ["latest", "2.1"],
        )

if __name__ == "__main__":
    unittest.main()
