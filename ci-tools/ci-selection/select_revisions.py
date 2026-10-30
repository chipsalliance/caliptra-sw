#!/usr/bin/env python3
# Licensed under the Apache-2.0 license
"""Select Caliptra hardware revisions affected by changed paths."""

import json
import sys

ALL_REVISIONS = ("latest", "2.1")


def select_revisions(paths):
    """Return both revisions unless changes are revision-specific."""
    selected = set()

    for path in paths:
        if path.startswith("hw/rev-2_1/"):
            selected.add("2.1")
        elif path.startswith("hw/latest/"):
            selected.add("latest")
        else:
            # Shared or unknown files may affect both revisions.
            return list(ALL_REVISIONS)

    # An empty change list must not accidentally skip CI.
    if not selected:
        return list(ALL_REVISIONS)

    return [rev for rev in ALL_REVISIONS if rev in selected]


if __name__ == "__main__":
    print(json.dumps(select_revisions(sys.argv[1:])))
