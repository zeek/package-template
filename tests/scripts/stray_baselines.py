#!/usr/bin/env python3
"""Helper scripts to identify baselines without matching test"""

import os
import re
import subprocess
import sys

TEST_DIR = os.path.realpath(__file__ + "/../../")

if __name__ == "__main__":
    try:
        available_tests = {
            x.decode("utf-8")
            for x in subprocess.check_output(
                ["btest", "-l", "-c", TEST_DIR + "/btest.cfg"]
            ).splitlines()
        }

        test_baselines = set(os.listdir(TEST_DIR + "/Baseline"))
    except subprocess.CalledProcessError:
        # We need to run against at least btest-0.70 in order to list tests,
        # but this is not available in the latest release, yet.
        #
        # TODO(bbannier): Remove this try/except once we have that BTest
        # version available.
        print("Cannot list tests with 'btest -l', cannot run", file=sys.stderr)
        sys.exit(0)

    stray_tests = sorted(
        filter(
            lambda cand: not re.match("\\d$", cand.split("-")[-1]),
            test_baselines.difference(available_tests),
        )
    )

    if stray_tests:
        print(
            f"No matching tests for the following baselines:\n\n{os.linesep.join(stray_tests)}",
            file=sys.stderr,
        )
        sys.exit(1)
