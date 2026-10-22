"""Static checks over the whole package: pyflakes reports nothing -- no undefined name (a
NameError on a path no test runs: the writer flow's `imp`, TODO #132), no definition that
shadows another (a test class defined twice runs only once), no unused import or local.
A finding fails the suite (TODO #136)."""
import importlib.util
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestPyflakes(unittest.TestCase):

    def test_no_findings(self):
        self.assertIsNotNone(importlib.util.find_spec("pyflakes"),
                             "pyflakes is not installed in this interpreter (requirements.txt)")
        run = subprocess.run([sys.executable, "-m", "pyflakes", ROOT],
                             capture_output=True, text=True)
        self.assertEqual(run.stdout + run.stderr, "")


if __name__ == "__main__":
    unittest.main()
