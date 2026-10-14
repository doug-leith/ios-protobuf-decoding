"""The test gate must reach every test file.

A regression once shipped because a hand-kept subset of test modules did not run
`tests.test_synthetic_fixtures`.  The gate is pytest over pytest.ini's testpaths; these tests
pin that it cannot quietly narrow.
"""
import configparser
import os
import re
import unittest

_TESTS = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_TESTS))


class TestRunnerWiring(unittest.TestCase):

    def test_pytest_ini_collects_this_tests_directory(self):
        cp = configparser.ConfigParser()
        cp.read(os.path.join(_ROOT, 'pytest.ini'))
        testpaths = cp['pytest']['testpaths'].split()
        self.assertIn('apple_protobuf_extractor/tests', testpaths)
        self.assertEqual(cp['pytest']['python_files'].strip(), 'test_*.py')

    def test_every_test_file_matches_the_collection_pattern(self):
        stray = [f for f in os.listdir(_TESTS)
                 if f.endswith('.py') and re.search(r'(^|_)test', f) and not f.startswith('test_')
                 and f not in ('conftest.py',)]
        self.assertEqual(stray, [], 'files that look like tests but pytest would not collect')


if __name__ == '__main__':
    unittest.main()
