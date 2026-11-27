# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os
import stat
import tempfile
import unittest
from types import SimpleNamespace

from ansible_collections.community.internal_test_tools.tests.unit.compat.mock import MagicMock, patch
from ansible_collections.pfsensible.core.plugins.module_utils.pfsense import PFSenseModule


class TestPFSenseDebugFile(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = directory.name
        self.path = os.path.join(self.directory, "pfsense.debug")
        debug_file = patch.object(PFSenseModule, "DEBUG_FILE", self.path)
        debug_file.start()
        self.addCleanup(debug_file.stop)

    def leave_previous_trace(self):
        """A trace written by an earlier version, readable by all"""
        with open(self.path, "w") as previous:
            previous.write("old secrets")
        os.chmod(self.path, 0o644)

    def test_no_trace_by_default(self):
        for module in (None, SimpleNamespace(_debug=False)):
            self.leave_previous_trace()
            debug = PFSenseModule._open_debug(module)
            self.assertEqual(debug.name, os.devnull)
            debug.close()
            self.assertFalse(os.path.lexists(self.path))

    def test_trace_in_debug_mode(self):
        self.leave_previous_trace()
        debug = PFSenseModule._open_debug(SimpleNamespace(_debug=True))
        debug.write("trace")
        debug.close()
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        with open(self.path) as written:
            self.assertEqual(written.read(), "trace")

    def test_symlink_not_followed(self):
        target = os.path.join(self.directory, "target")
        with open(target, "w") as other:
            other.write("untouched")
        os.symlink(target, self.path)
        debug = PFSenseModule._open_debug(SimpleNamespace(_debug=True))
        debug.write("trace")
        debug.close()
        self.assertFalse(os.path.islink(self.path))
        with open(target) as other:
            self.assertEqual(other.read(), "untouched")

    def test_cannot_create(self):
        module = MagicMock(_debug=True)
        with patch.object(PFSenseModule, "DEBUG_FILE", os.path.join(self.directory, "missing", "pfsense.debug")):
            debug = PFSenseModule._open_debug(module)
        self.assertEqual(debug.name, os.devnull)
        debug.close()
        module.warn.assert_called_once()
