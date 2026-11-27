# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from ansible.errors import AnsibleActionFail
from ansible.playbook.task import Task
from ansible_collections.pfsensible.core.plugins.action.pfsense_system_patch import ActionModule, NormalAction


class TestPFSenseSystemPatchAction(TestCase):
    def setUp(self):
        task = Task()
        task.args = {"uniqid": "banner", "src": "banner.patch"}
        self.task = task
        self.action = ActionModule(task, None, None, None, None, None)
        dispatcher = patch.object(NormalAction, "run", autospec=True, side_effect=lambda action, *_: action._task.args)
        self.dispatch = dispatcher.start()
        self.addCleanup(dispatcher.stop)

    def test_default_resolves_controller_path_and_passes_text(self):
        content = "some UTF-8 patch text ä\r\n"
        with TemporaryDirectory() as directory:
            source = Path(directory) / "banner.patch"
            source.write_bytes(content.encode("utf-8"))
            with patch.object(self.action, "_find_needle", return_value=str(source)) as find:
                self.assertEqual(self.action.run(), {"uniqid": "banner", "content": content})
        find.assert_called_once_with("files", "banner.patch")
        self.assertEqual(self.task.args, {"uniqid": "banner", "src": "banner.patch"})

    def test_remote_src_bypasses_controller_lookup(self):
        self.task.args["remote_src"] = "yes"
        with patch.object(self.action, "_find_needle") as find:
            self.assertEqual(self.action.run(), self.task.args)
        find.assert_not_called()

    def test_content_and_src_are_left_for_module_validation(self):
        self.task.args["content"] = "explicit content"
        with patch.object(self.action, "_find_needle") as find:
            self.assertEqual(self.action.run(), self.task.args)
        find.assert_not_called()

    def test_invalid_utf8_fails_before_dispatch(self):
        with TemporaryDirectory() as directory:
            source = Path(directory) / "banner.patch"
            source.write_bytes(b"\xff")
            with patch.object(self.action, "_find_needle", return_value=str(source)):
                with self.assertRaisesRegex(AnsibleActionFail, "Unable to read controller patch file"):
                    self.action.run()
        self.dispatch.assert_not_called()
