# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import base64
import io
import json
from pathlib import Path
import re
from unittest.mock import patch
import xml.etree.ElementTree as ET

from parameterized import parameterized

from ansible_collections.community.internal_test_tools.tests.unit.plugins.modules.utils import set_module_args
from ansible_collections.pfsensible.core.plugins.module_utils import system_patch
from ansible_collections.pfsensible.core.plugins.modules import pfsense_system_patch
from .pfsense_module import TestPFSenseModule


DESCR = 'Lab\'s "banner" patch'
CONTENT = "--- a/banner\n+++ b/banner\n@@ -1 +1 @@\n-Welcome\n+Welcome to the lab\n"
COMMIT = "abcdef123456"
URL = f"https://github.com/pfsense/pfsense/commit/{COMMIT}.patch"


class TestPFSenseSystemPatchModule(TestPFSenseModule):
    module = pfsense_system_patch

    def setUp(self):
        super(TestPFSenseSystemPatchModule, self).setUp()
        self.config = Path(self.tmp_file)
        self.package_exists = self.start_mock(patch.object(system_patch, "isfile", return_value=True))
        self.download = self.start_mock(patch.object(system_patch, "open_url", return_value=io.BytesIO(CONTENT.encode())))
        self.run_command = self.start_mock(patch("ansible.module_utils.basic.AnsibleModule.run_command", return_value=(0, "", "")))

    def start_mock(self, mock_patch):
        mock = mock_patch.start()
        self.addCleanup(mock_patch.stop)
        return mock

    def run_module(self, changed=False, **params):
        with set_module_args(dict({"descr": DESCR}, **params)):
            return self.changed(changed)

    def fail_module(self, **params):
        with set_module_args(dict({"descr": DESCR}, **params)):
            return self.failed()

    def entry(self):
        return ET.parse(self.config).find("installedpackages/patches/item")

    def test_create_update_check_mode_and_delete(self):
        initial = self.config.read_bytes()
        self.run_module(changed=True, content=CONTENT, auto_apply=True, _ansible_check_mode=True)
        self.assertEqual(self.config.read_bytes(), initial)
        self.run_module(changed=True, content=CONTENT.replace("\n", "\r\n"), auto_apply=True)
        entry = self.entry()
        self.assertEqual(entry.findtext("descr"), DESCR)
        self.assertEqual(base64.b64decode(entry.findtext("patch")), CONTENT.encode())
        self.assertEqual(entry.findtext("pathstrip"), "2")
        self.assertEqual(entry.findtext("basedir"), "/")
        self.assertIsNotNone(entry.find("ignorewhitespace"))
        self.assertIsNotNone(entry.find("autoapply"))
        uniqid = entry.findtext("uniqid")
        self.assertTrue(uniqid)
        for field in ("content", "src", "remote_src", "run", "auto_apply", "ignore_whitespace"):
            self.assertIsNone(entry.find(field))
        self.assertEqual([elt.text for elt in ET.parse(self.config).findall("system/earlyshellcmd")], [system_patch.BOOT_COMMAND])

        saved = self.config.read_bytes()
        self.run_module(content=CONTENT, auto_apply=True)
        self.assertEqual(self.config.read_bytes(), saved)
        self.run_module(changed=True, pathstrip=0, ignore_whitespace=False)
        entry = self.entry()
        self.assertEqual(entry.findtext("uniqid"), uniqid)
        self.assertEqual(entry.findtext("pathstrip"), "0")
        self.assertIsNone(entry.find("ignorewhitespace"))
        self.assertIsNotNone(entry.find("autoapply"))
        self.assertEqual(base64.b64decode(entry.findtext("patch")), CONTENT.encode())
        self.run_module(changed=True, auto_apply=False)
        self.assertIsNone(self.entry().find("autoapply"))
        self.run_module(auto_apply=False)

        saved = self.config.read_bytes()
        self.run_module(changed=True, state="absent", _ansible_check_mode=True)
        self.assertEqual(self.config.read_bytes(), saved)
        self.run_module(changed=True, state="absent")
        self.assertIsNone(self.entry())
        self.run_module(state="absent")
        self.assertEqual(ET.parse(self.config).findtext("system/earlyshellcmd"), system_patch.BOOT_COMMAND)
        self.run_command.assert_not_called()

    def test_file_source_preserves_bytes(self):
        contents = CONTENT.replace("\n", "\r\n").encode()
        src = self.config.with_suffix(".patch")
        src.write_bytes(contents)
        self.run_module(changed=True, src=str(src), remote_src=True, basedir=str(src.parent), ignore_whitespace=False)
        self.assertEqual(base64.b64decode(self.entry().findtext("patch")), contents)
        self.assertIsNone(self.entry().find("ignorewhitespace"))
        self.run_module(src=str(src), remote_src=True)
        self.download.assert_not_called()

    def test_create_rename_and_remove_by_uniqid(self):
        self.run_module(changed=True, uniqid="banner-a", content=CONTENT)
        self.run_module(changed=True, uniqid="banner-b", content=CONTENT)
        self.run_module(uniqid="banner-b", descr=None)
        self.assertIn("multiple patches", self.fail_module(state="absent")["msg"])

        original = self.config.read_bytes()
        self.run_module(changed=True, uniqid="banner-b", descr="Renamed banner", _ansible_check_mode=True)
        self.assertEqual(self.config.read_bytes(), original)
        result = self.run_module(changed=True, uniqid="banner-b", descr="Renamed banner")
        self.assertEqual(result["commands"], ["update system_patch 'banner-b' set descr='Renamed banner'"])
        self.run_module(uniqid="banner-b", descr="Renamed banner")
        entries = ET.parse(self.config).findall("installedpackages/patches/item")
        self.assertEqual([(elt.findtext("uniqid"), elt.findtext("descr")) for elt in entries], [("banner-a", DESCR), ("banner-b", "Renamed banner")])

        self.run_module(changed=True, uniqid="banner-b", descr=None, state="absent", run="revert")
        self.run_module(uniqid="banner-b", descr=None, state="absent", run="revert")
        self.assertEqual(self.entry().findtext("uniqid"), "banner-a")
        self.run_command.assert_called_once()

    def test_duplicate_ids_are_ambiguous(self):
        self.run_module(changed=True, uniqid="banner", content=CONTENT)
        tree = ET.parse(self.config)
        entries = tree.find("installedpackages/patches")
        entries.append(entries.find("item"))
        tree.write(self.config)
        self.assertIn("multiple patches with uniqid", self.fail_module(uniqid="banner", descr=None, state="absent")["msg"])
        self.run_command.assert_not_called()

    def test_url_fetch_reuses_saved_content_and_handles_change(self):
        self.run_module(changed=True, location=COMMIT)
        self.download.assert_called_once_with(URL)
        self.assertEqual(self.entry().findtext("location"), URL)
        self.run_module(location=URL.removesuffix(".patch"))
        self.download.assert_called_once()
        self.download.reset_mock()
        replacement = "https://patches.example.org/banner.patch"
        self.download.return_value = io.BytesIO(CONTENT.replace("+Welcome", "+Hello").encode())
        self.run_module(changed=True, location=replacement)
        self.download.assert_called_once_with(replacement)
        self.assertIn(b"+Hello", base64.b64decode(self.entry().findtext("patch")))
        self.run_module(changed=True, location="", content=CONTENT)
        self.assertEqual(self.entry().findtext("location"), "")
        self.assertEqual(base64.b64decode(self.entry().findtext("patch")), CONTENT.encode())
        self.download.assert_called_once()

    def test_failed_download_preserves_existing_entry(self):
        self.run_module(changed=True, content=CONTENT)
        before = self.config.read_bytes()
        self.download.side_effect = system_patch.URLConnectionError("certificate verification failed")
        result = self.fail_module(location=URL)
        self.assertIn("certificate verification failed", result["msg"])
        self.assertEqual(self.config.read_bytes(), before)

    def test_apply_in_check_mode_and_retry_noop(self):
        self.run_module(changed=True, content=CONTENT)
        before = self.config.read_bytes()
        self.run_module(changed=True, run="apply", _ansible_check_mode=True)
        method = self.run_command.call_args
        self.assertEqual(method.args, ("/usr/local/bin/php",))
        command = method.kwargs["data"]
        self.assertIn(f'require_once("{system_patch.PATCHES_INC}");', command)
        self.assertIn("patch_test_apply($patch)", command)
        self.assertIn("patch_test_revert($patch)", command)
        self.assertNotIn("exit(patch_apply($patch)", command)
        encoded = re.search(r'base64_decode\("([^"]+)"\)', command).group(1)
        payload = json.loads(base64.b64decode(encoded))
        self.assertEqual(base64.b64decode(payload["patch"]), CONTENT.encode())
        self.assertEqual(payload["basedir"], "/")
        self.assertEqual(payload["pathstrip"], "2")
        self.assertTrue(payload["ignorewhitespace"])

        result = self.run_module(changed=True, run="apply")
        self.assertIn("exit(patch_apply($patch) ? 0 : 12);", self.run_command.call_args.kwargs["data"])
        self.assertEqual(result["commands"], [f"apply system_patch '{DESCR}'"])
        self.assertEqual(self.config.read_bytes(), before)
        self.run_command.return_value = (10, "", "")
        self.run_module(run="apply")
        self.run_module(run="apply", _ansible_check_mode=True)

    def test_failed_preflight_does_not_create_entry(self):
        before = self.config.read_bytes()
        self.run_command.return_value = (11, "", "")
        result = self.fail_module(content=CONTENT, run="apply")
        self.assertIn("cannot apply cleanly", result["msg"])
        self.assertFalse(result["changed"])
        self.assertEqual(self.config.read_bytes(), before)
        self.run_command.assert_called_once()

    def test_revert_before_deleting_and_keep_entry_on_failure(self):
        self.run_module(changed=True, content=CONTENT)
        before = self.config.read_bytes()
        self.run_module(changed=True, state="absent", run="revert", _ansible_check_mode=True)
        self.assertNotIn("exit(patch_revert($patch)", self.run_command.call_args.kwargs["data"])
        self.assertEqual(self.config.read_bytes(), before)

        self.run_command.return_value = (12, "", "patch failed")
        result = self.fail_module(state="absent", run="revert")
        self.assertIn("Failed to revert", result["msg"])
        self.assertEqual(self.config.read_bytes(), before)

        def revert(command, *, data):
            self.assertEqual(self.config.read_bytes(), before)
            self.assertIn("exit(patch_revert($patch) ? 0 : 12);", data)
            return 0, "", ""

        self.run_command.side_effect = revert
        self.run_module(changed=True, state="absent", run="revert")
        self.assertIsNone(self.entry())
        self.run_command.reset_mock()
        self.run_module(state="absent", run="revert")
        self.run_command.assert_not_called()

    def test_missing_package(self):
        self.package_exists.return_value = False
        self.assertIn("package must be installed", self.fail_module(content=CONTENT)["msg"])

    def test_duplicate_descriptions(self):
        self.run_module(changed=True, content=CONTENT)
        tree = ET.parse(self.config)
        entries = tree.find("installedpackages/patches")
        entries.append(entries.find("item"))
        tree.write(self.config)
        self.assertIn("multiple patches", self.fail_module(state="absent")["msg"])
        self.run_command.assert_not_called()

    @parameterized.expand(
        [
            ({"descr": "  ", "content": CONTENT}, "descr"),
            ({}, "Provide content, src, or location"),
            ({"content": "", "location": URL}, "nonempty"),
            ({"src": "/nonexistent/banner.patch", "remote_src": True}, "Unable to read patch"),
            ({"src": "banner.patch"}, "action plugin resolves controller-side src"),
            ({"content": CONTENT, "src": "banner.patch"}, "mutually exclusive"),
            ({"descr": None, "content": CONTENT}, "one of the following is required: descr, uniqid"),
            ({"descr": None, "uniqid": "banner", "content": CONTENT}, "descr is required when creating"),
            ({"uniqid": "", "content": CONTENT}, "uniqid must be nonempty"),
            ({"uniqid": "../banner", "content": CONTENT}, "cannot contain slashes"),
            ({"location": "ftp://patches.example.org/test"}, "Invalid patch location"),
            ({"location": "https://patches.example.org:invalid/test"}, "Invalid patch location"),
            ({"content": CONTENT, "pathstrip": -1}, "pathstrip"),
            ({"content": CONTENT, "pathstrip": 21}, "pathstrip"),
            ({"content": CONTENT, "basedir": "relative"}, "basedir"),
            ({"content": CONTENT, "basedir": "/nonexistent"}, "basedir"),
            ({"state": "absent", "run": "apply"}, "run=apply requires state=present"),
        ]
    )
    def test_validation(self, params, message):
        before = self.config.read_bytes()
        self.assertIn(message, self.fail_module(**params)["msg"])
        self.assertEqual(self.config.read_bytes(), before)
        self.run_command.assert_not_called()
        self.download.assert_not_called()
