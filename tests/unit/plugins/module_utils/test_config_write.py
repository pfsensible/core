"""Standalone regression tests; no Ansible installation or firewall required."""

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import errno
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET


CORE = Path(__file__).resolve().parents[4]
SPEC = importlib.util.spec_from_file_location(
    "pfsense_config_test", CORE / "plugins/module_utils/pfsense.py")
pfsense = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pfsense)
PHP_BINARY = os.environ.get("PFSENSE_PHP_BINARY") or shutil.which("php")
XMLPARSE = os.environ.get("PFSENSE_XMLPARSE_INC")
NATIVE_PHP = bool(PHP_BINARY and XMLPARSE)

CONFIG = b"""<?xml version="1.0"?>
<pfsense>
  <version>24.0</version>
  <system><hostname>firewall</hostname><password><![CDATA[secret&amp;literal]]></password></system>
  <interfaces><lan><if>igb0</if></lan></interfaces>
  <filter><rule><descr><![CDATA[Allow &lt;test&gt; &amp; monitor]]></descr></rule></filter>
  <installedpackages><suricata><rule><passthru><![CDATA[regex: [a-z]+ &copy;]]></passthru></rule></suricata></installedpackages>
  <revision><time>0</time><description>baseline</description><username>test</username></revision>
</pfsense>"""


class ModuleFailure(Exception):
    def __init__(self, result):
        self.result = result
        super().__init__(result["msg"])


class Module:
    def fail_json(self, **result):
        raise ModuleFailure(result)

    def run_command(self, command):
        if NATIVE_PHP:
            command = list(command)
            command[0] = PHP_BINARY
            command[2] = command[2].replace("'/etc/inc/xmlparse.inc'", json.dumps(XMLPARSE))
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            return result.returncode, result.stdout, result.stderr
        # Exercise filesystem safety without PHP. Formatting-specific tests
        # require the real native parser/serializer rather than an imitation.
        return 0, "", ""


class ConfigWriteTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="pfsense-config-tests-")
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "config.xml"
        self.lock = self.path.with_suffix(".lock")
        self.cache = self.path.with_suffix(".cache")
        self.backup = Path(str(self.path) + ".ansible.bak")
        self.path.write_bytes(CONFIG)
        self.path.chmod(0o640)
        self.cache.write_bytes(b"old cache")

        # The debug trace, written in debug mode only, goes to the test directory
        debug_file_patch = patch.object(pfsense.PFSenseModule, "DEBUG_FILE", str(Path(self.directory.name) / "pfsense.debug"))
        debug_file_patch.start()
        self.addCleanup(debug_file_patch.stop)
        # The test runner may use a UID without a local passwd entry.
        username_patch = patch.object(pfsense.PFSenseModule, "get_username", return_value="test")
        username_patch.start()
        self.addCleanup(username_patch.stop)

    def helper(self):
        helper = pfsense.PFSenseModule(Module(), str(self.path), str(self.lock), str(self.cache))
        helper.get_username = lambda: "synthetic-test"
        return helper

    def assert_original(self):
        self.assertEqual(self.path.read_bytes(), CONFIG)
        self.assertEqual(self.cache.read_bytes(), b"old cache")

    def assert_no_temporary_files(self):
        self.assertEqual(list(self.path.parent.glob(".config.xml*")), [])

    def test_commit_preserves_metadata_and_exact_protected_backup(self):
        helper = self.helper()
        metadata = self.path.stat()
        helper.root.find("system/hostname").text = "changed"
        helper.write_config("test change")
        self.assertEqual(self.backup.read_bytes(), CONFIG)
        self.assertEqual(stat.S_IMODE(self.backup.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o640)
        self.assertEqual((self.path.stat().st_uid, self.path.stat().st_gid),
                         (metadata.st_uid, metadata.st_gid))
        self.assertEqual(self.helper().root.findtext("system/hostname"), "changed")
        self.assertFalse(self.cache.exists())
        self.assertTrue(self.lock.exists())
        self.assert_no_temporary_files()

    def test_native_failure_reports_only_stage_and_exit_code(self):
        stages = {
            10: "load_parser", 11: "parse_candidate", 12: "serialize_candidate",
            13: "write_formatted_candidate", 14: "parse_formatted_candidate",
            15: "compare_native_roundtrip", 255: "php_command", -9: "php_command",
        }
        for exit_code, stage in stages.items():
            with self.subTest(exit_code=exit_code):
                helper = self.helper()
                with patch.object(helper.module, "run_command",
                                  return_value=(exit_code, "private stdout", "private stderr")):
                    with self.assertRaises(ModuleFailure) as failure:
                        helper.write_config()
                self.assertEqual(failure.exception.result["native_validation"],
                                 {"stage": stage, "exit_code": exit_code})
                self.assertIn(stage, failure.exception.result["msg"])
                self.assertNotIn("private", str(failure.exception.result))
                self.assertFalse(failure.exception.result["changed"])
                self.assert_original()
                self.assert_no_temporary_files()

    def test_native_roundtrip_failure_locates_changed_field(self):
        helper = self.helper()

        def change_candidate(command):
            candidate = Path(command[-1])
            candidate.write_bytes(candidate.read_bytes().replace(b"firewall", b"private changed value"))
            return 15, "private stdout", "private stderr"

        with patch.object(helper.module, "run_command", side_effect=change_candidate):
            with self.assertRaises(ModuleFailure) as failure:
                helper.write_config()
        self.assertEqual(failure.exception.result["config_mismatch"],
                         {"path": "/pfsense[1]/system[1]/hostname[1]", "reason": "text differs"})
        self.assertEqual(failure.exception.result["native_validation"]["stage"], "compare_native_roundtrip")
        self.assertNotIn("private", str(failure.exception.result))
        self.assert_original()
        self.assert_no_temporary_files()

    def test_native_roundtrip_failure_decodes_legacy_entities(self):
        with patch.object(pfsense.PFSenseModule, "_uses_legacy_html_entities", return_value=True):
            helper = self.helper()

        def format_candidate(command):
            candidate = Path(command[-1])
            # The legacy entity spelling preserves the passthru value.
            serialized = candidate.read_bytes()
            copyright_sign = "\u00a9".encode("utf-8")
            self.assertIn(copyright_sign, serialized)
            formatted = serialized.replace(copyright_sign, b"&copy;")
            candidate.write_bytes(formatted.replace(b"firewall", b"private changed value"))
            return 15, "", ""

        with patch.object(helper.module, "run_command", side_effect=format_candidate):
            with self.assertRaises(ModuleFailure) as failure:
                helper.write_config()
        self.assertEqual(failure.exception.result["native_validation"],
                         {"stage": "compare_native_roundtrip", "exit_code": 15})
        self.assertEqual(failure.exception.result["config_mismatch"],
                         {"path": "/pfsense[1]/system[1]/hostname[1]", "reason": "text differs"})
        self.assertFalse(failure.exception.result["changed"])
        self.assert_original()
        self.assert_no_temporary_files()

    def test_temporary_files_always_share_config_directory(self):
        helper = self.helper()
        with patch.object(pfsense, "mkstemp", wraps=pfsense.mkstemp) as create:
            helper.write_config()
        self.assertEqual(create.call_count, 2)
        for call in create.call_args_list:
            self.assertEqual(Path(call.kwargs["dir"]), self.path.parent)

    def test_empty_elements_have_explicit_end_tags(self):
        self.path.write_bytes(CONFIG.replace(b"<hostname>", b"<enable/><hostname>"))
        helper = self.helper()
        ET.SubElement(helper.root.find("system"), "empty")
        ET.SubElement(helper.root.find("system"), "empty_string").text = ""
        helper.root.find("system/password").text = "literal <enable/>"
        for cycle in range(2):
            helper.write_config("empty element formatting")
            serialized = self.path.read_bytes()
            for tag in ("enable", "empty", "empty_string"):
                self.assertIn(("<{0}></{0}>".format(tag)).encode(), serialized)
                self.assertNotIn(("<{0}/>".format(tag)).encode(), serialized)
            helper = self.helper()
            self.assertEqual(helper.root.findtext("system/password"), "literal <enable/>")

    @unittest.skipUnless(NATIVE_PHP, "requires native PHP serializer")
    def test_native_cdata_field_prefixes_wrap_plain_text(self):
        helper = self.helper()
        # Pin the native list independently of the implementation, including
        # prefix matches rather than only exact field-name matches.
        prefixes = (
            "aclname", "auth_pass", "auth_prompt", "auth_user", "certca", "certname",
            "city", "common_name", "descr", "detail", "email", "encryption_password",
            "hint", "ldap_attr", "ldap_authcn", "ldap_basedn", "ldap_basedomain",
            "ldap_bind", "ldapbinddn", "ldapbindpass", "ldap_extended_query",
            "ldap_filter", "ldap_pam_groupdn", "ldap_pass", "ldap_user", "login_banner",
            "organization", "password", "proxypass", "proxyuser", "rangedescr",
            "state", "text", "username", "varusersusername", "varuserspassword",
        )
        fields = list(prefixes) + [prefix + "_extra" for prefix in prefixes] + ["description"]
        container = ET.SubElement(helper.root, "cdata_test")
        for field in fields:
            ET.SubElement(container, field).text = "plain value"
        ET.SubElement(container, "hostname").text = "plain value"
        for cycle in range(2):
            helper.write_config("plain revision description")
            serialized = self.path.read_bytes()
            for field in fields:
                self.assertIn(("<{0}><![CDATA[plain value]]></{0}>".format(field)).encode(), serialized)
            self.assertIn(b"<description><![CDATA[plain revision description]]></description>", serialized)
            self.assertIn(b"<hostname>plain value</hostname>", serialized)
            helper = self.helper()
            for field in fields:
                self.assertEqual(helper.root.findtext("cdata_test/" + field), "plain value")

    def test_empty_native_cdata_fields_keep_explicit_end_tags(self):
        helper = self.helper()
        container = ET.SubElement(helper.root, "cdata_test")
        for field in ("descr", "description", "ldap_basedn", "password"):
            ET.SubElement(container, field)
        helper.write_config()
        serialized = self.path.read_bytes()
        for field in ("descr", "description", "ldap_basedn", "password"):
            self.assertIn(("<{0}></{0}>".format(field)).encode(), serialized)
            self.assertNotIn(("<{0}><![CDATA[]]>".format(field)).encode(), serialized)

    @unittest.skipUnless(NATIVE_PHP, "requires native PHP serializer")
    def test_native_shellcmd_fields_use_plain_escaped_text(self):
        helper = self.helper()
        for field in ("shellcmd", "earlyshellcmd", "afterfilterchangeshellcmd"):
            ET.SubElement(helper.root.find("system"), field).text = "echo ready"
        package = ET.SubElement(helper.root.find("installedpackages"), "shellcmdsettings")
        config = ET.SubElement(package, "config")
        ET.SubElement(config, "cmd").text = "echo package"
        ET.SubElement(config, "cmdtype").text = "shellcmd"
        for cycle in range(2):
            helper.write_config()
            serialized = self.path.read_bytes()
            for field in ("shellcmd", "earlyshellcmd", "afterfilterchangeshellcmd"):
                self.assertIn(("<{0}>echo ready</{0}>".format(field)).encode(), serialized)
            self.assertIn(b"<cmd>echo package</cmd>", serialized)
            self.assertIn(b"<cmdtype>shellcmd</cmdtype>", serialized)
            helper = self.helper()

    @unittest.skipUnless(NATIVE_PHP, "requires native PHP serializer")
    def test_native_formatter_removes_extra_package_cdata(self):
        helper = self.helper()
        suricata = helper.root.find("installedpackages/suricata")
        suricata.find("rule/passthru").text = "plain original"
        rule = ET.SubElement(suricata, "rule")
        ET.SubElement(rule, "passthru").text = "plain sibling"
        unrelated = ET.SubElement(helper.root.find("installedpackages"), "unrelated")
        ET.SubElement(unrelated, "passthru").text = "plain unrelated"
        for cycle in range(2):
            helper.write_config()
            serialized = self.path.read_bytes()
            self.assertIn(b"<passthru>plain original</passthru>", serialized)
            self.assertIn(b"<passthru>plain sibling</passthru>", serialized)
            self.assertIn(b"<passthru>plain unrelated</passthru>", serialized)
            helper = self.helper()
            self.assertEqual(helper.root.findtext("installedpackages/suricata/rule/passthru"), "plain original")

    @unittest.skipUnless(NATIVE_PHP, "requires native PHP serializer")
    def test_native_formatter_decides_cdata_on_each_commit(self):
        helper = self.helper()
        value = ET.SubElement(helper.root.find("installedpackages"), "custom_value")
        value.text = "needs & escaping"
        helper.write_config()
        value.text = "now plain"
        helper.write_config()
        self.assertIn(b"<custom_value>now plain</custom_value>", self.path.read_bytes())

    def test_empty_package_cdata_still_uses_explicit_empty_tag(self):
        helper = self.helper()
        helper.root.find("installedpackages/suricata/rule/passthru").text = ""
        helper.write_config()
        self.assertIn(b"<passthru></passthru>", self.path.read_bytes())

    @unittest.skipUnless(NATIVE_PHP, "requires native PHP serializer")
    def test_native_format_matches_sanitized_diff_examples(self):
        helper = self.helper()
        system = helper.root.find("system")
        ET.SubElement(system, "shellcmd").text = "echo 'ready' >> /tmp/example"
        authserver = ET.SubElement(system, "authserver")
        ET.SubElement(authserver, "radius_secret").text = "synthetic&secret"
        ET.SubElement(authserver, "ldap_basedn").text = "DC=example,DC=test"
        server = ET.SubElement(ET.SubElement(helper.root, "openvpn"), "openvpn-server")
        ET.SubElement(server, "custom_options").text = "server example;\npush \"example\";"
        package = ET.SubElement(helper.root.find("installedpackages"), "package")
        ET.SubElement(package, "url").text = "/pkg_edit.php?xml=example.xml&id=0"
        ET.SubElement(package, "descr").text = "Package 'example'"
        for cycle in range(2):
            helper.write_config("native format")
            xml = self.path.read_bytes()
            self.assertTrue(xml.startswith(b"<?xml version=\"1.0\"?>\n<pfsense>\n"))
            self.assertTrue(xml.endswith(b"</pfsense>\n"))
            self.assertIn(b"\n\t<openvpn>\n\t\t<openvpn-server>\n", xml)
            self.assertIn(b"<radius_secret>synthetic&amp;secret</radius_secret>", xml)
            self.assertIn(b"<ldap_basedn><![CDATA[DC=example,DC=test]]></ldap_basedn>", xml)
            self.assertIn(b"<shellcmd>echo &apos;ready&apos; &gt;&gt; /tmp/example</shellcmd>", xml)
            self.assertIn(b"<custom_options>server example;\npush &quot;example&quot;;</custom_options>", xml)
            self.assertIn(b"<url>/pkg_edit.php?xml=example.xml&amp;id=0</url>", xml)
            self.assertIn(b"<descr><![CDATA[Package &apos;example&apos;]]></descr>", xml)
            helper = self.helper()
            self.assertEqual(helper.root.findtext("openvpn/openvpn-server/custom_options"),
                             "server example;\npush \"example\";")
            self.assertIsNone(helper.root.find("interfaces/opt9"))
            self.assertIsNone(helper.root.find("virtualip_carp_maintenancemode"))

    def test_plain_xml_and_cdata_preserve_literal_entities_equally(self):
        parse = pfsense.PFSenseModule._parse_config
        ordinary = b"<pfsense><value>&amp;amp; &amp;copy; &amp;#65; &apos;quote&apos;</value></pfsense>"
        cdata = b"<pfsense><value><![CDATA[&amp;amp; &amp;copy; &amp;#65; &apos;quote&apos;]]></value></pfsense>"
        expected = "&amp; &copy; &#65; 'quote'"
        self.assertEqual(parse(ordinary).findtext("value"), expected)
        self.assertEqual(parse(cdata).findtext("value"), expected)

    @unittest.skipUnless(NATIVE_PHP, "requires native PHP serializer")
    def test_appending_openvpn_server_after_clients_is_safe(self):
        helper = self.helper()
        openvpn = ET.SubElement(helper.root, "openvpn")
        server = ET.SubElement(openvpn, "openvpn-server")
        ET.SubElement(server, "vpnid").text = "1"
        client = ET.SubElement(openvpn, "openvpn-client")
        ET.SubElement(client, "vpnid").text = "2"
        helper.write_config("existing VPNs")
        helper = self.helper()
        openvpn = helper.root.find("openvpn")
        # The server module appends a new server to the end of the parent,
        # after existing clients. Native PHP groups repeated tags together.
        server = ET.SubElement(openvpn, "openvpn-server")
        ET.SubElement(server, "vpnid").text = "3"
        helper.write_config("add inter-office server")
        result = self.helper().root.find("openvpn")
        self.assertEqual([item.findtext("vpnid") for item in result.findall("openvpn-server")], ["1", "3"])
        self.assertEqual([item.findtext("vpnid") for item in result.findall("openvpn-client")], ["2"])

    @unittest.skipUnless(NATIVE_PHP, "requires native PHP serializer")
    def test_long_multiline_values_survive_native_formatting(self):
        helper = self.helper()
        value = ("line one\nline two\n" * 1000) + "last line"
        helper.root.find("system/password").text = value
        helper.write_config()
        self.assertEqual(self.helper().root.findtext("system/password"), value)

    def test_stale_snapshot_cannot_overwrite_a_completed_write(self):
        first, second = self.helper(), self.helper()
        first.root.find("system/hostname").text = "first"
        first.write_config("first")
        committed, backup = self.path.read_bytes(), self.backup.read_bytes()
        self.cache.write_bytes(b"new cache")
        second.root.find("interfaces/lan/if").text = "igb1"
        with self.assertRaisesRegex(ModuleFailure, "changed since") as failure:
            second.write_config("second")
        self.assertFalse(failure.exception.result["changed"])
        self.assertEqual(self.path.read_bytes(), committed)
        self.assertEqual(self.backup.read_bytes(), backup)
        self.assertEqual(self.cache.read_bytes(), b"new cache")

    def test_same_helper_can_commit_again_and_rotates_one_backup(self):
        helper = self.helper()
        helper.write_config("first")
        first = self.path.read_bytes()
        helper.write_config("second")
        self.assertEqual(self.backup.read_bytes(), first)

    def test_invalid_control_character_never_reaches_live_config(self):
        helper = self.helper()
        helper.root.find("system/hostname").text = "bad\x01value"
        with self.assertRaises(ModuleFailure) as failure:
            helper.write_config()
        self.assertFalse(failure.exception.result["changed"])
        self.assert_original()
        self.assertFalse(self.backup.exists())

    def test_missing_critical_sections_are_rejected(self):
        for section in ("system", "interfaces", "version"):
            with self.subTest(section=section):
                helper = self.helper()
                helper.root.remove(helper.root.find(section))
                with self.assertRaises(ModuleFailure):
                    helper.write_config()
                self.assert_original()

    def test_wrong_root_and_duplicate_version_are_rejected(self):
        for mutate in (lambda root: setattr(root, "tag", "wrong"),
                       lambda root: ET.SubElement(root, "version")):
            helper = self.helper()
            mutate(helper.root)
            with self.assertRaises(ModuleFailure):
                helper.write_config()
            self.assert_original()

    def test_emptied_or_duplicated_critical_section_is_rejected(self):
        for mutate in (lambda root: root.find("system").clear(),
                       lambda root: ET.SubElement(root, "interfaces")):
            helper = self.helper()
            mutate(helper.root)
            with self.assertRaises(ModuleFailure):
                helper.write_config()
            self.assert_original()

    def test_missing_revision_fields_are_created(self):
        helper = self.helper()
        helper.root.remove(helper.root.find("revision"))
        helper.write_config("revision created")
        revision = self.helper().root.find("revision")
        self.assertEqual(revision.findtext("description"), "revision created")
        self.assertTrue(revision.findtext("time").isdigit())
        self.assertTrue(revision.findtext("username"))

    def test_invalid_source_is_not_repaired_or_backed_up_implicitly(self):
        self.path.write_bytes(b"<pfsense>truncated")
        with self.assertRaisesRegex(ModuleFailure, "Unable to read"):
            self.helper()
        self.assertEqual(self.path.read_bytes(), b"<pfsense>truncated")
        self.assertFalse(self.backup.exists())

    def test_backup_replace_failure_aborts_commit(self):
        helper = self.helper()
        with patch.object(pfsense.os, "replace", side_effect=OSError(errno.ENOSPC, "full")):
            with self.assertRaises(ModuleFailure):
                helper.write_config()
        self.assert_original()
        self.assert_no_temporary_files()

    def test_file_sync_failure_aborts_before_replacement(self):
        helper = self.helper()
        with patch.object(pfsense.os, "fsync", side_effect=OSError(errno.EIO, "sync failed")):
            with self.assertRaises(ModuleFailure):
                helper.write_config()
        self.assert_original()
        self.assertFalse(self.backup.exists())
        self.assert_no_temporary_files()

    def test_directory_sync_failure_before_commit_preserves_config(self):
        helper = self.helper()
        with patch.object(helper, "_sync_config_directory", side_effect=OSError(errno.EIO, "sync failed")):
            with self.assertRaises(ModuleFailure):
                helper.write_config()
        self.assert_original()
        self.assertEqual(self.backup.read_bytes(), CONFIG)

    def test_config_rename_failure_has_no_cross_device_copy_fallback(self):
        helper = self.helper()
        replace = os.replace

        def fail_config_replace(source, destination):
            if destination == str(self.path):
                raise OSError(errno.EXDEV, "cross-device")
            return replace(source, destination)

        with patch.object(pfsense.os, "replace", side_effect=fail_config_replace):
            with self.assertRaises(ModuleFailure) as failure:
                helper.write_config()
        self.assertFalse(failure.exception.result["changed"])
        self.assert_original()
        self.assertEqual(self.backup.read_bytes(), CONFIG)
        self.assert_no_temporary_files()

    def test_native_validator_rejection_preserves_live_config(self):
        helper = self.helper()
        with patch.object(helper.module, "run_command", return_value=(1, "private value", "private error")):
            with self.assertRaisesRegex(ModuleFailure, "Native pfSense XML validation/formatting failed") as failure:
                helper.write_config()
        self.assertFalse(failure.exception.result["changed"])
        self.assertNotIn("private", str(failure.exception.result))
        self.assert_original()
        self.assertEqual(self.backup.read_bytes(), CONFIG)
        self.assert_no_temporary_files()

    def test_formatter_value_change_is_rejected_before_replacement(self):
        helper = self.helper()

        def change_candidate(command):
            candidate = Path(command[-1])
            candidate.write_bytes(candidate.read_bytes().replace(b"firewall", b"changed unexpectedly"))
            return 0, "", ""

        with patch.object(helper.module, "run_command", side_effect=change_candidate):
            with self.assertRaisesRegex(ModuleFailure, "formatting changed configuration values") as failure:
                helper.write_config()
        self.assertEqual(failure.exception.result["config_mismatch"],
                         {"path": "/pfsense[1]/system[1]/hostname[1]", "reason": "text differs"})
        self.assertNotIn("changed unexpectedly", str(failure.exception.result))
        self.assert_original()
        self.assert_no_temporary_files()

    def test_formatter_reordering_rules_is_still_rejected(self):
        helper = self.helper()
        rules = helper.root.find("filter")
        ET.SubElement(ET.SubElement(rules, "rule"), "descr").text = "synthetic private description"
        run_command = helper.module.run_command

        def reorder_rules(command):
            result = run_command(command)
            candidate = Path(command[-1])
            tree = helper._parse_config(candidate.read_bytes())
            rules = tree.find("filter")
            first = rules.find("rule")
            rules.remove(first)
            rules.append(first)
            candidate.write_bytes(ET.tostring(tree.getroot(), encoding="utf-8"))
            return result

        with patch.object(helper.module, "run_command", side_effect=reorder_rules):
            with self.assertRaisesRegex(ModuleFailure, "formatting changed configuration values") as failure:
                helper.write_config()
        self.assertEqual(failure.exception.result["config_mismatch"],
                         {"path": "/pfsense[1]/filter[1]/rule[1]/descr[1]", "reason": "text differs"})
        self.assertNotIn("synthetic private description", str(failure.exception.result))
        self.assertFalse(failure.exception.result["changed"])
        self.assert_original()
        self.assert_no_temporary_files()

    def test_formatter_reordering_named_fields_is_allowed(self):
        helper = self.helper()
        run_command = helper.module.run_command

        def reorder_fields(command):
            result = run_command(command)
            candidate = Path(command[-1])
            tree = helper._parse_config(candidate.read_bytes())
            system = tree.find("system")
            hostname = system.find("hostname")
            system.remove(hostname)
            system.append(hostname)
            candidate.write_bytes(ET.tostring(tree.getroot(), encoding="utf-8"))
            return result

        with patch.object(helper.module, "run_command", side_effect=reorder_fields):
            helper.write_config()
        self.assertEqual(self.helper().root.findtext("system/hostname"), "firewall")

    def test_formatter_dropped_field_has_value_free_diagnostic(self):
        helper = self.helper()
        run_command = helper.module.run_command

        def remove_field(command):
            result = run_command(command)
            candidate = Path(command[-1])
            tree = helper._parse_config(candidate.read_bytes())
            tree.getroot().remove(tree.find("filter"))
            candidate.write_bytes(ET.tostring(tree.getroot(), encoding="utf-8"))
            return result

        with patch.object(helper.module, "run_command", side_effect=remove_field):
            with self.assertRaises(ModuleFailure) as failure:
                helper.write_config()
        self.assertEqual(failure.exception.result["config_mismatch"],
                         {"path": "/pfsense[1]/filter[1]", "reason": "element count differs"})
        self.assert_original()

    def test_formatted_candidate_sync_failure_aborts_replacement(self):
        helper = self.helper()
        with patch.object(pfsense.os, "fsync", side_effect=[None, None, None, OSError(errno.EIO, "sync failed")]):
            with self.assertRaises(ModuleFailure) as failure:
                helper.write_config()
        self.assertFalse(failure.exception.result["changed"])
        self.assert_original()
        self.assert_no_temporary_files()

    @unittest.skipUnless(NATIVE_PHP, "requires native PHP serializer")
    def test_native_parser_rejects_duplicate_scalar_field(self):
        helper = self.helper()
        ET.SubElement(helper.root.find("system"), "hostname").text = "duplicate"
        with self.assertRaisesRegex(ModuleFailure, "Native pfSense XML validation/formatting failed") as failure:
            helper.write_config()
        self.assertEqual(failure.exception.result["native_validation"]["stage"], "parse_candidate")
        self.assert_original()
        self.assert_no_temporary_files()

    @unittest.skipUnless(NATIVE_PHP, "requires native PHP serializer")
    def test_unstable_native_round_trip_is_rejected(self):
        helper = self.helper()
        helper.root.find("system/password").text = "line\rvalue"
        with self.assertRaisesRegex(ModuleFailure, "live configuration was not replaced") as failure:
            helper.write_config()
        self.assertEqual(failure.exception.result["config_mismatch"],
                         {"path": "/pfsense[1]/system[1]/password[1]", "reason": "text differs"})
        self.assert_original()
        self.assert_no_temporary_files()

    def test_directory_sync_failure_after_commit_reports_committed_state(self):
        helper = self.helper()
        with patch.object(helper, "_sync_config_directory", side_effect=[None, OSError(errno.EIO, "sync failed")]):
            with self.assertRaises(ModuleFailure) as failure:
                helper.write_config()
        self.assertTrue(failure.exception.result["changed"])
        self.assertNotEqual(self.path.read_bytes(), CONFIG)
        self.assertEqual(self.backup.read_bytes(), CONFIG)
        self.assertFalse(self.cache.exists())

    def test_cache_invalidation_failure_reports_committed_state(self):
        helper = self.helper()
        unlink = os.unlink

        def fail_cache(path, *args, **kwargs):
            if path == str(self.cache):
                raise OSError(errno.EACCES, "cache access denied")
            return unlink(path, *args, **kwargs)

        with patch.object(pfsense.os, "unlink", side_effect=fail_cache):
            with self.assertRaisesRegex(ModuleFailure, "finalization failed") as failure:
                helper.write_config()
        self.assertTrue(failure.exception.result["changed"])
        self.assertNotEqual(self.path.read_bytes(), CONFIG)
        self.assertEqual(self.backup.read_bytes(), CONFIG)
        self.helper()  # The lock was released even on failure.

    def test_missing_cache_is_allowed(self):
        helper = self.helper()
        self.cache.unlink()
        helper.write_config()
        self.assertTrue(self.backup.exists())

    def test_lock_is_released_before_a_php_style_apply_hook(self):
        helper = self.helper()
        helper.write_config()
        with self.lock.open("w") as native:
            fcntl.flock(native, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(native, fcntl.LOCK_UN)

    def test_lock_timeout_does_not_write_config(self):
        helper = self.helper()
        with patch.object(pfsense.fcntl, "flock", side_effect=BlockingIOError(errno.EAGAIN, "busy")):
            with patch.object(pfsense.time, "monotonic", side_effect=[0, 31]):
                with self.assertRaisesRegex(ModuleFailure, "Timed out"):
                    helper.write_config()
        self.assert_original()
        self.assertFalse(self.backup.exists())

    def test_native_writer_lock_is_respected_and_its_change_preserved(self):
        helper = self.helper()
        ready, release = threading.Event(), threading.Event()

        def native_writer():
            with self.lock.open("w") as native:
                fcntl.flock(native, fcntl.LOCK_EX)
                self.path.write_bytes(CONFIG.replace(b"firewall", b"native"))
                ready.set()
                release.wait(5)

        writer = threading.Thread(target=native_writer)
        writer.start()
        self.addCleanup(writer.join, 5)
        self.addCleanup(release.set)
        self.assertTrue(ready.wait(5))
        flock = fcntl.flock

        def acquire(descriptor, operation):
            release.set()
            return flock(descriptor, operation)

        with patch.object(pfsense.fcntl, "flock", side_effect=acquire):
            with self.assertRaisesRegex(ModuleFailure, "changed since"):
                helper.write_config()
        writer.join(5)
        self.assertFalse(writer.is_alive())
        self.assertEqual(self.path.read_bytes(), CONFIG.replace(b"firewall", b"native"))
        self.assertFalse(self.backup.exists())

    def test_package_and_entity_values_survive_repeated_unrelated_writes(self):
        helper = self.helper()
        expected = {
            "system/password": "secret&literal",
            "filter/rule/descr": "Allow <test> & monitor",
            "installedpackages/suricata/rule/passthru": "regex: [a-z]+ &copy;",
        }
        for path, value in expected.items():
            self.assertEqual(helper.root.findtext(path), value)
        for value in ("literal &amp; &copy; &#65; &#x41;", "quotes: ' \" < > & ]]> café 中文",
                      "regex: ^[a-z]+\\s+(foo|bar)$", "invalid entity: &#1;",
                      "line one\nline two\tvalue"):
            helper.root.find("system/password").text = value
            for cycle in range(3):
                helper.write_config("unrelated change {0}".format(cycle))
                helper = self.helper()
                self.assertEqual(helper.root.findtext("system/password"), value)
                for path, original in expected.items():
                    if path != "system/password":
                        self.assertEqual(helper.root.findtext(path), original)

    def test_xml_only_decoding_matches_native_entity_rules(self):
        decode = pfsense.PFSenseModule._decode_xml_entities
        self.assertEqual(decode("&copy; &not; &amp; &apos; &#65; &#x1f600;"),
                         "&copy; &not; & ' A 😀")
        self.assertEqual(decode("&amp;lt;"), "&lt;")
        self.assertEqual(decode("&#0; &#1; &#xD800; &#1114112;"),
                         "&#0; &#1; &#xD800; &#1114112;")

    @unittest.skipUnless(NATIVE_PHP,
                         "requires PHP XML extension and PFSENSE_XMLPARSE_INC")
    def test_native_php_parser_round_trip(self):
        helper = self.helper()
        value = "literal &amp; &copy; &#65; quotes: ' \" < > & ]]> café"
        helper.root.find("system/password").text = value
        helper.write_config()
        command = ("require $argv[1]; "
                   "$c = parse_xml_config($argv[2], array(\"pfsense\")); "
                   "echo json_encode($c[\"system\"][\"password\"]);")
        result = subprocess.run([PHP_BINARY, "-r", command, XMLPARSE, str(self.path)],
                                check=True, capture_output=True, text=True)
        self.assertEqual(json.loads(result.stdout), value)


if __name__ == "__main__":
    unittest.main()
