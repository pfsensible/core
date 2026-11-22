"""Alias XML and runtime initialization regressions, without a firewall."""

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import ast
import errno
import importlib.util
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import xml.etree.ElementTree as ET

if __package__:
    from .test_config_write import CORE, NATIVE_PHP, PHP_BINARY, XMLPARSE, ModuleFailure, pfsense
else:
    # unittest discovery imports these files as top-level modules.
    from test_config_write import CORE, NATIVE_PHP, PHP_BINARY, XMLPARSE, ModuleFailure, pfsense


def load_source(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PREFIX = "ansible_collections.pfsensible.core.plugins.module_utils."
route = load_source("alias_test_arg_route", CORE / "plugins/module_utils/arg_route.py")
with patch.dict(sys.modules, {PREFIX + "pfsense": pfsense, PREFIX + "arg_route": route}):
    base = load_source("alias_test_base", CORE / "plugins/module_utils/module_base.py")
    with patch.dict(sys.modules, {PREFIX + "module_base": base}):
        alias = load_source("alias_test", CORE / "plugins/module_utils/alias.py")


class ModuleExit(Exception):
    def __init__(self, result):
        self.result = result


class Module:
    argument_spec = alias.ALIAS_ARGUMENT_SPEC
    check_mode = False

    def fail_json(self, **result):
        raise ModuleFailure(result)

    def exit_json(self, **result):
        raise ModuleExit(result)

    warn = Mock()


class AliasTests(unittest.TestCase):
    def setUp(self):
        self.module = Module()
        self.module.run_command = Mock(return_value=(0, "", ""))
        self.helper = pfsense.PFSenseModule.__new__(pfsense.PFSenseModule)
        self.helper.module = self.module
        self.helper.debug = io.StringIO()
        self.helper.root = ET.fromstring("<pfsense><aliases/><interfaces/></pfsense>")
        self.helper.aliases = self.helper.root.find("aliases")
        self.helper.interfaces = self.helper.root.find("interfaces")
        self.events = []
        self.helper.write_config = Mock(side_effect=lambda **kwargs: self.events.append("write"))
        self.helper.php = Mock(side_effect=lambda command: self.events.append("initialize") or {"failed_aliases": []})
        self.helper.phpshell = Mock(side_effect=lambda command: self.events.append("reload") or (0, "", ""))
        self.alias = alias.PFSenseAliasModule(self.module, self.helper)
        self.stat_patch = patch.object(alias.os.path, "getsize", return_value=12)
        self.stat_patch.start()
        self.addCleanup(self.stat_patch.stop)

    def params(self, **changes):
        params = {name: spec.get("default") for name, spec in alias.ALIAS_ARGUMENT_SPEC.items()}
        params.update(name="fail2ban", state="present", type="urltable",
                      url="https://127.0.0.1/aliastables/fail2ban", updatefreq=128)
        params.update(changes)
        return params

    def commit(self):
        with self.assertRaises(ModuleExit) as result:
            self.alias.commit_changes()
        return result.exception.result

    def test_reject_removal_from_alias_reference_fields(self):
        """Reject alias deletion before writing when supported fields still reference it."""
        references = (
            ("filter/rule", "source/port", "1000-test_alias"),
            ("nat/rule", "target", "test_alias"),
            ("nat/onetoone", "destination/address", "test_alias"),
            ("nat/outbound/rule", "source/address", "test_alias"),
            ("nat/outbound/rule", "dstport", "test_alias:2000"),
            ("aliases/alias", "address", "192.0.2.10 test_alias 192.0.2.20"),
            ("staticroutes/route", "network", "test_alias"),
            ("openvpn/openvpn-client", "remote_network", "192.0.2.0/24, test_alias"),
        )
        for section, field, value in references:
            with self.subTest(section=section, field=field):
                self.helper.root = ET.fromstring("<pfsense><aliases/><interfaces/></pfsense>")
                self.helper.aliases = self.helper.root.find("aliases")
                self.alias = alias.PFSenseAliasModule(self.module, self.helper)
                self.alias.run(self.params(name="test_alias", type="port" if "port" in field else "host",
                                           url=None, address="1024" if "port" in field else "192.0.2.1", updatefreq=None))
                self.alias.run(self.params(name="test_alias", state="absent"))
                entry = self.helper.root
                for tag in section.split("/") + field.split("/"):
                    existing = entry.find(tag)
                    entry = ET.SubElement(entry, tag) if existing is None else existing
                entry.text = value

                with self.assertRaises(ModuleFailure) as failure:
                    self.commit()
                self.assertIn(f"Alias 'test_alias' is in use by {section}", failure.exception.result["msg"])
                self.assertEqual(self.events, [])

    def test_alias_removal_ignores_similar_names_and_descriptions(self):
        """Allow deletion when only a similar alias name or description matches."""
        self.alias.run(self.params(name="test_host", type="host", address="192.0.2.1", url=None, updatefreq=None))
        self.alias.run(self.params(name="other_hosts", type="host", address="test_host_extra", descr="test_host", url=None, updatefreq=None))
        self.alias.run(self.params(name="test_host", state="absent"))
        self.assertTrue(self.commit()["changed"])
        self.assertEqual(self.events, ["write", "reload"])

    def test_urltable_creation_stores_both_url_and_address(self):
        for kind in ("urltable", "urltable_ports"):
            with self.subTest(kind=kind):
                params = self.params(name=kind + "_test", type=kind)
                self.alias.run(params)
                result = self.helper.find_alias(params["name"])
                self.assertEqual(result.findtext("address"), params["url"])
                self.assertEqual(result.findtext("url"), params["url"])
        self.commit()
        self.assertEqual(self.events, ["write", "initialize", "reload"])

    def test_deprecated_address_populates_both_fields(self):
        self.alias.run(self.params(url=None, address="https://127.0.0.1/aliastables/fail2ban"))
        result = self.helper.find_alias("fail2ban")
        self.assertEqual(result.findtext("address"), result.findtext("url"))

    def test_preexisting_missing_address_is_repaired(self):
        self.alias.run(self.params())
        existing = self.helper.find_alias("fail2ban")
        existing.remove(existing.find("address"))
        repair = alias.PFSenseAliasModule(self.module, self.helper)
        repair.run(self.params())
        self.assertTrue(repair.result["changed"])
        self.assertEqual(existing.findtext("address"), self.params()["url"])

    def test_unchanged_alias_and_ready_cache_are_idempotent(self):
        self.alias.run(self.params())
        self.alias = alias.PFSenseAliasModule(self.module, self.helper)
        self.alias.run(self.params())
        result = self.commit()
        self.assertFalse(result["changed"])
        self.assertEqual(self.events, [])

    def test_missing_or_empty_cache_is_repaired_on_an_unchanged_alias(self):
        self.alias.run(self.params())
        for failure in (FileNotFoundError(errno.ENOENT, "missing"), None):
            repair = alias.PFSenseAliasModule(self.module, self.helper)
            with patch.object(alias.os.path, "getsize", side_effect=failure, return_value=0):
                repair.run(self.params())
            self.assertTrue(repair.result["changed"])
            repair.initialize_url_tables()
        self.assertEqual(self.helper.php.call_count, 2)

    def test_changed_url_forces_refresh_but_metadata_change_does_not(self):
        self.alias.run(self.params())
        repair = alias.PFSenseAliasModule(self.module, self.helper)
        repair.run(self.params(descr="different description"))
        self.assertEqual(repair._urltable_updates, {"fail2ban": False})
        repair.run(self.params(url="https://127.0.0.1/aliastables/new"))
        self.assertEqual(repair._urltable_updates, {"fail2ban": True})

    def test_initialization_failure_stops_filter_reload(self):
        self.alias.run(self.params())
        self.helper.php.side_effect = lambda command: {"failed_aliases": ["fail2ban"]}
        with self.assertRaises(ModuleFailure) as failure:
            self.alias.commit_changes()
        self.assertTrue(failure.exception.result["changed"])
        self.assertEqual(failure.exception.result["failed_aliases"], ["fail2ban"])
        self.helper.phpshell.assert_not_called()

    def test_url_change_replaces_existing_kernel_entries_before_filter_reload(self):
        self.alias.run(self.params())
        self.alias = alias.PFSenseAliasModule(self.module, self.helper)
        self.alias.run(self.params(url="https://127.0.0.1/aliastables/new"))
        kernel_entries = ["192.0.2.10"]
        downloaded_entries = ["198.51.100.20"]
        self.helper.php.side_effect = lambda command: {"failed_aliases": [], "updated_aliases": ["fail2ban"]}

        def kernel(command):
            if command == ["/sbin/pfctl", "-s", "Tables"]:
                return 0, "fail2ban\n", ""
            if command == ["/sbin/pfctl", "-t", "fail2ban", "-T", "replace", "-f", "/var/db/aliastables/fail2ban.txt"]:
                kernel_entries[:] = downloaded_entries
                return 0, "", ""
            raise AssertionError("Unexpected kernel operation: " + str(command))

        def reload(command):
            # Model a modern filter reload that does nothing when rules did not
            # change. The table must already be updated before this point.
            self.assertEqual(kernel_entries, downloaded_entries)
            return 0, "", ""

        self.module.run_command.side_effect = kernel
        self.helper.phpshell.side_effect = reload
        self.commit()
        self.assertEqual(kernel_entries, ["198.51.100.20"])

    def test_new_table_is_left_for_normal_filter_creation(self):
        self.alias.run(self.params())
        self.helper.php.side_effect = lambda command: {"failed_aliases": [], "updated_aliases": ["fail2ban"]}
        self.commit()
        self.module.run_command.assert_called_once_with(["/sbin/pfctl", "-s", "Tables"])
        self.helper.phpshell.assert_called_once()

    def test_kernel_replacement_failure_stops_filter_reload(self):
        self.alias.run(self.params())
        self.helper.php.side_effect = lambda command: {"failed_aliases": [], "updated_aliases": ["fail2ban"]}
        self.module.run_command.side_effect = [(0, "fail2ban\n", ""), (1, "private output", "private error")]
        with self.assertRaises(ModuleFailure) as failure:
            self.commit()
        self.assertTrue(failure.exception.result["changed"])
        self.assertEqual(failure.exception.result["failed_aliases"], ["fail2ban"])
        self.assertNotIn("private", str(failure.exception.result))
        self.helper.phpshell.assert_not_called()

    def test_kernel_table_inspection_failure_stops_filter_reload(self):
        self.alias.run(self.params())
        self.helper.php.side_effect = lambda command: {"failed_aliases": [], "updated_aliases": ["fail2ban"]}
        self.module.run_command.return_value = (1, "", "")
        with self.assertRaises(ModuleFailure) as failure:
            self.commit()
        self.assertTrue(failure.exception.result["changed"])
        self.helper.phpshell.assert_not_called()

    def test_check_mode_performs_no_runtime_writes(self):
        self.module.check_mode = True
        self.alias.run(self.params())
        self.assertTrue(self.commit()["changed"])
        self.assertEqual(self.events, [])
        self.module.run_command.assert_not_called()

    def test_host_alias_does_not_initialize_url_tables(self):
        self.alias.run(self.params(type="host", url=None, address="192.0.2.10", updatefreq=None))
        self.commit()
        self.helper.php.assert_not_called()

    def test_deleted_alias_is_not_downloaded(self):
        self.alias.run(self.params())
        self.alias.run(self.params(state="absent", type=None, url=None, updatefreq=None))
        self.commit()
        self.helper.php.assert_not_called()

    def test_urltable_requires_a_url(self):
        with self.assertRaisesRegex(ModuleFailure, "is required"):
            self.alias.run(self.params(url=None))

    def test_aggregate_initializes_before_any_filter_reload(self):
        self.alias.run(self.params())
        # Execute the actual aggregate method without importing unrelated
        # module implementations or requiring an Ansible runtime.
        tree = ast.parse((CORE / "plugins/modules/pfsense_aggregate.py").read_text())
        cls = next(node for node in tree.body if isinstance(node, ast.ClassDef)
                   and node.name == "PFSenseModuleAggregate")
        method = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == "_update")
        namespace = {}
        exec(compile(ast.Module(body=[method], type_ignores=[]), "<aggregate update>", "exec"), namespace)
        aggregate = SimpleNamespace(pfsense=self.helper, pfsense_aliases=self.alias)
        for name in ("vlans", "interfaces", "rules", "rule_separators", "nat_port_forwards", "nat_outbounds"):
            setattr(aggregate, "pfsense_" + name, SimpleNamespace(result={"changed": False}))
        namespace["_update"](aggregate)
        self.assertEqual(self.events, ["initialize", "reload"])

    @unittest.skipUnless(NATIVE_PHP, "requires native PHP runtime and pfSense source")
    def test_native_urltable_initialization_and_alias_resolution(self):
        # Execute the checked-out native process/lookup functions. Substitute
        # local fixture downloads and a /tmp cache, without networking or PF.
        source_dir = Path(XMLPARSE).parent

        def function(filename, name):
            content = (source_dir / filename).read_text()
            return re.search(r"^function " + re.escape(name) + r"\(.*?^}", content, re.M | re.S).group()

        functions = "\n".join((function("pfsense-utils.inc", "process_alias_urltable"),
                               function("util.inc", "alias_make_table"), function("util.inc", "alias_expand")))
        with tempfile.TemporaryDirectory(prefix="urltable-native-") as directory:
            source = Path(directory) / "download.txt"
            source.write_text("127.0.0.100\n")
            self.alias.run(self.params())
            stubs = """error_reporting(0);
$g = array('cf_conf_path' => %s);
$config_aliases = %s;
function config_get_path($path, $default = null) { global $config_aliases; return $path === 'aliases/alias' ? $config_aliases : $default; }
function config_path_enabled($path, $key) { return false; }
function get_reserved_table_names($name = null) { return array(); }
function is_validaliasname($name) { return true; }
function is_URL($url) { return filter_var($url, FILTER_VALIDATE_URL) !== false; }
function is_numericint($value) { return preg_match('/^[0-9]+$/D', $value) === 1; }
function is_ipaddr($value) { return filter_var($value, FILTER_VALIDATE_IP) !== false; }
function is_subnet($value) { return false; }
function is_port_or_range($value) { return false; }
function unlink_if_exists($path) { if (file_exists($path)) { unlink($path); } }
function download_file($url, $destination, $verify) { return copy(%s, $destination); }
function mwexec($command) { return 0; }
function parse_aliases_file($path, $type, $count, $keep) { return file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES); }
function group_ports($ports, $group) { return $ports; }
""" % (json.dumps(directory), "json_decode(" + json.dumps(json.dumps([
                self.helper.element_to_dict(self.helper.find_alias("fail2ban"))])) + ", true)", json.dumps(str(source)))

            def native(command):
                command = command.replace("require_once(\"pfsense-utils.inc\");", stubs + functions)
                command = command.replace("/var/db/aliastables/", directory + "/cache/")
                command = command.replace("echo json_encode(array('failed_aliases' => $failed, 'updated_aliases' => $updated));",
                                          "alias_make_table(); $resolved = alias_expand('fail2ban'); "
                                          "unset($config_aliases[0]['address']); alias_make_table(); "
                                          "echo json_encode(array('failed_aliases' => $failed, 'updated_aliases' => $updated, 'resolved' => $resolved, "
                                          "'without_address' => alias_expand('fail2ban')));")
                result = subprocess.run([PHP_BINARY, "-r", command], capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
                result = json.loads(result.stdout)
                self.assertEqual(result["resolved"], "$fail2ban")
                self.assertIsNone(result["without_address"])
                return result

            self.helper.php.side_effect = native
            self.commit()
            self.assertEqual((Path(directory) / "cache/fail2ban.txt").read_text(), "127.0.0.100")


if __name__ == "__main__":
    unittest.main()
