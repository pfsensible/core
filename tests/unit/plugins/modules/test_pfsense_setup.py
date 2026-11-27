# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import pytest
import sys
import xml.etree.ElementTree as ET

if sys.version_info < (2, 7):
    pytestmark = pytest.mark.skip("pfSense Ansible modules require Python >= 2.7")

from ansible_collections.pfsensible.core.plugins.modules import pfsense_setup
from .pfsense_module import TestPFSenseModule
from ansible_collections.community.internal_test_tools.tests.unit.compat.mock import patch
from ansible_collections.community.internal_test_tools.tests.unit.plugins.modules.utils import set_module_args


class TestPFSenseSetupModule(TestPFSenseModule):
    module = pfsense_setup

    def __init__(self, *args, **kwargs):
        super(TestPFSenseSetupModule, self).__init__(*args, **kwargs)
        self.config_file = "pfsense_setup_config.xml"

    @staticmethod
    def get_args_fields():
        """return params fields"""
        fields = ["hostname", "domain", "dns_addresses", "dns_hostnames", "dns_gateways", "dnsallowoverride", "dnslocalhost", "timezone"]
        fields += ["timeservers", "language", "webguicss", "webguifixedmenu", "webguihostnamemenu", "dashboardcolumns", "interfacessort"]
        fields += ["dashboardavailablewidgetspanel", "systemlogsfilterpanel", "systemlogsmanagelogpanel", "statusmonitoringsettingspanel"]
        fields += ["requirestatefilter", "webguileftcolumnhyper", "disablealiaspopupdetail", "roworderdragging", "logincss", "loginshowhost"]
        return fields

    def setUp(self):
        """mocking up"""

        super(TestPFSenseSetupModule, self).setUp()

        # Remove validate command for webguicss which references files on the pfSense instance
        self.mock_validate_webguicss = patch.dict(
            "ansible_collections.pfsensible.core.plugins.modules.pfsense_setup.SETUP_ARG_ROUTE", dict(webguicss=dict(parse=pfsense_setup.p2o_webguicss))
        )
        self.mock_validate_webguicss.start()

        self.mock_run_command = patch("ansible.module_utils.basic.AnsibleModule.run_command")
        self.run_command = self.mock_run_command.start()
        self.run_command.return_value = (0, "", "")

    def tearDown(self):
        """mocking down"""
        super(TestPFSenseSetupModule, self).tearDown()

        self.mock_validate_webguicss.stop()
        self.run_command.stop()

    ##############
    # tests utils
    #
    def get_target_elt(self, obj, absent=False, module_result=None):
        """get the generated xml definition"""
        return self.assert_find_xml_elt(self.xml_result, "system")

    def check_target_elt(self, obj, target_elt):
        """test the xml definition of setup elt"""
        webgui_elt = self.assert_find_xml_elt(target_elt, "webgui")

        def check_param(param, elt):
            if obj.get(param) is not None:
                self.assert_xml_elt_equal(elt, param, obj[param])

        def check_bool_param(param, elt):
            if obj.get(param) is not None:
                if obj[param]:
                    self.assert_xml_elt_is_none_or_empty(elt, param)
                else:
                    self.assert_not_find_xml_elt(elt, param)

        check_param("hostname", target_elt)
        check_param("domain", target_elt)
        check_bool_param("dnsallowoverride", target_elt)
        check_param("dnslocalhost", target_elt)
        check_param("timezone", target_elt)
        check_param("timeservers", target_elt)
        check_param("language", target_elt)

        if obj.get("webguicss") is not None:
            self.assert_xml_elt_equal(webgui_elt, "webguicss", obj["webguicss"] + ".css")

        self.check_param_bool(obj, webgui_elt, "webguifixedmenu", value_true="fixed")
        check_param("webguihostnamemenu", webgui_elt)
        check_param("dashboardcolumns", webgui_elt)
        check_bool_param("interfacessort", webgui_elt)
        check_bool_param("dashboardavailablewidgetspanel", webgui_elt)
        check_bool_param("systemlogsfilterpanel", webgui_elt)
        check_bool_param("systemlogsmanagelogpanel", webgui_elt)
        check_bool_param("statusmonitoringsettingspanel", webgui_elt)
        check_bool_param("requirestatefilter", webgui_elt)
        check_bool_param("webguileftcolumnhyper", webgui_elt)
        check_bool_param("disablealiaspopupdetail", webgui_elt)
        check_bool_param("roworderdragging", webgui_elt)
        check_bool_param("loginshowhost", webgui_elt)
        check_param("logincss", webgui_elt)

        # TODO: check dns_addresses, dns_hostnames, dns_gateways

    ##############
    # tests
    #
    def test_setup_hostname(self):
        """test setup hostname"""
        setup = dict(hostname="acme")
        command = "update setup general set hostname='acme'"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_hostname_invalid(self):
        """test setup hostname"""
        setup = dict(hostname="acme.corp.com")
        msg = "A valid hostname is specified, but the domain name part should be omitted"
        self.do_module_test(setup, msg=msg, state=None, failed=True)

    def test_setup_hostname_invalid2(self):
        """test setup hostname"""
        setup = dict(hostname="(invalid)")
        msg = "The hostname can only contain the characters A-Z, 0-9 and '-'. It may not start or end with '-'"
        self.do_module_test(setup, msg=msg, state=None, failed=True)

    def test_setup_domain(self):
        """test setup domain"""
        setup = dict(domain="corp.com")
        command = "update setup general set domain='corp.com'"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_domain_invalid(self):
        """test setup domain"""
        setup = dict(domain="@invalid.com")
        msg = "The domain may only contain the characters a-z, 0-9, '-' and '.'"
        self.do_module_test(setup, msg=msg, state=None, failed=True)

    def test_setup_dnsallowoverride(self):
        """test setup general"""
        setup = dict(dnsallowoverride=False)
        command = "update setup general set dnsallowoverride=False"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_dnslocalhost(self):
        """test setup dnslocalhost"""
        setup = dict(dnslocalhost="remote")
        command = "update setup general set dnslocalhost='remote'"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_webguifixedmenu(self):
        """test setup webguifixedmenu"""
        setup = dict(webguifixedmenu=True)
        command = "update setup general set webguifixedmenu=True"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_webgui_false_is_idempotent_when_options_are_absent(self):
        self.load_fixtures()
        with set_module_args(dict(interfacessort=False, webguifixedmenu=False)):
            self.assertEqual(self.changed(False)["commands"], [])
        self.phpshell.assert_not_called()

    def test_setup_disables_enabled_webgui_options(self):
        options = (
            "dashboardavailablewidgetspanel",
            "disablealiaspopupdetail",
            "interfacessort",
            "loginshowhost",
            "requirestatefilter",
            "roworderdragging",
            "statusmonitoringsettingspanel",
            "systemlogsfilterpanel",
            "systemlogsmanagelogpanel",
            "webguifixedmenu",
            "webguileftcolumnhyper",
        )
        self.load_fixtures()
        tree = ET.parse(self.tmp_file)
        webgui = tree.find("system/webgui")
        for option in options:
            ET.SubElement(webgui, option).text = "fixed" if option == "webguifixedmenu" else None
        ET.SubElement(webgui, "nohttpreferercheck")
        tree.write(self.tmp_file)

        params = dict.fromkeys(options, False)
        params["dashboardcolumns"] = 3
        with set_module_args(params):
            result = self.changed(True)
        for option in options:
            self.assertIn(option, result["diff"]["before"]["webgui"])
            self.assertNotIn(option, result["diff"]["after"]["webgui"])
            self.assertIn(f"{option}=False", result["commands"][0])
        webgui = ET.parse(self.tmp_file).find("system/webgui")
        self.assertEqual(webgui.findtext("protocol"), "http")
        self.assertEqual(webgui.findtext("dashboardcolumns"), "3")
        self.assertIsNotNone(webgui.find("nohttpreferercheck"))
        for option in options:
            self.assertIsNone(webgui.find(option))
        with set_module_args(params):
            self.assertEqual(self.changed(False)["commands"], [])

    def test_setup_applies_webgui_options_when_section_is_absent(self):
        self.load_fixtures()
        tree = ET.parse(self.tmp_file)
        system = tree.find("system")
        system.remove(system.find("webgui"))
        tree.write(self.tmp_file)

        with set_module_args(dict(interfacessort=False)):
            self.assertEqual(self.changed(False)["commands"], [])
        with set_module_args(dict(interfacessort=False, dashboardcolumns=3)):
            result = self.changed(True)
        self.assertEqual(result["diff"]["after"]["webgui"], {"dashboardcolumns": "3"})

    def test_setup_interfacessort(self):
        """test setup interfacessort"""
        setup = dict(interfacessort=True)
        command = "update setup general set interfacessort=True"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_dashboardavailablewidgetspanel(self):
        """test setup dashboardavailablewidgetspanel"""
        setup = dict(dashboardavailablewidgetspanel=True)
        command = "update setup general set dashboardavailablewidgetspanel=True"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_systemlogsfilterpanel(self):
        """test setup systemlogsfilterpanel"""
        setup = dict(systemlogsfilterpanel=True)
        command = "update setup general set systemlogsfilterpanel=True"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_systemlogsmanagelogpanel(self):
        """test setup systemlogsmanagelogpanel"""
        setup = dict(systemlogsmanagelogpanel=True)
        command = "update setup general set systemlogsmanagelogpanel=True"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_statusmonitoringsettingspanel(self):
        """test setup statusmonitoringsettingspanel"""
        setup = dict(statusmonitoringsettingspanel=True)
        command = "update setup general set statusmonitoringsettingspanel=True"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_requirestatefilter(self):
        """test setup requirestatefilter"""
        setup = dict(requirestatefilter=True)
        command = "update setup general set requirestatefilter=True"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_webguileftcolumnhyper(self):
        """test setup webguileftcolumnhyper"""
        setup = dict(webguileftcolumnhyper=True)
        command = "update setup general set webguileftcolumnhyper=True"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_disablealiaspopupdetail(self):
        """test setup disablealiaspopupdetail"""
        setup = dict(disablealiaspopupdetail=True)
        command = "update setup general set disablealiaspopupdetail=True"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_roworderdragging(self):
        """test setup roworderdragging"""
        setup = dict(roworderdragging=True)
        command = "update setup general set roworderdragging=True"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_loginshowhost(self):
        """test setup loginshowhost"""
        setup = dict(loginshowhost=True)
        command = "update setup general set loginshowhost=True"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_language(self):
        """test setup language"""
        setup = dict(language="fr_FR")
        command = "update setup general set language='fr_FR'"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_timeservers(self):
        """test setup timeservers"""
        setup = dict(timeservers="1.2.3.4 0.pool.ntp.org")
        command = "update setup general set timeservers='1.2.3.4 0.pool.ntp.org'"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_timezone(self):
        """test setup timezone"""
        setup = dict(timezone="Europe/Paris")
        command = "update setup general set timezone='Europe/Paris'"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_webguicss(self):
        """test setup webguicss"""
        setup = dict(webguicss="pfSense-dark")
        command = "update setup general set webguicss='pfSense-dark'"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_webguihostnamemenu(self):
        """test setup webguihostnamemenu"""
        setup = dict(webguihostnamemenu="fqdn")
        command = "update setup general set webguihostnamemenu='fqdn'"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_dashboardcolumns(self):
        """test setup dashboardcolumns"""
        setup = dict(dashboardcolumns="3")
        command = "update setup general set dashboardcolumns='3'"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_dashboardcolumns_invalid(self):
        """test setup dashboardcolumns"""
        setup = dict(dashboardcolumns="0")
        msg = "The submitted Dashboard Columns value is invalid."
        self.do_module_test(setup, msg=msg, state=None, failed=True)

    def test_setup_logincss(self):
        """test setup logincss"""
        setup = dict(logincss="ff0000")
        command = "update setup general set logincss='ff0000'"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_logincss_invalid(self):
        msg = "logincss must contain six hexadecimal digits with an optional trailing semicolon."
        for value in ("gg0000", "1e3f75;;", "+12345", "1e3f75\n"):
            with self.subTest(value=value):
                self.do_module_test(dict(logincss=value), msg=msg, state=None, failed=True)

    def test_setup_logincss_dark_blue_uses_pfsense_form(self):
        self.load_fixtures()
        with set_module_args(dict(logincss="1e3f75")):
            result = self.changed(True)
        self.assertEqual(result["diff"]["after"]["webgui"]["logincss"], "1e3f75;")
        self.assertEqual(ET.parse(self.tmp_file).findtext("system/webgui/logincss"), "1e3f75;")
        for value in ("1e3f75", "1e3f75;"):
            with self.subTest(value=value), set_module_args(dict(logincss=value)):
                self.assertEqual(self.changed(False)["commands"], [])

    def test_setup_logincss_preserves_equivalent_saved_value(self):
        self.load_fixtures()
        tree = ET.parse(self.tmp_file)
        ET.SubElement(tree.find("system/webgui"), "logincss").text = "1e3f75"
        tree.write(self.tmp_file)
        with set_module_args(dict(logincss="1e3f75;", _ansible_check_mode=True)):
            self.assertEqual(self.changed(False)["commands"], [])
        self.phpshell.assert_not_called()

    def test_setup_consolebell(self):
        """test setup consolebell: off (never saved in the fixture), again (no change), then on"""
        self.load_fixtures()
        with set_module_args(dict(consolebell=False)):
            result = self.changed(True)
        self.assertEqual(result["commands"], ["update setup general set consolebell='disabled'"])
        self.assertEqual(ET.parse(self.tmp_file).findtext("system/consolebell"), "disabled")
        cmd = self.phpshell.call_args[0][0]
        self.assertIn("set_single_sysctl('kern.vt.enable_bell', '0');", cmd)
        self.assertNotIn("activate_powerd();", cmd)
        self.phpshell.reset_mock()
        with set_module_args(dict(consolebell=False)):
            self.assertEqual(self.changed(False)["commands"], [])
        self.phpshell.assert_not_called()
        with set_module_args(dict(consolebell=True)):
            result = self.changed(True)
        self.assertEqual(result["commands"], ["update setup general set consolebell='enabled'"])
        self.assertEqual(ET.parse(self.tmp_file).findtext("system/consolebell"), "enabled")
        self.assertIn("set_single_sysctl('kern.vt.enable_bell', '1');", self.phpshell.call_args[0][0])

    def test_setup_powerd(self):
        """test setup powerd: on, again (no change), a mode, then off"""
        self.load_fixtures()
        with set_module_args(dict(powerd_enable=False)):
            self.assertEqual(self.changed(False)["commands"], [])
        with set_module_args(dict(powerd_enable=True)):
            result = self.changed(True)
        self.assertEqual(result["commands"], ["update setup general set powerd_enable=True"])
        self.assertIsNotNone(ET.parse(self.tmp_file).find("system/powerd_enable"))
        cmd = self.phpshell.call_args[0][0]
        self.assertIn("activate_powerd();", cmd)
        self.assertNotIn("set_single_sysctl(", cmd)
        self.phpshell.reset_mock()
        with set_module_args(dict(powerd_enable=True, powerd_ac_mode="hadp")):
            self.assertEqual(self.changed(False)["commands"], [])
        self.phpshell.assert_not_called()
        with set_module_args(dict(powerd_ac_mode="adp", powerd_battery_mode="min", powerd_normal_mode="max")):
            result = self.changed(True)
        self.assertEqual(result["commands"], ["update setup general set powerd_ac_mode='adp', powerd_battery_mode='min', powerd_normal_mode='max'"])
        system = ET.parse(self.tmp_file).find("system")
        self.assertEqual(system.findtext("powerd_ac_mode"), "adp")
        self.assertEqual(system.findtext("powerd_battery_mode"), "min")
        self.assertEqual(system.findtext("powerd_normal_mode"), "max")
        self.assertIn("activate_powerd();", self.phpshell.call_args[0][0])
        with set_module_args(dict(powerd_enable=False)):
            result = self.changed(True)
        self.assertEqual(result["commands"], ["update setup general set powerd_enable=False"])
        system = ET.parse(self.tmp_file).find("system")
        self.assertIsNone(system.find("powerd_enable"))
        self.assertEqual(system.findtext("powerd_ac_mode"), "adp")
        self.assertIn("activate_powerd();", self.phpshell.call_args[0][0])

    def test_setup_powerd_mode_invalid(self):
        """test setup powerd with a mode the web page does not offer"""
        self.load_fixtures()
        with set_module_args(dict(powerd_ac_mode="fast")):
            self.assertIn("powerd_ac_mode", self.failed()["msg"])
        self.assertFalse(self.load_xml_result())

    def test_setup_gw_down_kill_states(self):
        """test setup gw_down_kill_states: from none to down, again (no change), then all"""
        self.load_fixtures()
        tree = ET.parse(self.tmp_file)
        ET.SubElement(tree.find("system"), "gw_down_kill_states").text = "none"
        tree.write(self.tmp_file)
        with set_module_args(dict(gw_down_kill_states="down")):
            result = self.changed(True)
        self.assertEqual(result["commands"], ["update setup general set gw_down_kill_states='down'"])
        self.assertEqual(ET.parse(self.tmp_file).findtext("system/gw_down_kill_states"), "down")
        cmd = self.phpshell.call_args[0][0]
        self.assertIn("filter_configure();", cmd)
        self.assertNotIn("activate_powerd();", cmd)
        self.assertNotIn("set_single_sysctl(", cmd)
        with set_module_args(dict(gw_down_kill_states="down")):
            self.assertEqual(self.changed(False)["commands"], [])
        with set_module_args(dict(gw_down_kill_states="all")):
            result = self.changed(True)
        self.assertEqual(result["commands"], ["update setup general set gw_down_kill_states='all'"])

    def test_setup_statepolicy(self):
        """test setup statepolicy: floating, again (no change), then back to if-bound"""
        self.load_fixtures()
        with set_module_args(dict(statepolicy="floating")):
            result = self.changed(True)
        self.assertEqual(result["commands"], ["update setup general set statepolicy='floating'"])
        self.assertEqual(ET.parse(self.tmp_file).findtext("system/statepolicy"), "floating")
        cmd = self.phpshell.call_args[0][0]
        self.assertIn("filter_configure();", cmd)
        self.assertNotIn("activate_powerd();", cmd)
        with set_module_args(dict(statepolicy="floating")):
            self.assertEqual(self.changed(False)["commands"], [])
        with set_module_args(dict(statepolicy="if-bound")):
            result = self.changed(True)
        self.assertEqual(result["commands"], ["update setup general set statepolicy='if-bound'"])
        self.assertEqual(ET.parse(self.tmp_file).findtext("system/statepolicy"), "if-bound")

    def test_setup_ipsec_mb(self):
        """test setup ipsec_mb: off (absent in the fixture), on, again (no change), then off"""
        self.load_fixtures()
        with set_module_args(dict(ipsec_mb=False)):
            self.assertEqual(self.changed(False)["commands"], [])
        self.phpshell.assert_not_called()
        with set_module_args(dict(ipsec_mb=True, _ansible_diff=True)):
            result = self.changed(True)
        self.assertEqual(result["commands"], ["update setup general set ipsec_mb=True"])
        self.assertNotIn("ipsec_mb", result["diff"]["before"])
        self.assertEqual(result["diff"]["after"]["ipsec_mb"], "")
        ipsec_mb = ET.parse(self.tmp_file).find("system/ipsec_mb")
        self.assertIsNotNone(ipsec_mb)
        self.assertFalse(ipsec_mb.text)
        # The usual apply step (it already runs load_crypto()), and nothing more
        self.assertIn("load_crypto();", self.phpshell.call_args[0][0])
        for step in ("setup_loader_settings();", "prefer_ipv4_or_ipv6();", "activate_powerd();"):
            self.assertNotIn(step, self.phpshell.call_args[0][0])
        self.phpshell.reset_mock()
        with set_module_args(dict(ipsec_mb=True)):
            self.assertEqual(self.changed(False)["commands"], [])
        self.phpshell.assert_not_called()
        with set_module_args(dict(ipsec_mb=False)):
            result = self.changed(True)
        self.assertEqual(result["commands"], ["update setup general set ipsec_mb=False"])
        self.assertIsNone(ET.parse(self.tmp_file).find("system/ipsec_mb"))
        self.assertIn("load_crypto();", self.phpshell.call_args[0][0])

    def test_setup_ipsec_mb_omitted(self):
        """test that ipsec_mb set by pfSense is kept when omitted, then removed with false"""
        self.load_fixtures()
        tree = ET.parse(self.tmp_file)
        ET.SubElement(tree.find("system"), "ipsec_mb")
        tree.write(self.tmp_file)
        with set_module_args(dict(hostname="acme")):
            result = self.changed(True)
        self.assertEqual(result["commands"], ["update setup general set hostname='acme'"])
        self.assertIsNotNone(ET.parse(self.tmp_file).find("system/ipsec_mb"))
        with set_module_args(dict(ipsec_mb=True)):
            self.assertEqual(self.changed(False)["commands"], [])
        with set_module_args(dict(ipsec_mb=False)):
            result = self.changed(True)
        self.assertEqual(result["commands"], ["update setup general set ipsec_mb=False"])
        self.assertIsNone(ET.parse(self.tmp_file).find("system/ipsec_mb"))
        self.assertIn("load_crypto();", self.phpshell.call_args[0][0])

    def test_setup_dns_addresses(self):
        """test setup dns"""
        setup = dict(dns_addresses="8.8.4.4 8.8.8.8", dns_hostnames="acme1 acme2", dns_gateways="none GW_WAN")
        command = "update setup general set dns_addresses='8.8.4.4 8.8.8.8', dns_hostnames='acme1 acme2', dns_gateways='none GW_WAN'"
        self.do_module_test(setup, command=command, state=None)

    def configure_dns_fixture(self, addresses=("8.8.4.4", "8.8.8.8")):
        self.load_fixtures()
        config = ET.parse(self.tmp_file)
        system = config.find("system")
        for address in addresses:
            ET.SubElement(system, "dnsserver").text = address
        ET.SubElement(system, "dns1gw").text = "none"
        ET.SubElement(system, "dns2gw").text = "none"
        ET.SubElement(system, "dns2host").text = "resolver.example.com"
        config.write(self.tmp_file, encoding="utf-8")

    def test_setup_omitted_dns_options_preserve_xml(self):
        self.configure_dns_fixture()
        with set_module_args({}):
            self.changed(changed=False)
        self.assertFalse(self.load_xml_result())
        with set_module_args({"hostname": "updated"}):
            result = self.changed(changed=True)
        self.assertEqual(result["commands"], ["update setup general set hostname='updated'"])
        for key in ("dnsserver", "dns1gw", "dns2gw", "dns2host"):
            self.assertEqual(result["diff"]["after"][key], result["diff"]["before"][key])
        self.run_command.assert_not_called()

    def test_setup_dns_addresses_preserve_omitted_slot_settings(self):
        self.configure_dns_fixture()
        with set_module_args({"dns_addresses": "1.1.1.1"}):
            result = self.changed(changed=True)
        after = result["diff"]["after"]
        self.assertEqual(after["dnsserver"], "1.1.1.1")
        self.assertEqual(after["dns1gw"], "none")
        self.assertEqual(after["dns2gw"], "none")
        self.assertEqual(after["dns2host"], "resolver.example.com")
        self.assertEqual(result["commands"], ["update setup general set dns_addresses='1.1.1.1'"])
        self.run_command.assert_not_called()

    def test_setup_dns_hostnames_only(self):
        self.configure_dns_fixture()
        with set_module_args({"dns_hostnames": "updated.example.com none"}):
            result = self.changed(changed=True)
        after = result["diff"]["after"]
        self.assertEqual(after["dnsserver"], ["8.8.4.4", "8.8.8.8"])
        self.assertEqual(after["dns1gw"], "none")
        self.assertEqual(after["dns2gw"], "none")
        self.assertEqual(after["dns1host"], "updated.example.com")
        self.assertNotIn("dns2host", after)
        self.assertEqual(result["commands"], ["update setup general set dns_hostnames='updated.example.com'"])
        self.run_command.assert_not_called()

    def test_setup_dns_gateway_only(self):
        self.configure_dns_fixture(addresses=("8.8.4.4",))
        with set_module_args({"dns_gateways": "GW_WAN"}):
            result = self.changed(changed=True)
            self.changed(changed=False)
        after = result["diff"]["after"]
        self.assertEqual(after["dnsserver"], "8.8.4.4")
        self.assertEqual(after["dns1gw"], "GW_WAN")
        self.assertNotIn("dns2gw", after)
        self.assertEqual(after["dns2host"], "resolver.example.com")
        self.assertEqual(result["commands"], ["update setup general set dns_gateways='GW_WAN'"])
        self.run_command.assert_called_once_with("/sbin/route delete 8.8.4.4")

    def test_setup_dns_addresses_invalid(self):
        """test setup dns"""
        setup = dict(dns_addresses="8.8.4.4 8.8.8.8 256.255.254.253", dns_hostnames="acme1 acme2", dns_gateways="none GW_WAN")
        msg = "A valid IP address must be specified for DNS server 256.255.254.253."
        self.do_module_test(setup, msg=msg, state=None, failed=True)

    def test_setup_dns_addresses_ipv6(self):
        """test setup dns"""
        setup = dict(dns_addresses="2001::8 8.8.4.4", dns_hostnames="acme1 acme2", dns_gateways="none GW_WAN")
        command = "update setup general set dns_addresses='2001::8 8.8.4.4', dns_hostnames='acme1 acme2', dns_gateways='none GW_WAN'"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_dns_addresses_invalid_ipv4(self):
        """test setup dns"""
        setup = dict(dns_addresses="8.8.4.4 8.8.8.8", dns_hostnames="acme1 acme2", dns_gateways="none GW_LAN6")
        msg = 'The IPv6 gateway "GW_LAN6" can not be specified for IPv4 DNS server "8.8.8.8".'
        self.do_module_test(setup, msg=msg, state=None, failed=True)

    def test_setup_dns_addresses_invalid_ipv6(self):
        """test setup dns"""
        setup = dict(dns_addresses="8.8.4.4 2001::8", dns_hostnames="acme1 acme2", dns_gateways="none GW_WAN")
        msg = 'The IPv4 gateway "GW_WAN" can not be specified for IPv6 DNS server "2001::8".'
        self.do_module_test(setup, msg=msg, state=None, failed=True)

    def test_setup_dns_addresses_invalid_gw(self):
        """test setup dns"""
        setup = dict(dns_addresses="8.8.4.4 8.8.8.8", dns_hostnames="acme1 acme2", dns_gateways="none GW_ACME")
        msg = 'The gateway "GW_ACME" does not exist.'
        self.do_module_test(setup, msg=msg, state=None, failed=True)

    def test_setup_dns_addresses_invalid_gw2(self):
        """test setup dns"""
        setup = dict(dns_addresses="8.8.4.4 192.168.1.1", dns_hostnames="acme1 acme2", dns_gateways="none GW_WAN")
        msg = "A gateway can not be assigned to DNS '192.168.1.1' server which is on a directly connected network."
        self.do_module_test(setup, msg=msg, state=None, failed=True)

    def test_setup_dns_addresses_duplicates(self):
        """test setup dns"""
        setup = dict(dns_addresses="8.8.8.8 8.8.8.8", dns_hostnames="acme1 acme2", dns_gateways="none GW_WAN")
        msg = "Each configured DNS server must have a unique IP address. Remove the duplicated IP."
        self.do_module_test(setup, msg=msg, state=None, failed=True)

    def test_setup_althostnames(self):
        """test setup althostnames: set, again (no change), then removed by an empty list"""
        self.load_fixtures()
        names = ["fw.example.com", "192.168.1.1", "2001:db8::1"]
        with set_module_args(dict(althostnames=names)):
            result = self.changed(True)
        self.assertEqual(result["commands"], ["update setup general set althostnames='fw.example.com 192.168.1.1 2001:db8::1'"])
        self.assertEqual(ET.parse(self.tmp_file).findtext("system/webgui/althostnames"), "fw.example.com 192.168.1.1 2001:db8::1")
        self.assertNotIn("prefer_ipv4_or_ipv6();", self.phpshell.call_args[0][0])
        with set_module_args(dict(althostnames=names)):
            self.assertEqual(self.changed(False)["commands"], [])
        with set_module_args(dict(althostnames=[])):
            result = self.changed(True)
        self.assertEqual(result["commands"], ["update setup general set althostnames=none"])
        webgui = ET.parse(self.tmp_file).find("system/webgui")
        self.assertIsNone(webgui.find("althostnames"))
        self.assertEqual(webgui.findtext("protocol"), "http")
        with set_module_args(dict(althostnames=[])):
            self.assertEqual(self.changed(False)["commands"], [])

    def test_setup_althostnames_invalid(self):
        """test setup althostnames with a name that is not a hostname"""
        self.load_fixtures()
        with set_module_args(dict(althostnames=["fw.example.com", "fw example"])):
            self.assertIn("alternate hostname fw example", self.failed()["msg"])

    def test_setup_ipv6allow(self):
        """test setup ipv6allow: off (the fixture has it on), again (no change), then on"""
        self.load_fixtures()
        with set_module_args(dict(ipv6allow=False)):
            result = self.changed(True)
        self.assertEqual(result["commands"], ["update setup general set ipv6allow=False"])
        self.assertIsNone(ET.parse(self.tmp_file).find("system/ipv6allow"))
        self.assertIn("prefer_ipv4_or_ipv6();", self.phpshell.call_args[0][0])
        self.assertIn("filter_configure();", self.phpshell.call_args[0][0])
        with set_module_args(dict(ipv6allow=False)):
            self.assertEqual(self.changed(False)["commands"], [])
        with set_module_args(dict(ipv6allow=True)):
            result = self.changed(True)
        self.assertEqual(result["commands"], ["update setup general set ipv6allow=True"])
        self.assertIsNotNone(ET.parse(self.tmp_file).find("system/ipv6allow"))

    def test_setup_maximumstates(self):
        """test setup maximumstates: set, again (no change), then back to the default with 0"""
        self.load_fixtures()
        with set_module_args(dict(maximumstates=406000)):
            result = self.changed(True)
        self.assertEqual(result["commands"], ["update setup general set maximumstates='406000'"])
        self.assertEqual(ET.parse(self.tmp_file).findtext("system/maximumstates"), "406000")
        self.assertIn("setup_loader_settings();", self.phpshell.call_args[0][0])
        self.assertNotIn("prefer_ipv4_or_ipv6();", self.phpshell.call_args[0][0])
        with set_module_args(dict(maximumstates=406000)):
            self.assertEqual(self.changed(False)["commands"], [])
        with set_module_args(dict(maximumstates=0)):
            result = self.changed(True)
        self.assertEqual(result["commands"], ["update setup general set maximumstates=none"])
        self.assertIsNone(ET.parse(self.tmp_file).find("system/maximumstates"))
        with set_module_args(dict(maximumstates=0)):
            self.assertEqual(self.changed(False)["commands"], [])

    def test_setup_maximumstates_invalid(self):
        """test setup maximumstates below 0"""
        self.load_fixtures()
        with set_module_args(dict(maximumstates=-1)):
            self.assertEqual(self.failed()["msg"], "The Firewall Maximum States value must be 0 or more.")

    def test_setup_sshguard(self):
        """test setup login protection: set, again (no change), then back to the defaults with 0"""
        self.load_fixtures()
        args = dict(sshguard_threshold=30, sshguard_blocktime=120, sshguard_detection_time=1800)
        with set_module_args(args):
            result = self.changed(True)
        self.assertEqual(result["commands"], ["update setup general set sshguard_threshold='30', sshguard_blocktime='120', sshguard_detection_time='1800'"])
        system = ET.parse(self.tmp_file).find("system")
        self.assertEqual(system.findtext("sshguard_threshold"), "30")
        self.assertEqual(system.findtext("sshguard_blocktime"), "120")
        self.assertEqual(system.findtext("sshguard_detection_time"), "1800")
        self.assertIn("system_sshguard_stop();$retval |= system_syslogd_start(true);", self.phpshell.call_args[0][0])
        self.phpshell.reset_mock()
        with set_module_args(args):
            self.assertEqual(self.changed(False)["commands"], [])
        self.phpshell.assert_not_called()
        with set_module_args(dict(sshguard_blocktime=0)):
            result = self.changed(True)
        self.assertEqual(result["commands"], ["update setup general set sshguard_blocktime=none"])
        system = ET.parse(self.tmp_file).find("system")
        self.assertIsNone(system.find("sshguard_blocktime"))
        self.assertEqual(system.findtext("sshguard_threshold"), "30")
        self.assertIn("system_sshguard_stop();", self.phpshell.call_args[0][0])
        with set_module_args(dict(sshguard_blocktime=0)):
            self.assertEqual(self.changed(False)["commands"], [])

    def test_setup_sshguard_restart_only_on_change(self):
        """test that sshguard is restarted for a pass list change, not for another setting"""
        self.load_fixtures()
        with set_module_args(dict(hostname="acme")):
            self.changed(True)
        self.assertNotIn("system_sshguard_stop();", self.phpshell.call_args[0][0])
        with set_module_args(dict(sshguard_whitelist=["10.0.0.0/8"])):
            self.changed(True)
        self.assertIn("system_sshguard_stop();", self.phpshell.call_args[0][0])

    def test_setup_sshguard_invalid(self):
        """test setup login protection values the web form does not accept"""
        self.load_fixtures()
        for param, value in (("sshguard_threshold", 5), ("sshguard_blocktime", 125), ("sshguard_detection_time", -10)):
            with set_module_args({param: value}):
                self.assertEqual(self.failed()["msg"], "{0} must be 0 (pfSense's default) or a multiple of 10, 10 or more.".format(param))
        self.assertFalse(self.load_xml_result())

    def test_setup_diff_keeps_managed_fields(self):
        """test that the diff does not show the users and their password hashes"""
        self.load_fixtures()
        password_hash = ET.parse(self.tmp_file).findtext("system/user/bcrypt-hash")
        self.assertTrue(password_hash)
        with set_module_args(dict(hostname="acme", webguifixedmenu=True, dns_addresses="8.8.8.8", _ansible_diff=True)):
            result = self.changed(True)
        self.assertNotIn(password_hash, repr(result))
        for side in ("before", "after"):
            self.assertNotIn("user", result["diff"][side])
            self.assertNotIn("protocol", result["diff"][side]["webgui"])
        self.assertEqual(result["diff"]["after"]["hostname"], "acme")
        self.assertEqual(result["diff"]["after"]["webgui"]["webguifixedmenu"], "fixed")
        self.assertEqual(result["diff"]["after"]["dnsserver"], "8.8.8.8")
        self.assertEqual(ET.parse(self.tmp_file).findtext("system/user/bcrypt-hash"), password_hash)
