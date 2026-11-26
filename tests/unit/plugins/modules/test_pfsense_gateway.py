# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import pytest
import sys
from xml.etree import ElementTree as ET

if sys.version_info < (2, 7):
    pytestmark = pytest.mark.skip("pfSense Ansible modules require Python >= 2.7")

from ansible_collections.pfsensible.core.plugins.modules import pfsense_gateway
from ansible_collections.pfsensible.core.plugins.module_utils.gateway import PFSenseGatewayModule
from .pfsense_module import TestPFSenseModule, set_module_args


class TestPFSenseGatewayModule(TestPFSenseModule):

    module = pfsense_gateway

    def __init__(self, *args, **kwargs):
        super(TestPFSenseGatewayModule, self).__init__(*args, **kwargs)
        self.config_file = "pfsense_gateway_config.xml"
        self.pfmodule = PFSenseGatewayModule

    def check_target_elt(self, obj, target_elt):
        """ test the xml definition """

        self.check_param_equal_or_not_find(obj, target_elt, "monitor")

        self.check_param_equal_or_not_find(obj, target_elt, "disabled", empty=True)
        self.check_param_equal_or_not_find(obj, target_elt, "monitor_disable", empty=True)
        self.check_param_equal_or_not_find(obj, target_elt, "action_disable", empty=True)
        self.check_param_equal_or_not_find(obj, target_elt, "force_down", empty=True)
        self.check_param_equal_or_not_find(obj, target_elt, "nonlocalgateway", empty=True)

        for param in ["interval", "loss_interval", "time_period", "alert_interval", "data_payload"]:
            if param in obj:
                self.check_param_equal(obj, target_elt, param)

        self.check_value_equal(target_elt, "interface", self.unalias_interface(obj["interface"]))
        self.check_param_equal(obj, target_elt, "descr")
        self.check_param_equal(obj, target_elt, "weight", "1")
        self.check_param_equal(obj, target_elt, "gateway")
        self.check_param_equal(obj, target_elt, "ipprotocol", "inet")

    def get_target_elt(self, obj, absent=False, module_result=None):
        """ get the generated xml definition """
        rules_elt = self.assert_find_xml_elt(self.xml_result, "gateways")

        for item in rules_elt:
            name_elt = item.find("name")
            if name_elt is not None and name_elt.text == obj["name"]:
                return item

        return None

    ##############
    # tests
    #
    def test_gateway_create(self):
        """ test """
        obj = dict(name="test_gw", interface="lan", gateway="192.168.1.1")
        command = "create gateway 'test_gw', interface='lan', gateway='192.168.1.1'"
        self.do_module_test(obj, command=command)

    def test_gateway_create_without_gateways_section(self):
        self.load_fixtures()
        config = ET.parse(self.tmp_file)
        config.getroot().remove(config.find("gateways"))
        config.write(self.tmp_file, encoding="utf-8")
        with set_module_args(dict(name="test_gw", interface="lan", gateway="192.168.1.1")):
            self.changed(True)
        self.assert_xml_elt_dict("gateways", {"name": "test_gw"}, {"interface": "lan", "gateway": "192.168.1.1"})

    def test_gateway_create_with_params(self):
        """ test """
        obj = dict(name="test_gw", interface="lan", gateway="192.168.1.1", descr="a test gw", monitor="8.8.8.8", weight=10)
        command = "create gateway 'test_gw', interface='lan', gateway='192.168.1.1', descr='a test gw', monitor='8.8.8.8', weight='10'"
        self.do_module_test(obj, command=command)

    def test_gateway_create_ipv6(self):
        """ test """
        obj = dict(name="test_gw", interface="wan", ipprotocol="inet6", gateway="2001::1")
        command = "create gateway 'test_gw', interface='wan', ipprotocol='inet6', gateway='2001::1'"
        self.do_module_test(obj, command=command)

    def test_gateway_create_in_vip(self):
        """ test """
        obj = dict(name="test_gw", interface="lan", gateway="10.255.2.1")
        command = "create gateway 'test_gw', interface='lan', gateway='10.255.2.1'"
        self.do_module_test(obj, command=command)

    def test_gateway_create_invalid_name(self):
        """ test """
        obj = dict(name="___", interface="lan", gateway="192.168.1.1")
        msg = "The gateway name '___' must be less than 32 characters long, may not consist of only numbers, "
        msg += "may not consist of only underscores, and may only contain the following characters: a-z, A-Z, 0-9, _"
        self.do_module_test(obj, msg=msg, failed=True)

    def test_gateway_create_invalid_interface(self):
        """ test """
        obj = dict(name="test_gw", interface="lan_232", gateway="192.168.1.1")
        msg = "lan_232 is not a valid interface"
        self.do_module_test(obj, msg=msg, failed=True)

    def test_gateway_create_nonlocal(self):
        """ test """
        obj = dict(name="test_gw", interface="lan", gateway="1.2.3.4", nonlocalgateway=True)
        command = "create gateway 'test_gw', interface='lan', gateway='1.2.3.4', nonlocalgateway=True"
        self.do_module_test(obj, command=command)

    def test_gateway_create_invalid_ip(self):
        """ test """
        obj = dict(name="test_gw", interface="lan", gateway="acme.dyndns.org")
        msg = "gateway must use an IPv4 address"
        self.do_module_test(obj, msg=msg, failed=True)

    def test_gateway_create_invalid_ip2(self):
        """ test """
        obj = dict(name="test_gw", interface="lan", gateway="1.2.3.4")
        msg = "The gateway address 1.2.3.4 does not lie within one of the chosen interface's subnets."
        self.do_module_test(obj, msg=msg, failed=True)

    def test_gateway_create_invalid_ip3(self):
        """ test """
        obj = dict(name="test_gw", interface="lan", gateway="2001::1")
        msg = "gateway must use an IPv4 address"
        self.do_module_test(obj, msg=msg, failed=True)

    def test_gateway_create_invalid_ip4(self):
        """ test """
        obj = dict(name="test_gw", interface="vt1", gateway="192.168.1.1")
        msg = "Cannot add IPv4 Gateway Address because no IPv4 address could be found on the interface."
        self.do_module_test(obj, msg=msg, failed=True)

    def test_gateway_create_invalid_monitor(self):
        """ test """
        obj = dict(name="test_gw", interface="lan", gateway="192.168.1.1", monitor="2001::1")
        msg = "monitor must use an IPv4 address"
        self.do_module_test(obj, msg=msg, failed=True)

    def test_gateway_create_invalid_ipv6(self):
        """ test """
        obj = dict(name="test_gw", interface="lan", gateway="2001::1", ipprotocol="inet6")
        msg = "Cannot add IPv6 Gateway Address because no IPv6 address could be found on the interface."
        self.do_module_test(obj, msg=msg, failed=True)

    def test_gateway_create_invalid_ipv6_2(self):
        """ test """
        obj = dict(name="test_gw", interface="wan", gateway="192.168.1.2", ipprotocol="inet6")
        msg = "gateway must use an IPv6 address"
        self.do_module_test(obj, msg=msg, failed=True)

    def test_gateway_create_invalid_ipv6_monitor(self):
        """ test """
        obj = dict(name="test_gw", interface="wan", ipprotocol="inet6", gateway="2001::1", monitor="192.168.1.1")
        msg = "monitor must use an IPv6 address"
        self.do_module_test(obj, msg=msg, failed=True)

    def test_gateway_create_invalid_weight(self):
        """ test """
        obj = dict(name="test_gw", interface="lan", gateway="192.168.1.1", weight="40")
        msg = "weight must be between 1 and 30"
        self.do_module_test(obj, msg=msg, failed=True)

    def test_gateway_create_with_probe_timings(self):
        """ test """
        obj = dict(name="test_gw", interface="lan", gateway="192.168.1.1", latencyhigh=400, interval=1000, loss_interval=2000, time_period=30000,
                   alert_interval=1000, data_payload=10)
        command = ("create gateway 'test_gw', interface='lan', gateway='192.168.1.1', latencyhigh='400', interval='1000', loss_interval='2000', "
                   "time_period='30000', alert_interval='1000', data_payload='10'")
        self.do_module_test(obj, command=command)

    def test_gateway_create_invalid_interval(self):
        """ test """
        obj = dict(name="test_gw", interface="lan", gateway="192.168.1.1", interval=0)
        msg = "interval must be greater than 0"
        self.do_module_test(obj, msg=msg, failed=True)

    def test_gateway_create_invalid_data_payload(self):
        """ test """
        obj = dict(name="test_gw", interface="lan", gateway="192.168.1.1", data_payload=-1)
        msg = "data_payload must be 0 or greater"
        self.do_module_test(obj, msg=msg, failed=True)

    def test_gateway_create_invalid_latency_thresholds(self):
        """ test: latencylow above the default latencyhigh """
        obj = dict(name="test_gw", interface="lan", gateway="192.168.1.1", latencylow=600)
        msg = "latencyhigh (500) must be greater than latencylow (600)"
        self.do_module_test(obj, msg=msg, failed=True)

    def test_gateway_create_invalid_loss_thresholds(self):
        """ test: losslow above the default losshigh """
        obj = dict(name="test_gw", interface="lan", gateway="192.168.1.1", losslow=30)
        msg = "losshigh (20) must be greater than losslow (30)"
        self.do_module_test(obj, msg=msg, failed=True)

    def test_gateway_create_invalid_loss_interval(self):
        """ test: loss_interval below the default latencyhigh """
        obj = dict(name="test_gw", interface="lan", gateway="192.168.1.1", loss_interval=400)
        msg = "loss_interval (400) must be greater than or equal to latencyhigh (500)"
        self.do_module_test(obj, msg=msg, failed=True)

    def test_gateway_create_invalid_time_period(self):
        """ test """
        obj = dict(name="test_gw", interface="lan", gateway="192.168.1.1", interval=1000, loss_interval=2000, time_period=4000)
        msg = "time_period (4000) must be greater than twice interval (1000) plus loss_interval (2000)"
        self.do_module_test(obj, msg=msg, failed=True)

    def test_gateway_create_invalid_alert_interval(self):
        """ test: alert_interval below the default interval """
        obj = dict(name="test_gw", interface="lan", gateway="192.168.1.1", alert_interval=400)
        msg = "alert_interval (400) must be greater than or equal to interval (500)"
        self.do_module_test(obj, msg=msg, failed=True)

    def test_gateway_create_data_payload_zero(self):
        """ test """
        obj = dict(name="test_gw", interface="lan", gateway="192.168.1.1", data_payload=0)
        command = "create gateway 'test_gw', interface='lan', gateway='192.168.1.1', data_payload='0'"
        self.do_module_test(obj, command=command)

    def test_gateway_update_noop(self):
        """ test """
        obj = dict(name="GW_WAN", interface="wan", gateway="192.168.240.1", descr="Interface wan Gateway")
        self.do_module_test(obj, changed=False)

    def set_gw_wan(self, **fields):
        """ store fields on GW_WAN in the test config """
        self.load_fixtures()
        config = ET.parse(self.tmp_file)
        for item in config.getroot().find("gateways"):
            if item.findtext("name") == "GW_WAN":
                for field, value in fields.items():
                    ET.SubElement(item, field).text = value
        config.write(self.tmp_file, encoding="utf-8")

    def test_gateway_update_probe_timings(self):
        """ test: the empty interval of the fixture is replaced """
        obj = dict(name="GW_WAN", interface="wan", gateway="192.168.240.1", descr="Interface wan Gateway", interval=1000, alert_interval=2000)
        command = "update gateway 'GW_WAN' set interval='1000', alert_interval='2000'"
        self.do_module_test(obj, command=command)

    def test_gateway_update_probe_timings_noop(self):
        """ test: the same probe settings a second time change nothing """
        args = dict(name="GW_WAN", interface="wan", gateway="192.168.240.1", descr="Interface wan Gateway", interval=1000, loss_interval=2500)
        self.load_fixtures()
        with set_module_args(args):
            self.changed(True)
        with set_module_args(args):
            self.changed(False)

    def test_gateway_update_empty_interval_default(self):
        """ test: the empty interval of the fixture counts as the default 500 """
        obj = dict(name="GW_WAN", interface="wan", gateway="192.168.240.1", descr="Interface wan Gateway", alert_interval=400)
        msg = "alert_interval (400) must be greater than or equal to interval (500)"
        self.do_module_test(obj, msg=msg, failed=True)

    def test_gateway_update_probe_timings_current_value(self):
        """ test: the check takes the gateway's current loss_interval when it is not set """
        self.set_gw_wan(loss_interval="3000")
        with set_module_args(dict(name="GW_WAN", interface="wan", gateway="192.168.240.1", descr="Interface wan Gateway", latencyhigh=3000)):
            self.changed(True)
        with set_module_args(dict(name="GW_WAN", interface="wan", gateway="192.168.240.1", descr="Interface wan Gateway", latencyhigh=3500)):
            result = self.failed()
            self.assertEqual(result["msg"], "loss_interval (3000) must be greater than or equal to latencyhigh (3500)")

    def test_gateway_update_other_rules_not_checked(self):
        """ test: a stored losshigh below losslow does not block a change of the probe interval, and is not logged as removed """
        self.set_gw_wan(losshigh="5", latencylow="100")
        with set_module_args(dict(name="GW_WAN", interface="wan", gateway="192.168.240.1", descr="Interface wan Gateway", interval=1000)):
            result = self.changed(True)
        self.assertEqual(result["commands"], ["update gateway 'GW_WAN' set interval='1000'"])

    def test_gateway_update_dynamic(self):
        """ test """
        obj = dict(name="OPT3_VTIV4", interface="lan", gateway="dynamic")
        msg = "The gateway use 'dynamic' as a target. You can not change the interface"
        self.do_module_test(obj, msg=msg, failed=True)

    def test_gateway_update_dynamic2(self):
        """ test """
        obj = dict(name="OPT3_VTIV4", interface="lan_100", gateway="1.2.3.4")
        msg = "The gateway use 'dynamic' as a target. This is read-only, so you must set gateway as dynamic too"
        self.do_module_test(obj, msg=msg, failed=True)

    def test_gateway_update_dynamic3(self):
        """ test """
        obj = dict(name="OPT3_VTIV4", interface="lan_100", gateway="dynamic", ipprotocol="inet6")
        msg = "The gateway use 'dynamic' as a target. You can not change ipprotocol"
        self.do_module_test(obj, msg=msg, failed=True)

    def test_gateway_update_dynamic4(self):
        """ test """
        obj = dict(name="OPT3_VTIV4", interface="lan_100", gateway="dynamic", weight=2)
        command = "update gateway 'OPT3_VTIV4' set weight='2'"
        self.do_module_test(obj, command=command)

    def test_gateway_update_interface(self):
        """ test """
        obj = dict(name="GW_WAN", interface="lan", gateway="192.168.1.1", descr="Interface wan Gateway")
        command = "update gateway 'GW_WAN' set interface='lan', gateway='192.168.1.1'"
        self.do_module_test(obj, command=command)

    def test_gateway_update_bools_and_monitor(self):
        """ test """
        obj = dict(name="GW_LAN", interface="lan", gateway="192.168.1.1", descr="Interface lan Gateway")
        command = "update gateway 'GW_LAN' set disabled=False, monitor=none, monitor_disable=False, action_disable=False, force_down=False"
        self.do_module_test(obj, command=command)

    def test_gateway_delete(self):
        """ test """
        obj = dict(name="GW_WAN2")
        command = "delete gateway 'GW_WAN2'"
        self.do_module_test(obj, command=command, delete=True)

    def test_gateway_delete_static(self):
        """ test """
        obj = dict(name="OPT3_VTIV4")
        msg = "The gateway use 'dynamic' as a target. You can not delete it"
        self.do_module_test(obj, msg=msg, delete=True, failed=True)

    def test_gateway_delete_default(self):
        """ test """
        obj = dict(name="GW_DEFAULT")
        msg = "The gateway is still in use. You can not delete it"
        self.do_module_test(obj, msg=msg, delete=True, failed=True)

    def test_gateway_delete_in_group(self):
        """ test """
        obj = dict(name="GW_LAN")
        msg = "The gateway is still in use. You can not delete it"
        self.do_module_test(obj, msg=msg, delete=True, failed=True)

    def test_gateway_delete_in_route(self):
        """ test """
        obj = dict(name="GW_WAN")
        msg = "The gateway is still in use. You can not delete it"
        self.do_module_test(obj, msg=msg, delete=True, failed=True)
