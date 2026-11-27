# Copyright: (c) 2026, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import xml.etree.ElementTree as ET

from ansible_collections.community.internal_test_tools.tests.unit.plugins.modules.utils import set_module_args
from ansible_collections.pfsensible.core.plugins.modules import pfsense_dashboard
from .pfsense_module import TestPFSenseModule


SEQUENCE = "system_information:col1:open:0,traffic_graphs:col2:open:0,openvpn-0:col2:close:0"


class TestPFSenseDashboardModule(TestPFSenseModule):
    module = pfsense_dashboard

    def setUp(self):
        super(TestPFSenseDashboardModule, self).setUp()
        self.write_config()

    def write_config(self, widgets=""):
        with open(self.tmp_file, "w") as config:
            config.write("<pfsense><version>24.0</version>{0}</pfsense>".format(widgets))

    def run_module(self, changed=False, **params):
        with set_module_args(params):
            return self.changed(changed)

    def stored_widgets(self):
        return ET.parse(self.tmp_file).find("widgets")

    def test_widget_options_and_sequence(self):
        options = {
            "traffic_graphs": {"filter": "wan,lan", "period": 10, "show": True, "interfaces": ["wan", "lan"]},
            "openvpn-0": {"filter": "all"},
            "custom_widget-0": {"settings": {"label": "custom"}},
        }
        sequence = SEQUENCE + ",custom_widget-0:col1:open:1"
        result = self.run_module(changed=True, sequence=sequence, options=options)

        widgets = self.stored_widgets()
        self.assertEqual(widgets.findtext("sequence"), sequence)
        self.assertEqual(widgets.findtext("traffic_graphs/filter"), "wan,lan")
        self.assertEqual(widgets.findtext("traffic_graphs/period"), "10")
        self.assertEqual(widgets.findtext("traffic_graphs/show"), "true")
        self.assertEqual([item.text for item in widgets.findall("traffic_graphs/interfaces")], ["wan", "lan"])
        self.assertEqual(widgets.findtext("openvpn-0/filter"), "all")
        self.assertEqual(widgets.findtext("custom_widget-0/settings/label"), "custom")
        self.assertTrue(result["changed"])

    def test_options_only_uses_existing_sequence(self):
        self.write_config("<widgets><sequence>{0}</sequence></widgets>".format(SEQUENCE))
        self.run_module(changed=True, options={"traffic_graphs": {"filter": "wan"}})
        self.assertEqual(self.stored_widgets().findtext("traffic_graphs/filter"), "wan")

    def test_repeat_is_idempotent(self):
        params = dict(sequence=SEQUENCE, options={"traffic_graphs": {"filter": "wan"}})
        self.assertTrue(self.run_module(changed=True, **params)["changed"])
        self.assertFalse(self.run_module(**params)["changed"])

    def test_invalid_sequence(self):
        with set_module_args(dict(sequence="traffic_graphs:col7:open:0")):
            self.assertIn("Invalid dashboard sequence entry", self.failed()["msg"])

    def test_options_widget_must_be_in_sequence(self):
        with set_module_args(dict(sequence=SEQUENCE, options={"missing_widget": {"filter": "wan"}})):
            self.assertIn("is not present in the sequence", self.failed()["msg"])

    def test_invalid_widget_setting_name(self):
        with set_module_args(dict(sequence=SEQUENCE, options={"traffic_graphs": {"invalid name": "wan"}})):
            self.assertIn("Invalid dashboard widget setting name", self.failed()["msg"])

    def test_widget_options_must_be_a_mapping(self):
        with set_module_args(dict(sequence=SEQUENCE, options={"traffic_graphs": ["wan"]})):
            self.assertIn("must be a dictionary", self.failed()["msg"])
