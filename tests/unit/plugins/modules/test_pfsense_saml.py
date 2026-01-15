# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import pytest
import sys

if sys.version_info < (2, 7):
    pytestmark = pytest.mark.skip("pfSense Ansible modules require Python >= 2.7")

from ansible_collections.pfsensible.core.plugins.modules import pfsense_saml
from .pfsense_module import TestPFSenseModule


class TestPFSenseSAMLModule(TestPFSenseModule):

    module = pfsense_saml

    def __init__(self, *args, **kwargs):
        super(TestPFSenseSAMLModule, self).__init__(*args, **kwargs)
        self.config_file = 'pfsense_saml_config.xml'
        self.pfmodule = pfsense_saml.PFSenseSAMLModule

    @staticmethod
    def runTest():
        """ dummy function needed to instantiate this test module from another in python 2.7 """
        pass

    def get_target_elt(self, obj, absent=False, module_result=None):
        """ return target elt from XML """
        installed_pkgs_elt = self.assert_find_xml_elt(self.xml_result, 'installedpackages')
        pkgs_elts = installed_pkgs_elt.findall('package') if installed_pkgs_elt is not None else None

        for elt in pkgs_elts:
            pkg_name = elt.find('internal_name')
            if pkg_name is not None and pkg_name.text == "saml2-auth":
                conf_elt = elt.find('conf')
                if conf_elt is not None:
                    return conf_elt
        
        return None
    
    def check_target_elt(self, obj, target_elt):
        """ check XML definition of target elt """

        self.check_param_equal(obj, target_elt, 'enable')
        self.check_param_equal(obj, target_elt, 'strip_username')
        self.check_param_equal(obj, target_elt, 'debug_mode')

        self.check_param_equal(obj, target_elt, 'idp_metadata_url')
        self.check_param_equal(obj, target_elt, 'idp_entity_id', default='')
        self.check_param_equal(obj, target_elt, 'idp_sign_on_url', default='')
        self.check_param_equal(obj, target_elt, 'idp_groups_attribute', default='')
        self.check_param_equal(obj, target_elt, 'idp_x509_cert', default='')

        self.check_param_equal(obj, target_elt, 'sp_base_url')

        self.check_param_equal(obj, target_elt, 'custom_conf', default='')


    ##############
    # tests
    #

    # def test_conf_not_found(self):
    #     """ TODO """

    # def test_updated_settings(self):
    #     """ TODO """
    
    def test_x509_cert_update_noop(self):
        """ test not applying invalid x509 cert """
        obj = dict(sp_base_url="https://pfSense.local", idp_x509_cert="NOT_A_VALID_CERT")
        self.do_module_test(obj, command="update saml", changed=False)

    # def test_invalid_url_update_noop(self):
    #     """ test not appling an invalid url """
    #     obj = dict(sp_base_url="https://pfSense.local")
    #     self.do_module_test(obj, command="update saml", changed=False)

    # def test_invalid_json_update_noop(self):
    #     """ test not appling an invalid url """
    #     obj = dict(sp_base_url="https://pfSense.local", custom_conf="invalid_json")
    #     self.do_module_test(obj, command="update saml", changed=False)

