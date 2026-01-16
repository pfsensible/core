# Copyright: (c) 2026, Kevin Brooks <kbrooks81@proton.me>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import pytest
import sys

if sys.version_info < (2, 7):
    pytestmark = pytest.mark.skip("pfSense Ansible modules require Python >= 2.7")

from ansible_collections.pfsensible.core.plugins.modules import pfsense_saml
from .pfsense_module import TestPFSenseModule

CURRENT_CONFIG = dict(
    enable=True,
    sp_base_url="https://pfSense.local", 
    idp_metadata_url="https://keycloak.local/realms/master/protocol/saml/descriptor",
)

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

        self.check_param_bool(obj, target_elt, 'enable', default=True, value_true="yes")
        self.check_param_bool(obj, target_elt, 'strip_username', value_true="yes")
        self.check_param_bool(obj, target_elt, 'debug_mode', value_true="yes")

        self.check_param_equal(obj, target_elt, 'idp_metadata_url')
        self.check_param_equal(obj, target_elt, 'idp_entity_id')
        self.check_param_equal(obj, target_elt, 'idp_sign_on_url')
        self.check_param_equal(obj, target_elt, 'idp_groups_attribute')
        self.check_param_equal(obj, target_elt, 'idp_x509_cert')

        self.check_param_equal(obj, target_elt, 'sp_base_url')

        self.check_param_equal(obj, target_elt, 'custom_conf')

    ##############
    # test validation
    #
    def test_entity_id_required_if_metadata_unset(self):
        """ test not applying if not composite requirement fulfilled """
        obj = dict(enable=True, sp_base_url="https://pfSense.local")
        self.do_module_test(obj, state=None, failed=True, msg="idp_entity_id is required when idp_metadata_url is unset")

    def test_sign_on_url_required_if_metadata_unset(self):
        """ test not applying if not composite requirement fulfilled """
        obj = dict(enable=True, sp_base_url="https://pfSense.local", idp_entity_id="https://keycloak.local/realms/master")
        self.do_module_test(obj, state=None, failed=True, msg="idp_sign_on_url is required when idp_metadata_url is unset")

    def test_x509_cert_required_if_metadata_unset(self):
        """ test not applying if not composite requirement fulfilled """
        obj = dict(enable=True, sp_base_url="https://pfSense.local", idp_entity_id="https://keycloak.local/realms/master", idp_sign_on_url="https://keycloak.local/realms/master/protocol/saml")
        self.do_module_test(obj, state=None, failed=True, msg="idp_x509_cert is required when idp_metadata_url is unset")

    def test_composite_requirement_fulfilled_when_metadata_unset(self):
        """ test not applying if not composite requirement fulfilled """
        obj = dict(enable=True, sp_base_url="https://pfSense.local", idp_entity_id="https://keycloak.local/realms/master", idp_sign_on_url="https://keycloak.local/realms/master/protocol/saml", idp_x509_cert="-----BEGIN CERTIFICATE-----\nSOME_CERT\n-----END CERTIFICATE-----")
        self.do_module_test(obj, state=None, changed=True, command="update saml2-auth 'https://pfSense.local' set idp_metadata_url='', idp_entity_id='https://keycloak.local/realms/master', idp_sign_on_url='https://keycloak.local/realms/master/protocol/saml', idp_x509_cert='-----BEGIN CERTIFICATE-----\nSOME_CERT\n-----END CERTIFICATE-----'")

    def test_entity_id_update_noop(self):
        """ test not applying entity id with invalid characters """
        obj = CURRENT_CONFIG | dict(idp_entity_id="£")
        self.do_module_test(obj, state=None, failed=True, msg="idp_entity_id contains invalid characters")

    def test_entity_id_update_noop(self):
        """ test not applying too long entity id """
        obj = CURRENT_CONFIG | dict(idp_entity_id="x" * 1025)
        self.do_module_test(obj, state=None, failed=True, msg="idp_entity_id must be less than 1025 characters long")

    def test_x509_cert_update_noop(self):
        """ test not applying invalid x509 cert """
        obj = CURRENT_CONFIG | dict(idp_x509_cert="NOT_A_VALID_CERT")
        self.do_module_test(obj, state=None, failed=True, msg="idp_x509_cert is missing BEGIN and/or END tags")

    def test_invalid_url_update_noop(self):
        """ test not appling an invalid url """
        obj = CURRENT_CONFIG | dict(sp_base_url="test.com")
        self.do_module_test(obj, state=None, failed=True, msg="sp_base_url is not a valid URL")

    def test_invalid_json_update_noop(self):
        """ test not appling an invalid url """
        obj = CURRENT_CONFIG | dict(custom_conf="invalid_json")
        self.do_module_test(obj, state=None, failed=True, msg="custom_conf is not valid JSON")

    ##############
    # test apply
    #
    def test_updated_settings(self):
        """ test updating config """
        obj = CURRENT_CONFIG | dict(idp_groups_attribute="memberOf")
        self.do_module_test(obj, state=None, changed=True, command="update saml2-auth 'https://pfSense.local' set idp_groups_attribute='memberOf'")

    def test_nochange(self):
        """ test applying same config as set """
        obj = CURRENT_CONFIG
        self.do_module_test(obj, state=None, changed=False)
