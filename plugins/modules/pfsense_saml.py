#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Kevin Brooks <kbrooks81@proton.me>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

INSTALLATION = """
- name: Set pfSense-pkg-saml2-auth url for pfSense version 2.8
  tags:
    - setup
  set_fact:
    pfSense_saml2_pkg: https://github.com/pfrest/pfSense-pkg-saml2-auth/releases/latest/download/pfSense-2.8-pkg-saml2-auth.pkg

- name: Add plugin pfSense-pkg-saml2-auth to repo
  tags:
    - setup
  command: pkg add {{ pfSense_saml2_pkg }}
  register: pkg_command
  changed_when: not pkg_command.stdout is search("is already installed")
"""

DOCUMENTATION = """
---
module: pfsense_saml
version_added: 0.8.0
short_description: Manage pfSense SAML configuration
description:
  - Manage pfSense-pkg-saml2-auth configuration
author: Kevin Brooks (@KevinB-rocks)
notes:
options:
  enable:
    description: State of authentication through SAML
    default: true
    type: bool
  strip_username:
    description: State of removal of @domain.example from emails in NameID
    default: false
    type: bool
  debug_mode:
    description: State of debug mode
    default: false
    type: bool
  idp_metadata_url:
    description: Metadata URL to IdP for automatic settings
    default: ""
    type: str
  idp_entity_id:
    description: Entity ID of the upstream IdP.
    default: ""
    type: str
  idp_sign_on_url:
    description: Sign-on ID of the upstream IdP.
    default: ""
    type: str
  idp_groups_attribute:
    description: Name of groups attribute returned in the SAML assertion for groups based privilege mapping.
    default: ""
    type: str
  idp_x509_cert:
    description: x509 cert provided by the IdP.
    default: ""
    type: str
  sp_base_url:
    description: Base URL of pfSense.
    required: true
    type: str
  custom_conf:
    description: JSON-config extending the explicitly defined fields. Must comply with OneLogin PHP-SAML format. Use at your own risk.
    default: ""
    type: str
"""

EXAMPLES = """
- name: Modify SAML config
  pfsense_saml:
    enable: true
    idp_metadata_url: https://keycloak.local/realms/master/protocol/saml/descriptor
    sp_base_url: https://pfSense.local
"""

RETURN = """

"""

import re
import json
from urllib.parse import urlparse

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

SAML_ARGUMENT_SPEC = dict(
    enable=dict(default=True, type="bool"),
    strip_username=dict(default=False, type="bool"),
    debug_mode=dict(default=False, type="bool"),
    idp_metadata_url=dict(default="", type="str"),
    idp_entity_id=dict(default="", type="str"),
    idp_sign_on_url=dict(default="", type="str"),
    idp_groups_attribute=dict(default="", type="str"),
    idp_x509_cert=dict(default="", type="str"),
    sp_base_url=dict(required=True, type="str"),
    custom_conf=dict(default="", type="str"),
)

IDP_ENTITY_REGEX = r"[a-zA-Z0-9\-._~:\/?#\[\]@!$&'()*+,;=]+"

class PFSenseSAMLModule(PFSenseModuleBase):
    """ module managing saml config """

    ##############################
    # unit tests
    #
    # Must be class method for unit test usage
    @staticmethod
    def get_argument_spec():
        """return argument spec"""
        return SAML_ARGUMENT_SPEC

    def __init__(self, module, pfsense=None):
        super(PFSenseSAMLModule, self).__init__(module, pfsense, key="sp_base_url")

        self.name = "saml2-auth"
        self.root_elt = self._find_target()
        self.obj = dict()

    ##############################
    # params processing
    #
    def _validate_set_if_idp_metadata_unset(self, params, key):
        if params[key] == "":
            if params["idp_metadata_url"] == "":
                self.module.fail_json(msg="{0} is required when idp_metadata_url is unset".format(key))

    def _validate_url(self, params, key):
        try:
            url = urlparse(params[key])
            if not all([url.scheme, url.netloc]):
                raise Exception
        except Exception:
            self.module.fail_json(msg="{0} is not a valid URL".format(key))

    def _validate_params(self):
        """do some extra checks on input parameters"""

        params = self.params

        self._validate_url(params, "sp_base_url")

        if params["idp_metadata_url"] != "":
            self._validate_url(params, "idp_metadata_url")

        self._validate_set_if_idp_metadata_unset(params, "idp_entity_id")
        if params["idp_entity_id"] != "":
            if len(params["idp_entity_id"]) > 1024:
                self.module.fail_json(msg="idp_entity_id must be less than 1025 characters long")
            if not re.fullmatch(IDP_ENTITY_REGEX, params["idp_entity_id"]):
                self.module.fail_json(msg="idp_entity_id contains invalid characters")

        self._validate_set_if_idp_metadata_unset(params, "idp_sign_on_url")
        if params["idp_sign_on_url"] != "":
            self._validate_url(params, "idp_sign_on_url")

        self._validate_set_if_idp_metadata_unset(params, "idp_x509_cert")
        if params["idp_x509_cert"] != "":
            if not (params["idp_x509_cert"].startswith("-----BEGIN CERTIFICATE-----") and params["idp_x509_cert"].endswith("-----END CERTIFICATE-----")):
                self.module.fail_json(msg="idp_x509_cert is missing BEGIN and/or END tags")

        if params["custom_conf"] != "":
            try:
                json.loads(params["custom_conf"])
            except json.decoder.JSONDecodeError:
                self.module.fail_json(msg="custom_conf is not valid JSON")

    ##############################
    # XML processing
    #
    def _find_target(self):
        installed_pkgs_elt = self.pfsense.get_element("installedpackages")
        pkgs_elts = installed_pkgs_elt.findall("package") if installed_pkgs_elt is not None else None

        for elt in pkgs_elts:
            pkg_name = elt.find("internal_name")
            if pkg_name is not None and pkg_name.text == self.name:
                conf_elt = elt.find("conf")
                if conf_elt is not None:
                    return conf_elt

        return self.module.fail_json(msg="Unable to find XML configuration entry. Are you sure SAML2 package is installed?")

    def _copy_and_update_target(self):
        """ update the XML target_elt """

        self.diff["before"] = self.pfsense.element_to_dict(self.target_elt)
        self.diff["after"] = self.pfsense.element_to_dict(self.target_elt)

        changed = self.pfsense.copy_dict_to_element(self.obj, self.target_elt)

        return (self.diff["before"], changed)

    ##############################
    # logging
    #
    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ""

        if before is None:
            values += self.format_cli_field(self.obj, "enable", fvalue=self.fvalue_bool, none_value='')
            values += self.format_cli_field(self.obj, "strip_username", fvalue=self.fvalue_bool, none_value='')
            values += self.format_cli_field(self.obj, "debug_mode", fvalue=self.fvalue_bool, none_value='')
            values += self.format_cli_field(self.obj, "idp_metadata_url")
            values += self.format_cli_field(self.obj, "idp_entity_id")
            values += self.format_cli_field(self.obj, "idp_sign_on_url")
            values += self.format_cli_field(self.obj, "idp_groups_attribute")
            values += self.format_cli_field(self.obj, "idp_x509_cert")
            values += self.format_cli_field(self.obj, "sp_base_url")
            values += self.format_cli_field(self.obj, "custom_config")
        else:
            values += self.format_updated_cli_field(self.obj, before, "enable", add_comma=(values), fvalue=self.fvalue_bool, none_value='')
            values += self.format_updated_cli_field(self.obj, before, "strip_username", add_comma=(values), fvalue=self.fvalue_bool, none_value='')
            values += self.format_updated_cli_field(self.obj, before, "debug_mode", add_comma=(values), fvalue=self.fvalue_bool, none_value='')
            values += self.format_updated_cli_field(self.obj, before, "idp_metadata_url", add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, "idp_entity_id", add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, "idp_sign_on_url", add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, "idp_groups_attribute", add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, "idp_x509_cert", add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, "sp_base_url", add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, "custom_config", add_comma=(values))
        return values

def main():
    module = AnsibleModule(
        argument_spec=SAML_ARGUMENT_SPEC,
        supports_check_mode=True,
    )

    pfmodule = PFSenseSAMLModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == "__main__":
    main()
