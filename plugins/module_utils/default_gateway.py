# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# Copyright: (c) 2023, Nicolas Zagulajew <github@xoop.org>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase


DEFAULT_GATEWAY_ARGUMENT_SPEC = dict(
    gateway=dict(type='str'),
    ipprotocol=dict(default='inet', choices=['inet', 'inet6']),
)


class PFSenseDefaultGatewayModule(PFSenseModuleBase):
    """ module managing pfsense default gateways """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return DEFAULT_GATEWAY_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseDefaultGatewayModule, self).__init__(module, pfsense)
        self.name = "pfsense_default_gateway"
        self.root_elt = self.pfsense.get_element('gateways')
        self.target_elt = self.root_elt
        self.obj = dict()
        self.interface_elt = None
        self.read_only = False

    ##############################
    # params processing
    #
    def _params_to_obj(self):
        """ return a dict from module params
        gateway     required, str
        ipprotocol  default : inet, choice inet/inet6
        """
        params = self.params

        obj = dict()

        # Modification
        if params["gateway"]:
            my_defaultgw = self._gw2machine(params['gateway'])
            if params['ipprotocol'] == "inet":
                obj['defaultgw4'] = my_defaultgw
                self.result["defaultgw4"] = params["gateway"]
            elif params['ipprotocol'] == "inet6":
                obj['defaultgw6'] = my_defaultgw
                self.result["defaultgw6"] = params["gateway"]
            else:
                self.module.fail_json(msg='Please specify a valid ipprotocol (inet/inet6)')

        return obj

    def _validate_params(self):
        """ do some extra checks on input parameters
        gateway        required, str
        ipprotocol  default : inet, choice inet/inet6
        """
        params = self.params
        gateway_list = ["none", "automatic"] + [gw["Name"] for gw in self.pfsense.find_active_gateways()]

        # get list of current default gateways and append gateway_groups to list
        for elt in self.root_elt:
            if elt.tag in ["gateway_group"]:
                gateway_list.append(elt.find("name").text)
            elif elt.tag == "defaultgw4":
                self.result["defaultgw4"] = self._gw2human(elt.text)
            elif elt.tag == "defaultgw6":
                self.result["defaultgw6"] = self._gw2human(elt.text)

        if params["gateway"]:
            if str(params["gateway"]) not in gateway_list:
                self.module.fail_json(msg="Unknown gateway %s : %s" % (params["gateway"], gateway_list))

    ##############################
    # XML processing
    #
    def _create_target(self):
        """ create the XML target_elt """
        if self.params["ipprotocol"] == "inet":
            return self.pfsense.new_element('defaultgw4')
        elif self.params["ipprotocol"] == "inet6":
            return self.pfsense.new_element('defaultgw6')

    ##############################
    # Utilities
    #

    @staticmethod
    def _gw2machine(gateway):
        """
        Translates special gateway to machine-readable
        "-" means none
        "" means automatic
        """
        if gateway is not None:
            if gateway.lower() == "automatic":
                return ""
            elif gateway.lower() == "none":
                return "-"
        return gateway

    @staticmethod
    def _gw2human(gateway):
        """
        Translates special gateway as human-readable
        "-" means none
        "" means automatic
        """
        if gateway is None:
            return "automatic"
        elif gateway == "-":
            return "none"
        else:
            return gateway

    @staticmethod
    def _get_params_to_remove():
        """ returns the list of params to remove if they are not set """
        return []

    ##############################
    def run(self, params):
        """ process input params to add/update/delete """
        self.params = params
        self._check_deprecated_params()
        self._check_onward_params()
        self._validate_params()

        self.obj = self._params_to_obj()

        if params["gateway"]:
            self._add()

    def _update(self):
        """ make the target pfsense reload """
        return self.pfsense.phpshell('''
require_once("filter.inc");
$retval = 0;

$retval |= system_routing_configure();
$retval |= system_resolvconf_generate();
$retval |= filter_configure();
/* reconfigure our gateway monitor */
setup_gateways_monitor();
/* Dynamic DNS on gw groups may have changed */
send_event("service reload dyndnsall");

if ($retval == 0) clear_subsystem_dirty('staticroutes');
''')

    ##############################
    # Logging
    #
    def _get_obj_name(self):
        """ return obj's name """
        return ""

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''
        if self.params["ipprotocol"] == "inet":
            values += self.format_updated_cli_field(self.obj, before, 'defaultgw4', add_comma=values)
        elif self.params["ipprotocol"] == "inet6":
            values += self.format_updated_cli_field(self.obj, before, 'defaultgw6', add_comma=values)

        return values
