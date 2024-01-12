# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Orion Poplawski <orion@nwra.com>
# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

ALIAS_ARGUMENT_SPEC = dict(
    name=dict(required=True, type='str'),
    state=dict(default='present', choices=['present', 'absent']),
    type=dict(default=None, required=False, choices=['host', 'network', 'port', 'urltable', 'urltable_ports']),
    address=dict(default=None, required=False, type='str'),
    url=dict(default=None, required=False, type='str'),
    descr=dict(default=None, required=False, type='str'),
    detail=dict(default=None, required=False, type='str'),
    updatefreq=dict(default=None, required=False, type='int'),
)

ALIAS_PARAM_FORCE = ['descr', 'detail']

ALIAS_MUTUALLY_EXCLUSIVE = [
    ('address', 'url'),
]

ALIAS_REQUIRED_IF = [
    ["state", "present", ["type"]],
    ["type", "host", ["address"]],
    ["type", "network", ["address"]],
    ["type", "port", ["address"]],
    ["type", "urltable", ["updatefreq"]],
    ["type", "urltable_ports", ["updatefreq"]],
    # When "address" deprecation period is over
    # ["type", "urltable", ["updatefreq", "url"]],
    # ["type", "urltable_ports", ["updatefreq", "url"]],
]

ALIAS_MAP_PARAM_IF = [
    ["type", "urltable", ("address", "url")],
    ["type", "urltable_ports", ("address", "url")],
]

ALIAS_PHP_COMMAND_SET = """
require_once("filter.inc");
if (filter_configure() == 0) { clear_subsystem_dirty('aliases'); }
"""


class PFSenseAliasModule(PFSenseModuleBase):
    """ module managing pfsense aliases """

    ##############################
    # unit tests
    #
    # Must be class method for unit test usage
    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return ALIAS_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseAliasModule, self).__init__(module, pfsense, root='aliases', node='alias', key='name', update_php=ALIAS_PHP_COMMAND_SET,
                                                 map_param_if=ALIAS_MAP_PARAM_IF, param_force=ALIAS_PARAM_FORCE)
        # Override for use with aggregate
        self.argument_spec = ALIAS_ARGUMENT_SPEC

    ##############################
    # params processing
    #
    def _validate_params(self):
        """ do some extra checks on input parameters """
        params = self.params

        # check name
        self.pfsense.check_name(params['name'], 'alias')

        if params['state'] == 'present':
            # the GUI does not allow to create 2 aliases with same name and differents types
            alias_elt = self.pfsense.find_alias(params['name'])
            if alias_elt is not None:
                if params['type'] not in ['host', 'network'] or alias_elt.find('type').text not in ['host', 'network']:
                    if params['type'] != alias_elt.find('type').text:
                        self.module.fail_json(msg='An alias with this name and a different type already exists: \'{0}\''.format(params['name']))

            if self.pfsense.get_interface_by_display_name(params['name']) is not None:
                self.module.fail_json(msg='An interface description with this name already exists: \'{0}\''.format(params['name']))

            missings = ['type']
            for param, value in params.items():
                if param in missings and value is not None and value != '':
                    missings.remove(param)
            if missings:
                self.module.fail_json(msg='state is present but all of the following are missing: ' + ','.join(missings))

            # updatefreq is for urltable only
            if params['updatefreq'] is not None and params['type'] != 'urltable' and params['type'] != 'urltable_ports':
                self.module.fail_json(msg='updatefreq is only valid with type urltable or urltable_ports')

            # check details count
            details = params['detail'].split('||') if params['detail'] is not None else []
            if params['address'] is not None:
                addresses = params['address'].split(' ')
                if len(details) > len(addresses):
                    self.module.fail_json(msg='Too many details in relation to addresses')
                if params['type'] in ['urltable', 'urltable_ports']:
                    self.module.warn('Use of "address" with {type} is depracated, please use "url" instead'.format(type=params['type']))

            # pfSense GUI rule
            for detail in details:
                if detail.startswith('|') or detail.endswith('|'):
                    self.module.fail_json(msg='Vertical bars (|) at start or end of descriptions not allowed')

    ##############################
    # Logging
    #
    def _get_obj_name(self):
        """ return obj's name """
        return "'" + self.obj['name'] + "'"

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''
        if before is None:
            values += self.format_cli_field(self.obj, 'type')
            values += self.format_cli_field(self.obj, 'address')
            values += self.format_cli_field(self.obj, 'url')
            values += self.format_cli_field(self.obj, 'updatefreq')
            values += self.format_cli_field(self.obj, 'descr')
            values += self.format_cli_field(self.obj, 'detail')
        else:
            values += self.format_updated_cli_field(self.obj, before, 'type', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'address', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'url', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'updatefreq', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'descr', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'detail', add_comma=(values))
        return values
