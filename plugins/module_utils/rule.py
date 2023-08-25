# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Orion Poplawski <orion@nwra.com>
# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import time
import re
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

RULE_ARGUMENT_SPEC = dict(
    name=dict(required=True, type='str'),
    action=dict(default='pass', choices=['pass', 'block', 'match', 'reject']),
    state=dict(default='present', choices=['present', 'absent']),
    disabled=dict(default=False, required=False, type='bool'),
    interface=dict(required=True, type='str'),
    floating=dict(required=False, type='bool'),
    direction=dict(required=False, choices=["any", "in", "out"]),
    ipprotocol=dict(default='inet', choices=['inet', 'inet46', 'inet6']),
    protocol=dict(default='any', choices=["any", "tcp", "udp", "tcp/udp", "icmp", "igmp", "ospf", "esp", "ah", "gre", "pim", "sctp", "pfsync", "carp"]),
    source=dict(required=False, type='str'),
    source_port=dict(required=False, type='str'),
    destination=dict(required=False, type='str'),
    destination_port=dict(required=False, type='str'),
    log=dict(required=False, type='bool'),
    after=dict(required=False, type='str'),
    before=dict(required=False, type='str'),
    tcpflags_any=dict(required=False, type='bool'),
    statetype=dict(default='keep state', choices=['keep state', 'sloppy state', 'synproxy state', 'none']),
    queue=dict(required=False, type='str'),
    ackqueue=dict(required=False, type='str'),
    in_queue=dict(required=False, type='str'),
    out_queue=dict(required=False, type='str'),
    queue_error=dict(default=True, type='bool'),
    gateway=dict(default='default', type='str'),
    tracker=dict(required=False, type='str'),
    icmptype=dict(default='any', required=False, type='str'),
    sched=dict(required=False, type='str'),
    quick=dict(default=False, type='bool'),
)

RULE_REQUIRED_IF = [
    ["floating", True, ["direction"]],
    ["state", "present", ["source", "destination"]],
    ["protocol", "icmp", ["icmptype"]],
]

# These are rule elements that are (currently) unmanaged by this module
RULE_UNMANAGED_ELEMENTS = [
    'created', 'id', 'max', 'max-src-conn', 'max-src-nodes', 'max-src-states', 'os',
    'statetimeout', 'statetype', 'tag', 'tagged', 'updated'
]


class PFSenseRuleModule(PFSenseModuleBase):
    """ module managing pfsense rules """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return RULE_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseRuleModule, self).__init__(module, pfsense)
        self.name = "pfsense_rule"
        self.root_elt = self.pfsense.get_element('filter')
        self.obj = dict()

        self.result['added'] = []
        self.result['deleted'] = []
        self.result['modified'] = []

        self.obj = None
        self._floating = None               # are we on floating rule
        self._floating_interfaces = None    # rule's interfaces before change
        self._after = None                  # insert/move after
        self._before = None                 # insert/move before

        self._position_changed = False
        self.trackers = set()

    ##############################
    # params processing
    #
    def _params_to_obj(self):
        """ return a dict from module params """
        params = self.params

        obj = dict()
        self.obj = obj

        obj['descr'] = params['name']

        if params.get('floating'):
            obj['floating'] = 'yes'
            obj['interface'] = self._parse_floating_interfaces(params['interface'])
        else:
            obj['interface'] = self.pfsense.parse_interface(params['interface'])

        if params['state'] == 'present':
            obj['type'] = params['action']
            obj['ipprotocol'] = params['ipprotocol']
            obj['statetype'] = params['statetype']

            obj['source'] = self.pfsense.parse_address(params['source'])
            if params.get('source_port'):
                self.pfsense.parse_port(params['source_port'], obj['source'])

            obj['destination'] = self.pfsense.parse_address(params['destination'])
            if params.get('destination_port'):
                self.pfsense.parse_port(params['destination_port'], obj['destination'])

            if params['protocol'] not in ['tcp', 'udp', 'tcp/udp'] and ('port' in obj['source'] or 'port' in obj['destination']):
                self.module.fail_json(msg="{0}: you can't use ports on protocols other than tcp, udp or tcp/udp".format(self._get_obj_name()))

            for param in ['destination', 'source']:
                if 'address' in obj[param]:
                    self.pfsense.check_ip_address(obj[param]['address'], obj['ipprotocol'], 'rule')
                if 'network' in obj[param]:
                    self.pfsense.check_ip_address(obj[param]['network'], obj['ipprotocol'], 'rule', allow_networks=True)

            self._get_ansible_param(obj, 'protocol', exclude='any')
            if params['protocol'] == 'icmp':
                self._get_ansible_param(obj, 'icmptype')
            self._get_ansible_param(obj, 'direction')
            self._get_ansible_param(obj, 'queue', fname='defaultqueue')
            if params.get('ackqueue'):
                self._get_ansible_param(obj, 'ackqueue')
            self._get_ansible_param(obj, 'in_queue', fname='dnpipe')
            self._get_ansible_param(obj, 'out_queue', fname='pdnpipe')
            self._get_ansible_param(obj, 'associated-rule-id')
            self._get_ansible_param(obj, 'tracker', exclude='')
            self._get_ansible_param(obj, 'gateway', exclude='default')
            self._get_ansible_param(obj, 'sched')

            self._get_ansible_param_bool(obj, 'disabled', value='')
            self._get_ansible_param_bool(obj, 'log', value='')
            self._get_ansible_param_bool(obj, 'quick')
            self._get_ansible_param_bool(obj, 'tcpflags_any', value='')

        self._floating = 'floating' in self.obj and self.obj['floating'] == 'yes'
        self._after = params.get('after')
        self._before = params.get('before')

        return obj

    def _parse_floating_interfaces(self, interfaces):
        """ validate param interface field when floating is true """
        res = []
        for interface in interfaces.split(','):
            res.append(self.pfsense.parse_interface(interface))
        self._floating_interfaces = interfaces
        return ','.join(res)

    def _validate_params(self):
        """ do some extra checks on input parameters """
        params = self.params

        if params.get('ackqueue') and params['queue'] is None:
            self.module.fail_json(msg='A default queue must be selected when an acknowledge queue is also selected')

        if params.get('ackqueue') and params['ackqueue'] == params['queue']:
            self.module.fail_json(msg='Acknowledge queue and default queue cannot be the same')

        # as in pfSense 2.4, the GUI accepts any queue defined on any interface without checking, we do the same
        if params.get('ackqueue') and self.pfsense.find_queue(params['ackqueue'], enabled=True) is None and params['queue_error']:
            self.module.fail_json(msg='Failed to find enabled ackqueue=%s' % params['ackqueue'])

        if params.get('queue') is not None and self.pfsense.find_queue(params['queue'], enabled=True) is None and params['queue_error']:
            self.module.fail_json(msg='Failed to find enabled queue=%s' % params['queue'])

        if params.get('out_queue') is not None and params['in_queue'] is None:
            self.module.fail_json(msg='A queue must be selected for the In direction before selecting one for Out too')

        if params.get('out_queue') is not None and params['out_queue'] == params['in_queue']:
            self.module.fail_json(msg='In and Out Queue cannot be the same')

        if params.get('out_queue') is not None and self.pfsense.find_limiter(params['out_queue'], enabled=True) is None:
            self.module.fail_json(msg='Failed to find enabled out_queue=%s' % params['out_queue'])

        if params.get('in_queue') is not None and self.pfsense.find_limiter(params['in_queue'], enabled=True) is None:
            self.module.fail_json(msg='Failed to find enabled in_queue=%s' % params['in_queue'])

        if params.get('floating') and params.get('direction') == 'any' and (params['in_queue'] is not None or params['out_queue'] is not None):
            self.module.fail_json(msg='Limiters can not be used in Floating rules without choosing a direction')

        if params.get('after') and params.get('before'):
            self.module.fail_json(msg='Cannot specify both after and before')
        elif params.get('after'):
            if params['after'] == params['name']:
                self.module.fail_json(msg='Cannot specify the current rule in after')
        elif params.get('before'):
            if params['before'] == params['name']:
                self.module.fail_json(msg='Cannot specify the current rule in before')

        # gateway
        if params.get('gateway') is not None and params['gateway'] != 'default':
            if params['ipprotocol'] == 'inet46':
                self.module.fail_json(msg='Gateway selection is not valid for "IPV4+IPV6" address family.')
            elif (self.pfsense.find_gateway_group_elt(params['gateway'], params['ipprotocol']) is None
                  and self.pfsense.find_gateway_elt(params['gateway'], None, params['ipprotocol']) is None):
                self.module.fail_json(msg='Gateway "%s" does not exist or does not match target rule ip protocol.' % params['gateway'])

            if params.get('floating') and params.get('direction') == 'any':
                self.module.fail_json(msg='Gateways can not be used in Floating rules without choosing a direction')

        # tracker
        if params.get('tracker') is not None and int(params['tracker']) < 0:
            self.module.fail_json(msg='tracker {0} must be a positive integer'.format(params['tracker']))

        # sched
        if params.get('sched') is not None and self.pfsense.find_schedule_elt(params['sched']) is None:
            self.module.fail_json(msg='Schedule {0} does not exist'.format(params['sched']))

        # quick
        if params.get('quick') and not params.get('floating'):
            self.module.fail_json(msg='quick can only be used on floating rules')

        # ICMP
        if params.get('protocol') == 'icmp' and params.get('icmptype') is not None:
            both_types = ['any', 'echorep', 'echoreq', 'paramprob', 'redir', 'routeradv', 'routersol', 'timex', 'unreach']
            v4_types = ['althost', 'dataconv', 'inforep', 'inforeq', 'ipv6-here', 'ipv6-where', 'maskrep', 'maskreq', 'mobredir', 'mobregrep', 'mobregreq']
            v4_types += ['photuris', 'skip', 'squench', 'timerep', 'timereq', 'trace']
            v6_types = ['fqdnrep', 'fqdnreq', 'groupqry', 'grouprep', 'groupterm', 'listendone', 'listenrep', 'listqry', 'mtrace', 'mtraceresp', 'neighbradv']
            v6_types += ['neighbrsol', 'niqry', 'nirep', 'routrrenum', 'toobig', 'wrurep', 'wrureq']

            icmptypes = list(set(map(str.strip, params['icmptype'].split(','))))
            icmptypes.sort()
            if '' in icmptypes:
                icmptypes.remove('')
            if len(icmptypes) == 0:
                self.module.fail_json(msg='You must specify at least one icmptype or any for all of them')

            invalids = set(icmptypes) - set(v4_types) - set(v6_types) - set(both_types)
            if len(invalids) > 0:
                self.module.fail_json(msg='ICMP types {0} does not exist'.format(','.join(invalids)))

            if params['ipprotocol'] == 'inet':
                left = set(icmptypes) - set(v4_types) - set(both_types)
            elif params['ipprotocol'] == 'inet6':
                left = set(icmptypes) - set(v6_types) - set(both_types)
            else:   # inet46 only allow
                left = set(icmptypes) - set(both_types)
            if len(left) > 0:
                self.module.fail_json(msg='ICMP types {0} are invalid with IP type {1}'.format(','.join(left), params['ipprotocol']))
            params['icmptype'] = ','.join(icmptypes)

    ##############################
    # XML processing
    #
    def _adjust_separators(self, start_idx, add=True, before=False):
        """ update separators position """
        separators_elt = self.root_elt.find('separator')
        if separators_elt is None:
            return

        separators_elt = separators_elt.find(self.obj['interface'])
        if separators_elt is None:
            return

        for separator_elt in separators_elt:
            row_elt = separator_elt.find('row')
            if row_elt is None or row_elt.text is None:
                continue

            if_elt = separator_elt.find('if')
            if if_elt is None or if_elt.text != self.obj['interface']:
                continue

            match = re.match(r'fr(\d+)', row_elt.text)
            if match:
                idx = int(match.group(1))
                if add:
                    if before:
                        if idx > start_idx:
                            row_elt.text = 'fr' + str(idx + 1)
                    else:
                        if idx >= start_idx:
                            row_elt.text = 'fr' + str(idx + 1)
                elif idx > start_idx:
                    row_elt.text = 'fr' + str(idx - 1)

    def _check_tracker(self):
        """ check the tracking used is unique and change it if required """
        if not self.trackers:
            trackers = self.root_elt.findall('tracker')
            for tracker in trackers:
                self.trackers.add(tracker.text)

        start = int(time.time())
        while self.obj['tracker'] in self.trackers:
            start = start + 1
            self.obj['tracker'] = str(start)

        # keep the tracker for future calls if module is used with aggregate
        self.trackers.add(self.obj['tracker'])

    def _copy_and_add_target(self):
        """ create the XML target_elt """
        timestamp = '%d' % int(time.time())
        self.obj['id'] = ''
        if 'tracker' not in self.obj:
            self.obj['tracker'] = timestamp
        self._check_tracker()

        self.obj['created'] = self.obj['updated'] = dict()
        self.obj['created']['time'] = self.obj['updated']['time'] = timestamp
        self.obj['created']['username'] = self.obj['updated']['username'] = self.pfsense.get_username()
        self.pfsense.copy_dict_to_element(self.obj, self.target_elt)
        self.diff['after'] = self._rule_element_to_dict()
        self._insert(self.target_elt)
        self.result['added'].append(self.obj)

    def _copy_and_update_target(self):
        """ update the XML target_elt """
        timestamp = '%d' % int(time.time())
        before = self._rule_element_to_dict()
        if 'tracker' not in self.obj:
            self.obj['tracker'] = before['tracker']

        if 'associated-rule-id' not in self.obj and 'associated-rule-id' in before and before['associated-rule-id'] != '':
            self.module.fail_json(msg='Target filter rule is associated with a NAT rule.')

        self.diff['before'] = before
        changed = self.pfsense.copy_dict_to_element(self.obj, self.target_elt)
        if self._remove_deleted_params():
            changed = True

        if self._update_rule_position(self.target_elt):
            changed = True

        if changed:
            updated_elt = self.target_elt.find('updated')
            if updated_elt is None:
                updated_elt = self.pfsense.new_element('updated')
                updated_elt.append(self.pfsense.new_element('time', timestamp))
                updated_elt.append(self.pfsense.new_element('username', self.pfsense.get_username()))
                self.target_elt.append(updated_elt)
            else:
                updated_elt.find('time').text = timestamp
                updated_elt.find('username').text = self.pfsense.get_username()
            self.diff['after'].update(self._rule_element_to_dict())
            self.result['modified'].append(self._rule_element_to_dict())

        return (before, changed)

    def _create_target(self):
        """ create the XML target_elt """
        return self.pfsense.new_element('rule')

    def _find_matching_rule(self):
        """ return rule element and index that matches by description or action """
        # Prioritize matching my name
        if 'associated-rule-id' in self.obj:
            found, i = self._find_rule(self.obj['associated-rule-id'], 'associated-rule-id')
            if found is not None:
                return (found, i)

        found, i = self._find_rule(self.obj['descr'])
        if found is not None:
            return (found, i)

        # Match action without name/descr
        match_rule = self.obj.copy()
        del match_rule['descr']
        for rule_elt in self.root_elt:
            this_rule = self.pfsense.element_to_dict(rule_elt)
            this_rule.pop('descr', None)
            # Remove unmanaged elements
            for unwanted in RULE_UNMANAGED_ELEMENTS:
                this_rule.pop(unwanted, None)
            if this_rule == match_rule:
                return (rule_elt, i)
            i += 1

        return (None, -1)

    def _find_rule(self, value, field='descr'):
        """ return rule element and index on interface/floating that matches criteria """
        i = 0
        for rule_elt in self.root_elt:
            field_elt = rule_elt.find(field)
            if self._match_interface(rule_elt) and field_elt is not None and field_elt.text == value:
                return (rule_elt, i)
            i += 1
        return (None, -1)

    def _find_target(self):
        """ find the XML target_elt """
        rule_elt, dummy = self._find_matching_rule()
        if rule_elt is not None and self._floating:
            ifs_elt = rule_elt.find('interface')
            self._floating_interfaces = ','.join([self.pfsense.get_interface_display_name(interface) for interface in ifs_elt.text.split(',')])

        return rule_elt

    def _get_expected_rule_position(self):
        """ get expected rule position in interface/floating """
        if self._before == 'bottom':
            return self.pfsense.get_interface_rules_count(self.obj['interface'], self._floating) - 1
        elif self._after == 'top':
            return 0
        elif self._after is not None:
            return self._get_rule_position(self._after) + 1
        elif self._before is not None:
            position = self._get_rule_position(self._before) - 1
            if position < 0:
                return 0
            return position
        else:
            position = self._get_rule_position(self._after, fail=False)
            if position is not None:
                return position
            return self.pfsense.get_interface_rules_count(self.obj['interface'], self._floating)
        return -1

    def _get_expected_rule_xml_index(self):
        """ get expected rule index in xml """
        if self._before == 'bottom':
            return self._get_last_rule_xml_index() + 1
        elif self._after == 'top':
            return self._get_first_rule_xml_index()
        elif self._after is not None:
            found, i = self._find_rule(self._after)
            if found is not None:
                return i + 1
            else:
                self.module.fail_json(msg='Failed to insert after rule=%s interface=%s' % (self._after, self._interface_name()))
        elif self._before is not None:
            found, i = self._find_rule(self._before)
            if found is not None:
                return i
            else:
                self.module.fail_json(msg='Failed to insert before rule=%s interface=%s' % (self._before, self._interface_name()))
        else:
            found, i = self._find_rule(self.obj['descr'])
            if found is not None:
                return i
            return self._get_last_rule_xml_index() + 1
        return -1

    def _get_first_rule_xml_index(self):
        """ Find the first rule for the interface/floating and return its xml index """
        i = 0
        for rule_elt in self.root_elt:
            if self._match_interface(rule_elt):
                break
            i += 1
        return i

    def _get_last_rule_xml_index(self):
        """ Find the last rule for the interface/floating and return its xml index """
        last_found = -1
        i = 0
        for rule_elt in self.root_elt:
            if self._match_interface(rule_elt):
                last_found = i
            i += 1
        return last_found

    @staticmethod
    def _get_params_to_remove():
        """ returns the list of params to remove if they are not set """
        return ['log', 'protocol', 'disabled', 'defaultqueue', 'ackqueue', 'dnpipe', 'pdnpipe', 'gateway', 'icmptype', 'sched', 'quick', 'tcpflags_any']

    def _get_rule_position(self, descr=None, fail=True):
        """ get rule position in interface/floating """
        if descr is None:
            descr = self.obj['descr']

        res = self.pfsense.get_rule_position(descr, self.obj['interface'], self._floating)
        if fail and res is None:
            self.module.fail_json(msg='Failed to find rule=%s interface=%s' % (descr, self._interface_name()))
        return res

    def _insert(self, rule_elt):
        """ insert rule into xml """
        rule_xml_idx = self._get_expected_rule_xml_index()
        self.root_elt.insert(rule_xml_idx, rule_elt)

        rule_position = self._get_rule_position()
        self._adjust_separators(rule_position, before=(self._after is None and self._before is not None))

    def _match_interface(self, rule_elt):
        """ check if a rule elt match the targeted interface """
        return self.pfsense.rule_match_interface(rule_elt, self.obj['interface'], self._floating)

    def _update_rule_position(self, rule_elt):
        """ move rule in xml if required """
        current_position = self._get_rule_position()
        expected_position = self._get_expected_rule_position()
        if current_position == expected_position:
            self._position_changed = False
            return False

        self.diff['before']['position'] = current_position
        self.diff['after']['position'] = expected_position
        self._adjust_separators(current_position, add=False)
        self.root_elt.remove(rule_elt)
        self._insert(rule_elt)
        self._position_changed = True
        return True

    ##############################
    # run
    #
    def _pre_remove_target_elt(self):
        """ processing before removing elt """
        self._adjust_separators(self._get_rule_position(), add=False)
        self.diff['before'] = self._rule_element_to_dict()
        self.result['deleted'].append(self._rule_element_to_dict())

    def _rule_element_to_dict(self):
        """ convert rule_elt to dictionary like module arguments """
        rule = self.pfsense.element_to_dict(self.target_elt)

        # We use 'name' for 'descr'
        rule['name'] = rule.pop('descr', 'UNKNOWN')
        # We use 'action' for 'type'
        rule['action'] = rule.pop('type', 'UNKNOWN')

        # Convert addresses to argument format
        for addr_item in ['source', 'destination']:
            rule[addr_item], rule[addr_item + '_port'] = self.pfsense.addr_normalize(rule[addr_item])

        return rule

    def _update(self):
        """ make the target pfsense reload rules """
        return self.pfsense.phpshell('''require_once("filter.inc");
if (filter_configure() == 0) { clear_subsystem_dirty('filter'); }''')

    ##############################
    # Logging
    #
    def _get_obj_name(self):
        """ return obj's name """
        return "'{0}' on '{1}'".format(self.obj['descr'], self._interface_name())

    def _interface_name(self):
        """ return formated interface name for logging """
        if self._floating:
            if self._floating_interfaces is not None:
                return 'floating(' + self._floating_interfaces + ')'
            return 'floating(' + self.params['interface'] + ')'
        return self.params['interface']

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''
        if before is None:
            values += self.format_cli_field(self.params, 'source')
            values += self.format_cli_field(self.params, 'source_port')
            values += self.format_cli_field(self.params, 'destination')
            values += self.format_cli_field(self.params, 'destination_port')
            values += self.format_cli_field(self.params, 'protocol', default='any')
            values += self.format_cli_field(self.params, 'direction')
            values += self.format_cli_field(self.params, 'ipprotocol', default='inet')
            values += self.format_cli_field(self.params, 'icmptype', default='any')
            values += self.format_cli_field(self.params, 'tcpflags_any', fvalue=self.fvalue_bool)
            values += self.format_cli_field(self.params, 'statetype', default='keep state')
            values += self.format_cli_field(self.params, 'action', default='pass')
            values += self.format_cli_field(self.params, 'disabled', fvalue=self.fvalue_bool, default=False)
            values += self.format_cli_field(self.params, 'log', fvalue=self.fvalue_bool, default=False)
            values += self.format_cli_field(self.params, 'after')
            values += self.format_cli_field(self.params, 'before')
            values += self.format_cli_field(self.params, 'queue')
            values += self.format_cli_field(self.params, 'ackqueue')
            values += self.format_cli_field(self.params, 'in_queue')
            values += self.format_cli_field(self.params, 'out_queue')
            values += self.format_cli_field(self.params, 'gateway', default='default')
            values += self.format_cli_field(self.params, 'tracker')
            values += self.format_cli_field(self.params, 'sched')
            values += self.format_cli_field(self.params, 'quick', fvalue=self.fvalue_bool, default=False)
        else:
            fbefore = self._obj_to_log_fields(before)
            fafter = self._obj_to_log_fields(self.obj)
            fafter['before'] = self._before
            fafter['after'] = self._after

            values += self.format_updated_cli_field(fafter, fbefore, 'source', add_comma=(values))
            values += self.format_updated_cli_field(fafter, fbefore, 'source_port', add_comma=(values))
            values += self.format_updated_cli_field(fafter, fbefore, 'destination', add_comma=(values))
            values += self.format_updated_cli_field(fafter, fbefore, 'destination_port', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'protocol', none_value="'any'", add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'icmptype', add_comma=(values))
            values += self.format_updated_cli_field(fafter, fbefore, 'interface', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'floating', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'direction', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'ipprotocol', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'tcpflags_any', fvalue=self.fvalue_bool, add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'statetype', add_comma=(values))
            values += self.format_updated_cli_field(self.params, before, 'action', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'disabled', fvalue=self.fvalue_bool, add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'log', fvalue=self.fvalue_bool, add_comma=(values))
            if self._position_changed:
                values += self.format_updated_cli_field(fafter, {}, 'after', log_none=False, add_comma=(values))
                values += self.format_updated_cli_field(fafter, {}, 'before', log_none=False, add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'defaultqueue', fname='queue', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'ackqueue', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'dnpipe', fname='in_queue', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'pdnpipe', fname='out_queue', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'gateway', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'tracker', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'sched', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'quick', fvalue=self.fvalue_bool, add_comma=(values))
        return values

    def _obj_address_to_log_field(self, rule, addr):
        """ return formated address from dict """
        field = ''
        field_port = ''
        if isinstance(rule[addr], dict):
            if 'not' in rule[addr]:
                field += '!'
            if 'any' in rule[addr]:
                field += 'any'
            if 'address' in rule[addr]:
                field += rule[addr]['address']
            elif 'network' in rule[addr]:
                interface = None
                if rule[addr]['network'].endswith('ip'):
                    interface = self.pfsense.get_interface_display_name(rule[addr]['network'][:-2], return_none=True)

                if interface is None:
                    field += 'NET:' + self.pfsense.get_interface_display_name(rule[addr]['network'])
                else:
                    field += 'IP:' + interface

            if 'port' in rule[addr]:
                field_port += rule[addr]['port']
        else:
            if rule[addr].startswith('NET:'):
                field = 'NET:' + self.pfsense.get_interface_display_name(rule[addr][4:])
            elif rule[addr].startswith('IP:'):
                field = 'IP:' + self.pfsense.get_interface_display_name(rule[addr][3:])
            else:
                field = rule[addr]
            field_port = rule[addr + '_port']
        return field, field_port

    def _obj_to_log_fields(self, rule):
        """ return formated source and destination from dict """
        res = {}
        res['source'], res['source_port'] = self._obj_address_to_log_field(rule, 'source')
        res['destination'], res['destination_port'] = self._obj_address_to_log_field(rule, 'destination')
        res['interface'] = ','.join([self.pfsense.get_interface_display_name(interface) for interface in rule['interface'].split(',')])
        return res
