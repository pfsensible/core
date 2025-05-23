#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: pfsense_rfc2136

short_description: Manage pfSense rfc2136 dynamic DNS updates

version_added: "0.7.0"

description:
  - Manage pfSense rfc2136 dynamic DNS updates.

options:
  descr:
    description: The description of the rfc2136 DDNS update. This is used as a unique key by pfSensible.
    required: true
    type: str
  state:
    description: State in which to leave the rfc2136 DDNS update.
    default: present
    choices: ['present', 'absent']
    type: str
  enable:
    description: Enable the rfc2136 DDNS update.
    type: bool
  interface:
    description:
      - Interface to monitor for updates. The address of this interface will be used in the updated DNS record.
    default: wan
    type: str
  host:
    description: Fully qualified hostname of the host to be updated.
    type: str
  zone:
    description: Hostname zone (optional).
    type: str
  ttl:
    description: TTL (seconds) of the DNS entry.
    type: int
  keyname:
    description: This must match the update key name on the DNS server.
    type: str
  keyalgorithm:
    description: Key algorithm of the DNS update key. Defaults to hmac-md5 which is decpracted at this point.
    default: hmac-md5
    choices: ['hmac-md5', 'hmac-sha1', 'hmac-sha224', 'hmac-sha256', 'hmac-sha384', 'hmac-sha512']
    type: str
  keydata:
    description: The secret TSIG domain key.
    type: str
  server:
    description: DNS server to send the update.
    type: str
  usetcp:
    description: Use TCP instead of UDP.
    type: bool
  usepublicip:
    description: If the interface IP is private, attempt to fetch and use the public IP instead.
    type: bool
  updatesource:
    description: Interface or address from which the firewall will send the DNS update request. Defaults to the IP of `interface` above.
    default: ''
    type: str
  updatesourcefamily:
    description: Address family to use for sourcing updates. Defaults to automatic detection.
    default: ''
    choices: ['', 'inet', 'inet6']
    type: str
  recordtype:
    description: Record type to update.
    choices: ['A', 'AAAA', 'both']
    type: str

author: Orion Poplawski (@opoplawski)
'''

EXAMPLES = r'''
- name: Add myitem rfc2136
  pfsensible.core.pfsense_rfc2136:
    descr: myitem
    enable: true
    interface: WANGW_FAILOVER
    host: hos2
    zone: nwra.com
    ttl: 600
    keyname: DDNS_UPDATE
    keyalgorithm: hmac-sha512
    keydata: blah
    server: 8.8.8.8
    usetcp: true
    usepublicip: true
    updatesource: opt10
    updatesourcefamily: inet6
    recordtype: AAAA
    state: present

- name: Remove myitem rfc2136
  pfsensible.core.pfsense_rfc2136:
    descr: myitem
    state: absent
'''
RETURN = r'''
commands:
    description: the set of commands that would be pushed to the remote device (if pfSense had a CLI).
    returned: always
    type: list
    sample: ["create rfc2136 'myitem'", "update rfc2136 'myitem' set ...", "delete rfc2136 'myitem'"]
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase
from ansible_collections.pfsensible.core.plugins.module_utils.arg_route import p2o_interface_with_gwgroup

RFC2136_ARGUMENT_SPEC = dict(
    # Only descr should be required here - othewise you cannot remove an item with just 'descr'
    # Required arguments for creation should be noted in RFC2136_REQUIRED_IF = ['state', 'present', ...] below
    descr=dict(required=True, type='str'),
    enable=dict(type='bool'),
    state=dict(type='str', default='present', choices=['present', 'absent']),
    interface=dict(type='str', default='wan'),
    host=dict(type='str'),
    zone=dict(type='str'),
    ttl=dict(type='int'),
    keyname=dict(type='str'),
    keyalgorithm=dict(type='str', choices=['hmac-md5', 'hmac-sha1', 'hmac-sha224', 'hmac-sha256', 'hmac-sha384', 'hmac-sha512'], default='hmac-md5'),
    keydata=dict(type='str', no_log=True),
    server=dict(type='str'),
    usetcp=dict(type='bool'),
    usepublicip=dict(type='bool'),
    updatesource=dict(type='str', default=''),
    updatesourcefamily=dict(type='str', choices=['', 'inet', 'inet6'], default=''),
    recordtype=dict(type='str', choices=['A', 'AAAA', 'both'],),
)

# TODO - Check for validity - what parameters are actually required when creating a new rfc2136?
RFC2136_REQUIRED_IF = [
    ['state', 'present', ['host', 'ttl', 'keyname', 'keydata', 'recordtype']],
]

# TODO - Review this for clues for input validation.  Search for functions in the below require_once files in /etc and /usr/local/pfSense/include
PHP_VALIDATION = r'''
require_once("guiconfig.inc");



unset($input_errors);
$pconfig = $_POST;

/* input validation */
$reqdfields = array('host', 'ttl', 'keyname', 'keydata');
$reqdfieldsn = array(gettext("Hostname"), gettext("TTL"), gettext("Key name"), gettext("Key"));

do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);

if ($_POST['host'] && !is_domain($_POST['host'])) {
    $input_errors[] = gettext("The DNS update host name contains invalid characters.");
}
if ($_POST['zone'] && !is_domain($_POST['zone'])) {
    $input_errors[] = gettext("The DNS zone name contains invalid characters.");
}
if ($_POST['ttl'] && !is_numericint($_POST['ttl'])) {
    $input_errors[] = gettext("The DNS update TTL must be an integer.");
}
if ($_POST['keyname'] && !is_domain($_POST['keyname'])) {
    $input_errors[] = gettext("The DNS update key name contains invalid characters.");
}
if ($_POST['keyalgorithm'] && !array_key_exists($_POST['keyalgorithm'], $tsig_key_algos)) {
    $input_errors[] = gettext("The DNS update key algorithm is invalid.");
}

if (!$input_errors) {
    $rfc2136 = array();
    $rfc2136['enable'] = $_POST['enable'] ? true : false;
    $rfc2136['host'] = $_POST['host'];
    $rfc2136['zone'] = $_POST['zone'];
    $rfc2136['ttl'] = $_POST['ttl'];
    $rfc2136['keyname'] = $_POST['keyname'];
    $rfc2136['keyalgorithm'] = $_POST['keyalgorithm'];
    $rfc2136['keydata'] = $_POST['keydata'];
    $rfc2136['server'] = $_POST['server'];
    $rfc2136['usetcp'] = $_POST['usetcp'] ? true : false;
    $rfc2136['usepublicip'] = $_POST['usepublicip'] ? true : false;
    $rfc2136['recordtype'] = $_POST['recordtype'];
    $rfc2136['interface'] = $_POST['interface'];
    $rfc2136['updatesource'] = $_POST['updatesource'];
    $rfc2136['updatesourcefamily'] = $_POST['updatesourcefamily'];
    $rfc2136['descr'] = $_POST['descr'];

    if ($this_rfc2136_config && !$dup) {
        config_set_path("dnsupdates/dnsupdate/{$id}", $rfc2136);
    } else {
        config_set_path('dnsupdates/dnsupdate/', $rfc2136);
    }

    write_config(gettext("New/Edited RFC2136 dnsupdate entry was posted."));

    if ($_POST['force']) {
        $retval = services_dnsupdate_process("", $rfc2136['host'], true);
    } else {
        $retval = services_dnsupdate_process();
    }

    header("Location: services_rfc2136.php");
    exit;
}

'''

# TODO - Add validation and parsing methods for parameters that require it
RFC2136_ARG_ROUTE = dict(
    interface=dict(parse=p2o_interface_with_gwgroup,),
)

# TODO - Check for validity - what are default values when creating a new rfc2136
RFC2136_CREATE_DEFAULT = dict(
    interface='wan',
    keyalgorithm='hmac-md5',
    updatesource='',
    updatesourcefamily='',
)


class PFSenseRfc2136Module(PFSenseModuleBase):
    """ module managing pfsense rfc2136s """

    ##############################
    # unit tests
    #
    # Must be class method for unit test usage
    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return RFC2136_ARGUMENT_SPEC

    def __init__(self, module, pfsense=None):
        super(PFSenseRfc2136Module, self).__init__(module, pfsense, root='dnsupdates', node='dnsupdate', key='descr',
                                                   arg_route=RFC2136_ARG_ROUTE, create_default=RFC2136_CREATE_DEFAULT, create_root=True)

    ##############################
    # run
    #
    def _update(self):
        """ make the target pfsense update service """
        return self.pfsense.phpshell('''require_once("services.inc");services_dnsupdate_process();''')


def main():
    module = AnsibleModule(
        argument_spec=RFC2136_ARGUMENT_SPEC,
        required_if=RFC2136_REQUIRED_IF,
        supports_check_mode=True)

    pfmodule = PFSenseRfc2136Module(module)
    # Pass params for testing framework
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
