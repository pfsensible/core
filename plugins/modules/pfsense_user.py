#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019-2024, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: pfsense_user
version_added: 0.1.0
short_description: Manage pfSense users
description:
  >
    Manage pfSense users
author: Orion Poplawski (@opoplawski)
notes:
options:
  name:
    description: The name of the user.
    required: true
    type: str
  state:
    description: State in which to leave the user.
    default: present
    choices: [ "present", "absent" ]
    type: str
  descr:
    description: Description of the user
    type: str
  scope:
    description: Scope of the user ('user' is a normal user, use 'system' for 'admin' user). Defaults to `user`.
    choices: [ "user", "system" ]
    type: str
  uid:
    description:
    - UID of the user.
    - Will use next available UID if not specified.
    type: str
  groups:
    description: Groups of the user.
    type: list
    elements: str
  password:
    description: bcrypt encrypted password of the user.
    type: str
  priv:
    description:
    - A list of privileges to assign.
    - Allowed values include page-all, user-shell-access.
    type: list
    elements: str
  authorizedkeys:
    description: Authorized SSH Keys of the user. Can be base64 encoded.
    type: str
'''

EXAMPLES = r'''
- name: Add operator user
  pfsense_user:
    name: operator
    descr: Operator
    scope: user
    groups: [ 'Operators' ]
    priv: [ 'page-all', 'user-shell-access' ]

- name: Remove user
  pfsense_user:
    name: operator
    state: absent
'''

RETURN = r'''

'''

import base64
import re

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

USER_ARGUMENT_SPEC = dict(
    name=dict(required=True, type='str'),
    state=dict(type='str', default='present', choices=['present', 'absent']),
    descr=dict(type='str'),
    scope=dict(type='str', choices=['user', 'system']),
    uid=dict(type='str'),
    password=dict(type='str', no_log=True),
    groups=dict(type='list', elements='str'),
    priv=dict(type='list', elements='str'),
    authorizedkeys=dict(type='str'),
)

USER_CREATE_DEFAULT = dict(
    scope='user',
)

USER_MAP_PARAM = [
    ('password', 'bcrypt-hash'),
]


def parse_groups(self, name, params, obj):
    # Groups are not stored in the user object
    if params[name] is not None:
        self.user_groups = params[name]


def p2o_ssh_pub_key(self, name, params, obj):
    # Allow ssh keys to be clear or base64 encoded
    if params[name] is not None and 'ssh-' in params[name]:
        obj[name] = base64.b64encode(params[name].encode()).decode()


def validate_password(self, password):
    if not re.match(r'\$2[aby]\$', str(password)):
        raise ValueError('Password (%s) does not appear to be a bcrypt hash' % (password))


USER_ARG_ROUTE = dict(
    authorizedkeys=dict(parse=p2o_ssh_pub_key),
    groups=dict(parse=parse_groups),
    password=dict(validate=validate_password),
)

USER_PHP_COMMAND_PREFIX = """
require_once('auth.inc');
init_config_arr(array('system', 'user'));
"""

USER_PHP_COMMAND_SET = USER_PHP_COMMAND_PREFIX + """
$a_user = &$config['system']['user'];
$userent = $a_user[{idx}];
local_user_set($userent);
global $groupindex;
foreach ({mod_groups} as $groupname) {{
    $group = &$config['system']['group'][$groupindex[$groupname]];
    local_group_set($group);
}}
if (is_dir("/etc/inc/privhooks")) {{
    run_plugins("/etc/inc/privhooks");
}}
"""

# This runs after we remove the group from the config so we can't use $config
USER_PHP_COMMAND_DEL = USER_PHP_COMMAND_PREFIX + """
$userent['name'] = '{name}';
$userent['uid'] = {uid};
global $groupindex;
foreach ({mod_groups} as $groupname) {{
    $group = &$config['system']['group'][$groupindex[$groupname]];
    local_group_set($group);
}}
local_user_del($userent);
"""


class PFSenseUserModule(PFSenseModuleBase):
    """ module managing pfsense users """

    ##############################
    # unit tests
    #
    # Must be class method for unit test usage
    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return USER_ARGUMENT_SPEC

    def __init__(self, module, pfsense=None):
        super(PFSenseUserModule, self).__init__(module, pfsense, root='system', node='user', key='name',
                                                arg_route=USER_ARG_ROUTE, map_param=USER_MAP_PARAM, create_default=USER_CREATE_DEFAULT)
        self.groups = self.root_elt.findall('group')
        self.user_groups = None
        self.mod_groups = []

    ##############################
    # XML processing
    #
    def _find_group(self, name):
        return self.pfsense.find_elt('group', name, search_field='name', root_elt=self.root_elt)

    def _find_groups_for_uid(self, uid):
        groups = self.pfsense.find_elt_xpath("group[member='{0}']".format(uid), root_elt=self.root_elt, multiple_ok=True)
        if groups is not None:
            return groups
        else:
            return []

    def _nextuid(self):
        nextuid_elt = self.root_elt.find('nextuid')
        nextuid = nextuid_elt.text
        nextuid_elt.text = str(int(nextuid) + 1)
        return nextuid

    def _format_diff_priv(self, priv):
        if isinstance(priv, str):
            return [priv]
        else:
            return priv

    def _copy_and_add_target(self):
        """ populate the XML target_elt """
        obj = self.obj
        if 'bcrypt-hash' not in obj:
            self.module.fail_json(msg='Password is required when adding a user')
        if 'uid' not in obj:
            obj['uid'] = self._nextuid()

        self.diff['after'] = obj
        self.pfsense.copy_dict_to_element(self.obj, self.target_elt)
        self._update_groups()
        self.root_elt.insert(self._find_last_element_index(), self.target_elt)
        # Reset users list
        self.elements = self.root_elt.findall(self.node)

    def _copy_and_update_target(self):
        """ update the XML target_elt """
        before = self.pfsense.element_to_dict(self.target_elt)
        self.diff['before'] = before
        if 'priv' in before:
            before['priv'] = self._format_diff_priv(before['priv'])
        changed = self.pfsense.copy_dict_to_element(self.obj, self.target_elt)
        self.diff['after'] = self.pfsense.element_to_dict(self.target_elt)
        if 'priv' in self.diff['after']:
            self.diff['after']['priv'] = self._format_diff_priv(self.diff['after']['priv'])
        if self._update_groups():
            changed = True

        return (before, changed)

    def _update_groups(self):
        user = self.obj
        changed = False

        # Only modify group membership is groups was specified
        if self.user_groups is not None:
            # Handle group member element - need uid set or retrieved above
            uid = self.target_elt.find('uid').text
            # Get current group membership
            self.diff['before']['groups'] = self._find_groups_for_uid(uid)

            # Add user to groups if needed
            for group in self.user_groups:
                group_elt = self._find_group(group)
                if group_elt is None:
                    self.module.fail_json(msg='Group (%s) does not exist' % group)
                if len(group_elt.findall("[member='{0}']".format(uid))) == 0:
                    changed = True
                    self.mod_groups.append(group)
                    group_elt.append(self.pfsense.new_element('member', uid))

            # Remove user from groups if needed
            for group in self.diff['before']['groups']:
                if group not in self.user_groups:
                    group_elt = self._find_group(group)
                    if group_elt is None:
                        self.module.fail_json(msg='Group (%s) does not exist' % group)
                    for member_elt in group_elt.findall('member'):
                        if member_elt.text == uid:
                            changed = True
                            self.mod_groups.append(group)
                            group_elt.remove(member_elt)
                            break

            # Groups are not stored in the user element
            self.diff['after']['groups'] = self.user_groups

        # Decode keys for diff
        for k in self.diff:
            if 'authorizedkeys' in self.diff[k]:
                self.diff[k]['authorizedkeys'] = base64.b64decode(self.diff[k]['authorizedkeys'])

        return changed

    ##############################
    # run
    #
    def _update(self):
        if self.params['state'] == 'present':
            return self.pfsense.phpshell(USER_PHP_COMMAND_SET.format(idx=self._find_this_element_index(), mod_groups=self.mod_groups))
        else:
            return self.pfsense.phpshell(USER_PHP_COMMAND_DEL.format(name=self.obj['name'], uid=self.obj['uid'], mod_groups=self.mod_groups))

    def _pre_remove_target_elt(self):
        self.diff['after'] = {}
        if self.target_elt is not None:
            self.diff['before'] = self.pfsense.element_to_dict(self.target_elt)
            # Store uid for _update()
            self.obj['uid'] = self.target_elt.find('uid').text

            # Get current group membership
            self.diff['before']['groups'] = self._find_groups_for_uid(self.obj['uid'])

            # Remove user from groups if needed
            for group in self.diff['before']['groups']:
                group_elt = self._find_group(group)
                if group_elt is None:
                    self.module.fail_json(msg='Group (%s) does not exist' % group)
                for member_elt in group_elt.findall('member'):
                    if member_elt.text == self.obj['uid']:
                        self.mod_groups.append(group)
                        group_elt.remove(member_elt)
                        break


def main():
    module = AnsibleModule(
        argument_spec=USER_ARGUMENT_SPEC,
        supports_check_mode=True)

    pfmodule = PFSenseUserModule(module)
    # Pass params for testing framework
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
