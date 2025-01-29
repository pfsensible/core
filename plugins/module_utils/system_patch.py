# -*- coding: utf-8 -*-

# Copyright: (c) 2023, genofire <geno+dev@fireorbit.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from base64 import b64encode
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

SYSTEMPATCH_ARGUMENT_SPEC = dict(
    state=dict(default='present', choices=['present', 'absent']),
    run=dict(default='no', choices=['apply', 'revert', 'no']),
    # attributes
    id=dict(type='str', required=True),
    description=dict(type='str'),
    content=dict(type='str'),
    # patch or patch_file
    src=dict(type='path'),
    location=dict(type='str', default=""),
    pathstrip=dict(type='int', default=2),
    basedir=dict(type='str', default="/"),
    ignore_whitespace=dict(type='bool', default=True),
    auto_apply=dict(type='bool', default=False),
)

SYSTEMPATCH_MUTUALLY_EXCLUSIVE = [
    ['content', 'path'],
]

SYSTEMPATCH_REQUIRED_IF = [
    ['state', 'present', ['description']],
    ['state', 'present', ['content', 'src'], True],
    ['run', 'apply', ['content', 'src'], True],
    ['run', 'revert', ['content', 'src'], True],
]


class PFSenseSystemPatchModule(PFSenseModuleBase):
    """ module managing pfsense system patches """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return SYSTEMPATCH_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseSystemPatchModule, self).__init__(module, pfsense)
        self.name = "pfsense_systempatch"

        self.root_elt = None
        installedpackages_elt = self.pfsense.get_element('installedpackages')
        if installedpackages_elt is not None:
            self.root_elt = self.pfsense.get_element('patches', root_elt=installedpackages_elt, create_node=True)

        self.target_elt = None  # unknown
        self.obj = dict()  # The object to work on

    ##############################
    # params processing
    #

    def _validate_params(self):
        """ do some extra checks on input parameters """
        pass

    def _create_target(self):
        """ create the XML target_elt """
        return self.pfsense.new_element('item')

    def _find_target(self):
        """ find the XML target_elt """
        return self.pfsense.find_elt('item', self.params['id'], 'uniqid', root_elt=self.root_elt)

    def _get_obj_name(self):
        return "'{0}'".format(self.obj['uniqid'])

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''
        fields = [
            'uniqid',
            'descr',
            'location',
            'pathstrip',
            'basedir',
            'ignorewhitespace',
            'autoapply',
            'patch',
        ]
        if before is None:
            for field in fields:
                values += self.format_cli_field(self.obj, field)
        else:
            for field in fields:
                values += self.format_updated_cli_field(self.obj, before, field, add_comma=(values))
        return values

    @staticmethod
    def _get_params_to_remove():
        """ returns the list of params to remove if they are not set """
        return ['ignorewhitespace', 'autoapply']

    def _params_to_obj(self):
        """ return a dict from module params """
        obj = dict()

        self._get_ansible_param(obj, 'id', 'uniqid')
        self._get_ansible_param(obj, 'description', 'descr')
        self._get_ansible_param(obj, 'location')
        self._get_ansible_param(obj, 'pathstrip')
        self._get_ansible_param(obj, 'basedir')

        if self.params['ignore_whitespace']:
            obj['ignorewhitespace'] = ""
        if self.params['auto_apply']:
            obj['autoapply'] = ""

        # src copied to content by action
        if self.params['content'] is not None:
            obj['patch'] = b64encode(bytes(self.params['content'], 'utf-8')).decode('ascii')

        if self.params['run'] != 'no':
            # want to run _update so change manipulate
            self.result['changed'] = True

        return obj

    ##############################
    # run
    #

    def _update(self):
        run = self.params['run']
        if run == "no":
            return ('0', 'Patch is stored but not installed', '')

        other_direction = 'revert' if run == 'apply' else 'apply'

        cmd = '''
require_once('functions.inc');
require_once('patches.inc');

    '''
        cmd += self.pfsense.dict_to_php(self.obj, 'thispatch')
        cmd += '''

$retval = 0;
$test = patch_test_''' + run + '''($thispatch);
$retval |= $test;
$retval = $retval << 1;

if ($test) {
  $retval |= patch_''' + run + '''($thispatch);
} else {
  $rerun = patch_test_''' + other_direction + '''($thispatch);
  if($rerun) {
    patch_''' + other_direction + '''($thispatch);
    $retval |= patch_''' + run + '''($thispatch);
  }
}
exit($retval);'''
        (code, out, err) = self.pfsense.phpshell(cmd)
        self.result['rc_merged'] = code

        # patch_'''+ run
        rc_run = (code % 2) == 1
        self.result['rc_run'] = rc_run

        # patch_test_'''+ other_direction
        # restore test code, so if revert (other direction) not works - patch was already applyied
        rc_test = ((code >> 1) % 2) == 1
        self.result['rc_test'] = rc_test

        # recalc changed after overwritten to run _update
        self.result['changed'] = (rc_run and rc_test)
        if not rc_run:
            self.result['failed'] = True
            self.result['msg'] = "Patch was not possible to run (even after try other direction previously)"
        return ('', out, err)
