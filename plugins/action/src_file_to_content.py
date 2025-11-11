# -*- coding: utf-8 -*-

# Copyright: (c) 2023, genofire <geno+dev@fireorbit.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

import os

from ansible.errors import AnsibleError, AnsibleActionFail
from ansible.module_utils.common.text.converters import to_native, to_text
from ansible.plugins.action import ActionBase


class ActionModule(ActionBase):

    def run(self, tmp=None, task_vars=None):
        ''' handler for file transfer operations '''
        if task_vars is None:
            task_vars = dict()

        result = super(ActionModule, self).run(tmp, task_vars)
        del tmp  # tmp no longer has any effect

        source = self._task.args.get('src', None)
        new_module_args = self._task.args.copy()
        if source is not None:
            del new_module_args['src']
            try:
                # find in expected paths
                source = self._find_needle('files', source)
            except AnsibleError as e:
                result['failed'] = True
                result['msg'] = to_text(e)
                # result['exception'] = traceback.format_exc()
                return result

            if not os.path.isfile(source):
                raise AnsibleActionFail(u"Source (%s) is not a file" % source)

            try:
                with open(source, 'rb') as src:
                    content = src.read()
                new_module_args['content'] = content.decode('utf-8')
            except Exception as e:
                raise AnsibleError("Unexpected error while reading source (%s) for diff: %s " % (source, to_native(e)))
        module_return = self._execute_module(module_args=new_module_args, task_vars=task_vars)
        result.update(module_return)
        return result
