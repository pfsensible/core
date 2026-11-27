# -*- coding: utf-8 -*-

# Copyright: (c) 2023, genofire <geno+dev@fireorbit.de>
# Copyright: (c) 2026, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from pathlib import Path

from ansible.errors import AnsibleActionFail
from ansible.module_utils.common.validation import check_type_bool
from ansible.plugins.action.normal import ActionModule as NormalAction


class ActionModule(NormalAction):
    """Resolve controller-side patch files before running the module."""

    def run(self, tmp=None, task_vars=None):
        args = self._task.args
        src = args.get("src")
        if src is not None and args.get("content") is None and args.get("state") != "absent":
            remote_src = args.get("remote_src")
            if remote_src is not None:
                try:
                    remote_src = check_type_bool(remote_src)
                except TypeError as error:
                    raise AnsibleActionFail(f"Invalid remote_src: {error}") from error
            if not remote_src:
                path = Path(self._find_needle("files", src))
                try:
                    if not path.is_file():
                        raise AnsibleActionFail(f"Controller patch source {str(path)!r} is not a file")
                    content = path.read_bytes().decode("utf-8")
                except (OSError, ValueError) as error:
                    raise AnsibleActionFail(f"Unable to read controller patch file {str(path)!r}: {error}") from error
                self._task = self._task.copy()
                self._task.args = {**args, "content": content}
                del self._task.args["src"]
        return super(ActionModule, self).run(tmp, task_vars)
