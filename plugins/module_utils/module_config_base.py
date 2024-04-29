# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Frederic Bor <frederic.bor@wanadoo.fr>
# Copyright: (c) 2024, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import re
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase, merge_dicts


class PFSenseModuleConfigBase(PFSenseModuleBase):
    """ class for implementing pfSense modules that manage a set of configuration settings """

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None, package=None, name=None, root=None, root_is_exclusive=True, create_root=False, node=None, key='descr',
                 update_php=None, arg_route=None, map_param=None, map_param_if=None, param_force=None, bool_style=None, bool_values=None, have_refid=False,
                 create_default=None):
        super(PFSenseModuleConfigBase, self).__init__(module, pfsense=pfsense, package=package, name=name, root=root, root_is_exclusive=True, create_root=False,
                                                      update_php=update_php, arg_route=arg_route, map_param=map_param, map_param_if=map_param_if,
                                                      param_force=param_force, bool_style=bool_style, bool_values=bool_values, create_default=create_default)

    ##############################
    # params processing
    #
    def _params_to_obj(self):
        """ return a dict from module params """
        obj = self.pfsense.element_to_dict(self.root_elt)
        merge_dicts(obj, super(PFSenseModuleConfigBase, self)._params_to_obj(obj=obj))
        return obj

    ##############################
    # XML processing
    #
    def _find_target(self):
        """ find the XML target_elt """
        return self.root_elt

    ##############################
    # Logging
    #
    def _get_obj_name(self):
        """ return obj's name """
        return re.sub(r'pfsense_', '', self.name)
