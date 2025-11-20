# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


# module_base _params_to_obj currently does not call thse functions if
# params[name] is None.

def p2o_cert(self, name, params, obj):
    obj[name] = self.pfsense.get_certref(params[name])



def p2o_interface(self, name, params, obj):
    obj[name] = self.pfsense.parse_interface(params[name], with_virtual=True)


def p2o_interface_with_gwgroup(self, name, params, obj):
    obj[name] = self.pfsense.parse_interface(
        params[name], with_virtual=False, with_gwgroup=True
    )


def p2o_interface_without_virtual(self, name, params, obj):
    obj[name] = self.pfsense.parse_interface(params[name], with_virtual=False)


def p2o_port(self, name, params, obj):
    obj[name] = self.pfsense.parse_port(params[name], with_virtual=True)


def p2o_strip(self, name, params, obj):
    if params[name] is not None:
        obj[name] = params[name].strip()
