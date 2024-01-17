# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Frederic Bor <frederic.bor@wanadoo.fr>
# Copyright: (c) 2024, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible_collections.pfsensible.core.plugins.module_utils.pfsense import PFSenseModule


class PFSenseModuleBase(object):
    """ class providing base services for pfSense modules """

    ##############################
    # unit tests
    #
    # Must be class method for unit test usage
    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        raise NotImplementedError()

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None, package=None, name=None, root=None, root_is_exclusive=True, create_root=False, node=None, key='descr',
                 update_php=None, arg_route=None, map_param=None, map_param_if=None, param_force=None, bool_values=None, have_refid=False, create_default=None):
        self.module = module         # ansible module
        self.argument_spec = module.argument_spec  # Allow for being overriden for use with aggregate

        # pfSense helper module
        if pfsense is None:
            pfsense = PFSenseModule(module)
        self.pfsense = pfsense

        if name is not None:    # ansible module name
            self.name = name
        elif node is not None:
            self.name = 'pfsense_' + node
        else:
            self.name = None

        self.apply = True       # apply configuration at the end

        # xml parent of target_elt, node named by root
        if root is not None:
            if root == 'pfsense':
                self.root_elt = self.pfsense.root
                self.root_is_exclusive = False
            else:
                if package is None:
                    self.root_elt = self.pfsense.get_element(root, create_node=create_root)
                else:
                    self.root_elt = self.pfsense.get_element(root, root_elt=self.pfsense.root.find('installedpackages'))
                if root in ['system']:
                    self.root_is_exclusive = False
                else:
                    self.root_is_exclusive = root_is_exclusive
        else:
            self.root_elt = None
            self.root_is_exclusive = root_is_exclusive
        self.root = root

        # List of elements named node
        if node is not None:
            self.elements = self.root_elt.findall(node)
        else:
            self.elements = None
        self.node = node

        self.key = key          # item that identifies a target element
        self.obj = dict()       # dict holding target pfsense parameters
        if arg_route is not None:
            self.arg_route = arg_route        # routing for argument handling
        else:
            self.arg_route = dict()

        # rules for mapping parameters
        if map_param is not None:
            self.map_param = map_param
        else:
            self.map_param = list()

        # conditional rules for mapping parameters
        if map_param_if is not None:
            self.map_param_if = map_param_if
        else:
            self.map_param_if = list()

        if param_force is not None:
            self.param_force = param_force  # parameters that are forced to be present
        else:
            self.param_force = list()
        if bool_values is not None:
            self.bool_values = bool_values    # boolean values for arguments
        else:
            self.bool_values = dict()
        self.create_default = create_default  # default values for a created target
        self.have_refid = have_refid      # if the element has a refid item
        self.target_elt = None  # xml object holding target pfsense parameters

        self.update_php = update_php  # php code to update configuration

        self.change_descr = ''

        self.result = {}
        self.result['changed'] = False
        self.result['commands'] = []

        self.diff = {'after': {}, 'before': {}}
        self.result['diff'] = self.diff

    ##############################
    # params processing
    #
    def _get_ansible_param(self, obj, name, fname=None, force=False, exclude=None, force_value=''):
        """ get parameter from params and set it into obj """
        if fname is None:
            fname = name

        if self.params.get(name) is not None:
            if not (exclude is not None and exclude == self.params[name]):
                if isinstance(self.params[name], int):
                    obj[fname] = str(self.params[name])
                else:
                    obj[fname] = self.params[name]
        elif force:
            obj[fname] = force_value

    def _get_ansible_param_bool(self, obj, name, fname=None, force=False, value='yes', value_false=None):
        """ get bool parameter from params and set it into obj """
        if fname is None:
            fname = name

        if self.params.get(name) is not None:
            if self.params.get(name):
                obj[fname] = value
            elif value_false is not None:
                obj[fname] = value_false
            elif force:
                obj[fname] = None
        elif force:
            obj[fname] = value_false

    def _params_to_obj(self):
        """ return a dict from module params that sets self.obj """
        obj = dict()
        # Not all modules have 'state', treat them like they did
        if self.params.get('state', 'present') == 'present':
            # Ansible sets unspecied parameters to None, skip them and 'state'
            for param in [p for p in self.params if p != 'state' and self.params[p] is not None]:
                force = False
                if param in self.param_force:
                    force = True

                # If we have defined a parser for this arg, use it
                if param in self.arg_route and 'parse' in self.arg_route[param]:
                    self.arg_route[param]['parse'](self, param, self.params, obj)
                elif self.argument_spec[param].get('type') == 'bool':
                    if param in self.bool_values:
                        self._get_ansible_param_bool(obj, param, value=self.bool_values[param][1], value_false=self.bool_values[param][0], force=force)
                    else:
                        self._get_ansible_param_bool(obj, param, force=force)
                else:
                    self._get_ansible_param(obj, param, force=force)

            # Handle renaming of parameters
            for p, o in self.map_param:
                if self.params.get(p) is not None:
                    obj[o] = obj[p]
                    del obj[p]

            # Handle conditional renaming of parameters
            for map_param, map_value, map_tuple in self.map_param_if:
                if self.params.get(map_param) == map_value and map_tuple[0] in obj:
                    if map_tuple[1] not in obj:
                        obj[map_tuple[1]] = obj[map_tuple[0]]
                    del obj[map_tuple[0]]
        else:
            # Just use the key to remove items
            obj[self.key] = self.params[self.key]

        return obj

    ##############################
    # params processing
    #
    def _validate_params(self):
        """ do some extra checks on input parameters """
        params = self.params
        # Not all modules have 'state', treat them like they did
        if self.params.get('state', 'present') == 'present':
            # Ansible sets unspecied parameters to None, skip them
            for param in [p for p in self.params if self.params[p] is not None]:
                if param in self.arg_route and 'validate' in self.arg_route[param]:
                    try:
                        self.arg_route[param]['validate'](self, params[param])
                    except ValueError as e:
                        self.module.fail_json(msg=str(e))

    def _deprecated_params(self):
        """ return deprecated params """
        return None

    def _onward_params(self):
        """ return onwards params """
        return None

    def _check_deprecated_params(self):
        """ check if input parameters are deprecated """
        deprecated_params = self._deprecated_params()
        if deprecated_params is None:
            return

        for deprecated in deprecated_params:
            if self.params.get(deprecated[0]) is not None and deprecated[1]():
                self.module.fail_json(msg='{0} is deprecated on pfSense {1}.'.format(deprecated[0], self.pfsense.get_version()))

    def _check_onward_params(self):
        """ check if input parameters are too recents """
        onwards_params = self._onward_params()
        if onwards_params is None:
            return

        for onward in onwards_params:
            if self.params.get(onward[0]) is not None and not onward[1]():
                self.module.fail_json(msg='{0} is not supported on pfSense {1}.'.format(onward[0], self.pfsense.get_version()))

    ##############################
    # XML processing
    #
    def _copy_and_add_target(self):
        """ create the XML target_elt """
        self.pfsense.copy_dict_to_element(self.obj, self.target_elt)
        self.diff['after'] = self.obj
        if self.root_is_exclusive:
            self.root_elt.append(self.target_elt)
        else:
            self.root_elt.insert(self._find_last_element_index(), self.target_elt)
            # Reset elements list
            self.elements = self.root_elt.findall(self.node)

    def _copy_and_update_target(self):
        """ update the XML target_elt """
        before = self.pfsense.element_to_dict(self.target_elt)
        self.diff['before'] = before
        changed = self.pfsense.copy_dict_to_element(self.obj, self.target_elt)
        self.diff['after'] = self.pfsense.element_to_dict(self.target_elt)
        if self._remove_deleted_params():
            changed = True

        return (before, changed)

    def _create_target(self):
        """ create the XML target_elt """
        if self.node is not None:
            elt = self.pfsense.new_element(self.node)
            if self.have_refid:
                # Store in obj so that we can refer to it later if needed
                self.obj['refid'] = self.pfsense.uniqid()
                elt.append(self.pfsense.new_element('refid', text=self.obj['refid']))
            if self.create_default is not None:
                self.pfsense.copy_dict_to_element(self.create_default, elt)
            return elt
        else:
            raise NotImplementedError()

    def _find_this_element_index(self):
        return self.elements.index(self.target_elt)

    def _find_last_element_index(self):
        if len(self.elements):
            return list(self.root_elt).index(self.elements[len(self.elements) - 1])
        else:
            return len(list(self.root_elt))

    def _find_target(self):
        """ find the XML target_elt """
        if self.node is not None:
            result = self.root_elt.findall("{node}[{key}='{value}']".format(node=self.node, key=self.key, value=self.obj[self.key]))
            if len(result) == 1:
                return result[0]
            elif len(result) > 1:
                self.module.fail_json(msg='Found multiple {node}s for {key} {value}.'.format(node=self.node, key=self.key, value=self.obj[self.key]))
            else:
                return None
        else:
            raise NotImplementedError()

    @staticmethod
    def _get_params_to_remove():
        """ returns the list of params to remove if they are not set """
        return []

    def _remove_deleted_params(self):
        """ Remove from target_elt a few deleted params """
        changed = False
        params = self._get_params_to_remove()
        for param in params:
            if self.pfsense.remove_deleted_param_from_elt(self.target_elt, param, self.obj):
                changed = True

        return changed

    def _remove_target_elt(self):
        """ delete target_elt from xml """
        self.root_elt.remove(self.target_elt)
        self.result['changed'] = True

    ##############################
    # run
    #
    def _add(self):
        """ add or update obj """
        if self.target_elt is None:
            self.target_elt = self._create_target()
            self._copy_and_add_target()

            changed = True
            self.change_descr = 'ansible {0} added {1}'.format(self._get_module_name(), self._get_obj_name())
            self._log_create()
        else:
            (before, changed) = self._copy_and_update_target()
            if changed:
                self.change_descr = 'ansible {0} updated {1}'.format(self._get_module_name(), self._get_obj_name())
                self._log_update(before)

        if changed:
            self.result['changed'] = changed

    def commit_changes(self):
        """ apply changes and exit module """
        self.result['stdout'] = ''
        self.result['stderr'] = ''
        if self.result['changed'] and not self.module.check_mode:
            if self.apply:
                (dummy, self.result['stdout'], self.result['stderr']) = self._pre_update()

            self.pfsense.write_config(descr=self.change_descr)

            if self.apply:
                (dummy, stdout, stderr) = self._update()
                self.result['stdout'] += stdout
                self.result['stderr'] += stderr

        self.module.exit_json(**self.result)

    def _post_remove_target_elt(self):
        """ processing after removing elt """
        pass

    def _pre_remove_target_elt(self):
        """ processing before removing elt """
        self.diff['before'] = self.pfsense.element_to_dict(self.target_elt)

    def _remove(self):
        """ delete obj """
        if self.target_elt is not None:
            self._pre_remove_target_elt()
            self._log_delete()
            self._remove_target_elt()
            self._post_remove_target_elt()
            self.change_descr = 'ansible {0} removed {1}'.format(self._get_module_name(), self._get_obj_name())

    @staticmethod
    def _pre_update():
        """ tasks to run before making config changes """
        return ('', '', '')

    def _update(self):
        """ make the target pfsense reload """
        if self.update_php is not None:
            return self.pfsense.phpshell(self.update_php)
        else:
            return ('', '', '')

    # We take params here for use with pfsense_aggregate and the test framework
    def run(self, params):
        """ process input params to add/update/delete """
        self.params = params
        self.target_elt = None
        self._check_deprecated_params()
        self._check_onward_params()
        self._validate_params()

        self.obj = self._params_to_obj()
        if self.target_elt is None:
            self.target_elt = self._find_target()

        if params['state'] == 'absent':
            self._remove()
        else:
            self._add()

    ##############################
    # Logging
    #
    def _log_create(self):
        """ generate pseudo-CLI command to create an obj """
        log = "create {0} {1}".format(self._get_module_name(True), self._get_obj_name())
        log += self._log_fields()
        self.result['commands'].append(log)

    def _log_delete(self):
        """ generate pseudo-CLI command to delete an obj """
        log = "delete {0} {1}".format(self._get_module_name(True), self._get_obj_name())
        log += self._log_fields_delete()
        self.result['commands'].append(log)

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''
        if before is None:
            for param in [n for n in self.argument_spec.keys() if n != 'state' and n != self.key]:
                values += self.format_cli_field(self.obj, param)
        else:
            for param in [n for n in self.argument_spec.keys() if n != 'state' and n != self.key]:
                if self.argument_spec[param].get('type') == 'bool':
                    values += self.format_updated_cli_field(self.diff['after'], before, param, fvalue=self.fvalue_bool, add_comma=(values))
                else:
                    values += self.format_updated_cli_field(self.diff['after'], before, param, add_comma=(values))
        return values

    @staticmethod
    def _log_fields_delete():
        """ generate pseudo-CLI command fields parameters to delete an obj """
        return ""

    def _log_update(self, before):
        """ generate pseudo-CLI command to update an obj """
        log = "update {0} {1}".format(self._get_module_name(True), self._get_obj_name())
        values = self._log_fields(before)
        self.result['commands'].append(log + ' set ' + values)

    def _get_obj_name(self):
        """ return obj's name """
        return "'{0}'".format(self.obj[self.key])

    def _get_module_name(self, strip=False):
        """ return ansible module's name """
        if strip:
            return self.name.replace("pfsense_", "")
        return self.name

    def format_cli_field(self, after, field, log_none=False, add_comma=True, fvalue=None, default=None, fname=None, none_value=None, force=False):
        """ format field for pseudo-CLI command """
        if fvalue is None:
            fvalue = self.fvalue_idem

        if fname is None:
            fname = field

        if none_value is None:
            none_value = 'none'

        res = ''
        if field in after:
            if log_none and after[field] is None:
                res = "{0}={1}".format(fname, fvalue(none_value))
            if after[field] is not None:
                if default is None or after[field] != default:
                    if isinstance(after[field], str) and fvalue != self.fvalue_bool:
                        res = "{0}='{1}'".format(fname, fvalue(after[field].replace("'", "\\'")))
                    else:
                        res = "{0}={1}".format(fname, fvalue(after[field]))
        elif log_none or force:
            res = "{0}={1}".format(fname, fvalue(none_value))

        if add_comma and res:
            return ', ' + res
        return res

    def format_updated_cli_field(self, after, before, field, log_none=True, add_comma=True, fvalue=None, default=None, fname=None, none_value=None):
        """ format field for pseudo-CLI update command """
        log = False
        if none_value is None:
            none_value = 'none'

        if field in after and field in before:
            if fvalue is None and after[field] != before[field]:
                log = True
            elif fvalue is not None and fvalue(after[field]) != fvalue(before[field]):
                log = True
        elif fvalue is None:
            if field in after and field not in before or field not in after and field in before:
                log = True
        elif field in after and field not in before and fvalue(after[field]) != fvalue(none_value):
            log = True
        elif field not in after and field in before and fvalue(before[field]) != fvalue(none_value):
            log = True

        if log:
            return self.format_cli_field(
                after, field, log_none=log_none, add_comma=add_comma, fvalue=fvalue, default=default, fname=fname, none_value=none_value, force=True
            )
        return ''

    @staticmethod
    def fvalue_idem(value):
        """ dummy value formatting function """
        return value

    @staticmethod
    def fvalue_bool(value):
        """ boolean value formatting function """
        if value is None or value is False or value == 'none':
            return 'False'

        return 'True'
