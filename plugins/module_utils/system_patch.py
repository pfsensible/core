# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import base64
import json
import re
from os.path import isabs, isdir, isfile
from pathlib import Path
from urllib.parse import urlsplit

from ansible.module_utils.urls import ConnectionError as URLConnectionError
from ansible.module_utils.urls import open_url
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase


SYSTEMPATCH_ARGUMENT_SPEC = dict(
    descr=dict(type="str"),
    uniqid=dict(type="str"),
    content=dict(type="str"),
    src=dict(type="path"),
    remote_src=dict(type="bool", default=False),
    location=dict(type="str"),
    pathstrip=dict(type="int"),
    basedir=dict(type="str"),
    ignore_whitespace=dict(type="bool"),
    auto_apply=dict(type="bool"),
    state=dict(type="str", choices=["present", "absent"], default="present"),
    run=dict(type="str", choices=["no", "apply", "revert"], default="no"),
)
SYSTEMPATCH_MUTUALLY_EXCLUSIVE = [("content", "src")]

PATCHES_INC = "/usr/local/pkg/patches.inc"
BOOT_COMMAND = "/usr/local/bin/php-cgi -f /usr/local/bin/apply_patches.php"
GITHUB_COMMIT_ROOT = "https://github.com/pfsense/pfsense/commit/"
COMMIT_ID = re.compile(r"[0-9a-f]{5,40}")


def _patch_url(location):
    if COMMIT_ID.fullmatch(location):
        return GITHUB_COMMIT_ROOT + location + ".patch"

    url = urlsplit(location)
    if url.scheme not in ("http", "https") or not url.hostname or re.search(r"[\s\x00-\x1f\x7f]", location):
        raise ValueError("location must be an HTTP(S) URL or a pfSense GitHub commit ID")
    # Accessing port also validates it when the caller supplies one.
    if url.port == 0:
        raise ValueError("location port must be between 1 and 65535")
    if url.hostname == "github.com" and COMMIT_ID.fullmatch(url.path.rsplit("/", 1)[-1]):
        url = url._replace(path=url.path + ".patch")
        return url.geturl()
    return location


class PFSenseSystemPatchModule(PFSenseModuleBase):
    """Manage custom System Patches entries and apply or revert them on request."""

    @staticmethod
    def get_argument_spec():
        return SYSTEMPATCH_ARGUMENT_SPEC

    def __init__(self, module):
        if not isfile(PATCHES_INC):
            module.fail_json(msg="The pfSense System Patches package must be installed.")
        super(PFSenseSystemPatchModule, self).__init__(
            module,
            name="pfsense_system_patch",
            root="installedpackages/patches",
            create_root=True,
            node="item",
            key="uniqid" if module.params["uniqid"] is not None else "descr",
            bool_style="absent/present",
            map_param=[("ignore_whitespace", "ignorewhitespace"), ("auto_apply", "autoapply")],
        )

    def _validate_params(self):
        descr = self.params["descr"]
        uniqid = self.params["uniqid"]
        if descr is None and uniqid is None:
            self.module.fail_json(msg="one of the following is required: descr, uniqid")
        if descr is not None and not descr.strip():
            self.module.fail_json(msg="descr must be nonempty")
        if uniqid is not None and (not uniqid.strip() or re.search(r"[/\x00-\x1f\x7f]", uniqid)):
            self.module.fail_json(msg="uniqid must be nonempty and cannot contain slashes or control characters")
        if self.params["state"] == "absent":
            if self.params["run"] == "apply":
                self.module.fail_json(msg="run=apply requires state=present")
            return
        if self.params["src"] is not None and not self.params["remote_src"]:
            self.module.fail_json(msg="The action plugin resolves controller-side src. Set remote_src=true to read src on pfSense.")
        pathstrip = self.params["pathstrip"]
        if pathstrip is not None and not 0 <= pathstrip <= 20:
            self.module.fail_json(msg="pathstrip must be between 0 and 20")
        basedir = self.params["basedir"]
        if basedir is not None and (not isabs(basedir) or not isdir(basedir)):
            self.module.fail_json(msg="basedir must be an existing absolute directory on the pfSense device")

    def _params_to_obj(self, obj=None):
        obj = super(PFSenseSystemPatchModule, self)._params_to_obj(obj)
        for param in ("content", "src", "remote_src", "run"):
            obj.pop(param, None)
        if obj.get("location"):
            try:
                obj["location"] = _patch_url(obj["location"])
            except ValueError as error:
                self.module.fail_json(msg=f"Invalid patch location: {error}")
        return obj

    def _find_target(self):
        value = self.obj[self.key]
        matches = [entry for entry in self.elements if entry.findtext(self.key) == value]
        if len(matches) > 1:
            self.module.fail_json(msg=f"Found multiple patches with {self.key} {value!r}")
        return next(iter(matches), None)

    def _get_params_to_remove(self):
        return [xml_name for param, xml_name in self.map_param if self.params[param] is False]

    def _patch_content(self, existing):
        location = self.obj.get("location", existing.get("location"))
        src = self.params["src"]
        content = self.params["content"]
        try:
            if src is not None:
                data = Path(src).read_bytes()
            elif content is not None:
                data = content.replace("\r\n", "\n").encode("utf-8")
            elif location and (not existing.get("patch") or location != existing.get("location")):
                with open_url(location) as response:
                    data = response.read()
            else:
                return None
        except (OSError, ValueError, URLConnectionError) as error:
            self.module.fail_json(msg=f"Unable to read patch: {error}")
        if not data.strip():
            self.module.fail_json(msg="Patch contents must be nonempty")
        return base64.b64encode(data).decode("ascii")

    def _add(self):
        existing = {} if self.target_elt is None else self.pfsense.element_to_dict(self.target_elt)
        if self.target_elt is None:
            if "descr" not in self.obj:
                self.module.fail_json(msg="descr is required when creating a patch entry")
            for key, value in (("location", ""), ("pathstrip", "2"), ("basedir", "/")):
                self.obj.setdefault(key, value)
            if self.params["ignore_whitespace"] is None:
                self.obj["ignorewhitespace"] = ""
        patch = self._patch_content(existing)
        if patch is not None:
            self.obj["patch"] = patch
        elif not existing.get("patch"):
            self.module.fail_json(msg="Provide content, src, or location for a patch without saved contents")
        if "uniqid" not in self.obj and not existing.get("uniqid"):
            self.obj["uniqid"] = self.pfsense.uniqid()

        super(PFSenseSystemPatchModule, self)._add()

        if self.target_elt.find("autoapply") is not None:
            system = self.pfsense.get_element("system", create_node=True)
            if not any("apply_patches.php" in (cmd.text or "").lower() for cmd in system.findall("earlyshellcmd")):
                # Same entry as patch_add_shellcmd(). Save it atomically with the patch.
                system.append(self.pfsense.new_element("earlyshellcmd", text=BOOT_COMMAND))
                self.result["changed"] = True
                self.result["commands"].append("register System Patches boot command")
                if not self.change_descr:
                    self.change_descr = "ansible pfsense_system_patch registered the System Patches boot command"

    def _log_fields(self, before=None):
        fields = ("location", "pathstrip", "basedir", "ignorewhitespace", "autoapply")
        if self.key == "uniqid":
            fields = ("descr",) + fields
        if before is None:
            return "".join(self.format_cli_field(self.obj, field) for field in fields)
        return "".join(self.format_updated_cli_field(self.diff["after"], before, field) for field in fields).lstrip(", ")

    def _log_update(self, before):
        fields = self._log_fields(before)
        command = f"update system_patch {self._get_obj_name()}"
        if fields:
            command += f" set {fields}"
        self.result["commands"].append(command)

    def _run_patch(self, action, check, config_written=False):
        patch = {
            "patch": self.target_elt.findtext("patch"),
            "basedir": self.target_elt.findtext("basedir") or "/",
            "pathstrip": self.target_elt.findtext("pathstrip") or "2",
        }
        if not patch["patch"]:
            self.module.fail_json(msg=f"Cannot {action} a patch without saved contents")
        if self.target_elt.find("ignorewhitespace") is not None:
            patch["ignorewhitespace"] = True

        # Use a per-call ID for the scratch files that the package writes under /var/patches.
        encoded_patch = base64.b64encode(json.dumps(patch).encode("utf-8")).decode("ascii")
        opposite = "revert" if action == "apply" else "apply"
        php = f"""<?php
require_once("functions.inc");
require_once("config.inc");
require_once("{PATCHES_INC}");
$patch = json_decode(base64_decode("{encoded_patch}"), true);
$patch["uniqid"] = bin2hex(random_bytes(16));
if (patch_test_{opposite}($patch)) {{
    exit(10);
}}
if (!patch_test_{action}($patch)) {{
    exit(11);
}}
exit({"0" if check else f"patch_{action}($patch) ? 0 : 12"});
"""
        rc, stdout, stderr = self.module.run_command("/usr/local/bin/php", data=php)
        if rc == 10:
            return False
        if rc != 0:
            msg = f"Patch cannot {action} cleanly and its current state could not be determined" if rc == 11 else f"Failed to {action} system patch"
            self.module.fail_json(msg=msg, changed=config_written or rc == 12, rc=rc, stdout=stdout, stderr=stderr)
        return True

    def commit_changes(self):
        config_changed = self.result["changed"]
        action = self.params["run"]
        perform_action = action != "no" and self.target_elt is not None
        removing = self.params["state"] == "absent"
        check = self.module.check_mode
        runtime_changed = False

        # Revert before deletion so a failed revert keeps the saved patch available.
        if perform_action and (check or removing):
            runtime_changed = self._run_patch(action, check=check)
        elif perform_action and config_changed:
            perform_action = self._run_patch(action, check=True)
        if config_changed and not check:
            self.pfsense.write_config(descr=self.change_descr)
        if perform_action and not (check or removing):
            runtime_changed = self._run_patch(action, check=False, config_written=config_changed)
        if runtime_changed:
            command = f"{action} system_patch {self._get_obj_name()}"
            if removing:
                self.result["commands"].insert(0, command)
            else:
                self.result["commands"].append(command)
        self.result.update(changed=config_changed or runtime_changed, stdout="", stderr="")
        self.module.exit_json(**self.result)
