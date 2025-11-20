# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.pfsensible.core.plugins.module_utils.module_base import (
    PFSenseModuleBase,
)


IPSEC_ARGUMENT_SPEC = dict(
    state=dict(default="present", choices=["present", "absent"]),
    descr=dict(required=True, type="str"),
    iketype=dict(choices=["ikev1", "ikev2", "auto"], type="str"),
    protocol=dict(default="inet", choices=["inet", "inet6", "both"]),
    interface=dict(required=False, type="str"),
    remote_gateway=dict(required=False, type="str"),
    nattport=dict(required=False, type="int"),
    disabled=dict(required=False, type="bool"),
    authentication_method=dict(choices=["pre_shared_key", "rsasig"]),
    mode=dict(required=False, choices=["main", "aggressive"]),
    myid_type=dict(
        default="myaddress",
        choices=[
            "myaddress",
            "address",
            "fqdn",
            "user_fqdn",
            "asn1dn",
            "keyid tag",
            "dyn_dns",
            "auto",
        ],
    ),
    myid_data=dict(required=False, type="str"),
    peerid_type=dict(
        default="peeraddress",
        choices=[
            "any",
            "peeraddress",
            "address",
            "fqdn",
            "user_fqdn",
            "asn1dn",
            "keyid tag",
            "auto",
        ],
    ),
    peerid_data=dict(required=False, type="str"),
    certificate=dict(required=False, type="str"),
    certificate_authority=dict(required=False, type="str"),
    preshared_key=dict(required=False, type="str", no_log=True),
    lifetime=dict(default=28800, type="int"),
    rekey_time=dict(required=False, type="int"),
    reauth_time=dict(required=False, type="int"),
    rand_time=dict(required=False, type="int"),
    disable_rekey=dict(required=False, type="bool"),
    margintime=dict(required=False, type="int"),
    startaction=dict(default="", choices=["", "none", "start", "trap"]),
    closeaction=dict(default="", choices=["", "none", "start", "trap"]),
    disable_reauth=dict(default=False, type="bool"),
    mobike=dict(default="off", choices=["on", "off"]),
    gw_duplicates=dict(required=False, type="bool"),
    splitconn=dict(default=False, type="bool"),
    nat_traversal=dict(default="on", choices=["on", "force"]),
    enable_dpd=dict(default=True, type="bool"),
    dpd_delay=dict(default=10, type="int"),
    dpd_maxfail=dict(default=5, type="int"),
    apply=dict(default=True, type="bool"),
    # Dropped in 2.5.2
    responderonly=dict(required=False, type="bool"),
)

IPSEC_REQUIRED_IF = [
    [
        "state",
        "present",
        ["remote_gateway", "interface", "iketype", "authentication_method"],
    ],
    ["enable_dpd", True, ["dpd_delay", "dpd_maxfail"]],
    ["iketype", "auto", ["mode"]],
    ["iketype", "ikev1", ["mode"]],
    ["authentication_method", "pre_shared_key", ["preshared_key"]],
    ["authentication_method", "rsasig", ["certificate", "certificate_authority"]],
    ["myid_type", "address", ["myid_data"]],
    ["myid_type", "fqdn", ["myid_data"]],
    ["myid_type", "user_fqdn", ["myid_data"]],
    ["myid_type", "asn1dn", ["myid_data"]],
    ["myid_type", "keyid tag", ["myid_data"]],
    ["myid_type", "dyn_dns", ["myid_data"]],
    ["peerid_type", "address", ["peerid_data"]],
    ["peerid_type", "fqdn", ["peerid_data"]],
    ["peerid_type", "user_fqdn", ["peerid_data"]],
    ["peerid_type", "asn1dn", ["peerid_data"]],
    ["peerid_type", "keyid tag", ["peerid_data"]],
]

# Booleans that map to different values
IPSEC_BOOL_VALUES = dict(
    gw_duplicates=(None, ""),
)

IPSEC_MAP_PARAM = [
    ("preshared_key", "pre-shared-key"),
    ("remote_gateway", "remote-gateway"),
]

IPSEC_CREATE_DEFAULT = dict(
    rand_time=None,
    reauth_time=None,
    rekey_time=None,
)


def p2o_ipsec_interface(self, name, params, obj):
    # Valid interfaces are physical, virtual IPs, and gateway groups
    # TODO - handle gateway groups
    if params[name].lower().startswith("vip:"):
        obj[name] = self.pfsense.get_virtual_ip_interface(params[name][4:])
    else:
        obj[name] = self.pfsense.parse_interface(params[name], with_virtual=False)


IPSEC_ARG_ROUTE = dict(
    interface=dict(
        parse=p2o_ipsec_interface,
    ),
)


class PFSenseIpsecModule(PFSenseModuleBase):
    """module managing pfsense ipsec tunnels phase 1 options"""

    @staticmethod
    def get_argument_spec():
        """return argument spec"""
        return IPSEC_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseIpsecModule, self).__init__(
            module,
            pfsense,
            arg_route=IPSEC_ARG_ROUTE,
            bool_values=IPSEC_BOOL_VALUES,
            map_param=IPSEC_MAP_PARAM,
            create_default=IPSEC_CREATE_DEFAULT,
        )
        # Override for use with aggregate
        self.argument_spec = IPSEC_ARGUMENT_SPEC
        self.name = "pfsense_ipsec"
        self.apply = True

        self.root_elt = self.pfsense.ipsec

    ##############################
    # XML processing
    #
    def _create_target(self):
        """create the XML target_elt"""
        ipsec_elt = self.pfsense.new_element("phase1")
        self.obj["ikeid"] = str(self._find_free_ikeid())
        return ipsec_elt

    def _find_free_ikeid(self):
        """return first unused ikeid"""
        ikeid = 1
        while True:
            found = False
            for ipsec_elt in self.root_elt:
                ikeid_elt = ipsec_elt.find("ikeid")
                if ikeid_elt is not None and ikeid_elt.text == str(ikeid):
                    found = True
                    break

            if not found:
                return ikeid
            ikeid = ikeid + 1

    def _find_target(self):
        """find the XML target_elt"""
        if self.params.get("ikeid") is not None:
            return self.pfsense.find_ipsec_phase1(self.params["ikeid"], "ikeid")
        return self.pfsense.find_ipsec_phase1(self.obj["descr"])

    def _get_params_to_remove(self):
        """returns the list of params to remove if they are not set"""
        params = [
            "disabled",
            "rekey_enable",
            "reauth_enable",
            "splitconn",
            "nattport",
            "gw_duplicates",
        ]
        if self.params.get("disable_rekey"):
            params.append("margintime")

        if not self.params["enable_dpd"]:
            params.append("dpd_delay")
            params.append("dpd_maxfail")

        return params

    def _pre_remove_target_elt(self):
        """processing before removing elt"""
        self._remove_phases2()

    def _remove_phases2(self):
        """remove phase2 elts from xml"""
        ikeid_elt = self.target_elt.find("ikeid")
        if ikeid_elt is None:
            return
        ikeid = ikeid_elt.text
        phase2_elts = self.root_elt.findall("phase2")
        for phase2_elt in phase2_elts:
            ikeid_elt = phase2_elt.find("ikeid")
            if ikeid_elt is None:
                continue
            if ikeid == ikeid_elt.text:
                self.root_elt.remove(phase2_elt)

    ##############################
    # params processing
    #
    def _params_to_obj(self):
        """return an ipsec dict from module params"""

        ipsec = super(PFSenseIpsecModule, self)._params_to_obj()
        params = self.params
        self.apply = params["apply"]
        ipsec.pop("apply", None)

        if params["state"] == "present":
            if params["authentication_method"] == "rsasig":
                ca_elt = self.pfsense.find_ca_elt(params["certificate_authority"])
                if ca_elt is None:
                    self.module.fail_json(
                        msg="%s is not a valid certificate authority"
                        % (params["certificate_authority"])
                    )
                ipsec["caref"] = ca_elt.find("refid").text

                cert = self.pfsense.find_cert_elt(params["certificate"])
                if cert is None:
                    self.module.fail_json(
                        msg="%s is not a valid certificate" % (params["certificate"])
                    )
                ipsec["certref"] = cert.find("refid").text
                ipsec["pre-shared-key"] = ""
            else:
                ipsec["caref"] = ""
                ipsec["certref"] = ""

            if params.get("disable_rekey"):
                ipsec["rekey_enable"] = ""

            if params.get("enable_dpd"):
                ipsec["dpd_delay"] = str(params["dpd_delay"])
                ipsec["dpd_maxfail"] = str(params["dpd_maxfail"])
                del ipsec["enable_dpd"]

            if params.get("disable_reauth"):
                ipsec["reauth_enable"] = ""

        return ipsec

    def _deprecated_params(self):
        return [
            ["disable_rekey", self.pfsense.is_at_least_2_5_0],
            ["margintime", self.pfsense.is_at_least_2_5_0],
            ["responderonly", self.pfsense.is_at_least_2_5_2],
        ]

    def _onward_params(self):
        return [
            ["gw_duplicates", self.pfsense.is_at_least_2_5_0],
            ["nattport", self.pfsense.is_at_least_2_5_0],
            ["rekey_time", self.pfsense.is_at_least_2_5_0],
            ["reauth_time", self.pfsense.is_at_least_2_5_0],
            ["rand_time", self.pfsense.is_at_least_2_5_0],
            # TODO - Cannot add because it has a default value
            # ['startaction', self.pfsense.is_at_least_2_5_2],
            # ['closeaction', self.pfsense.is_at_least_2_5_2],
        ]

    def _validate_params(self):
        """do some extra checks on input parameters"""
        params = self.params
        if params["state"] == "absent":
            return

        if params.get("lifetime") is not None:
            if (
                params.get("rekey_time") is not None
                and params.get("rekey_time") >= params.get("lifetime")
                or params.get("reauth_time") is not None
                and params.get("reauth_time") >= params.get("lifetime")
            ):
                self.module.fail_json(
                    msg="Life Time must be larger than Rekey Time and Reauth Time."
                )

        for ipsec_elt in self.root_elt:
            if ipsec_elt.tag != "phase1":
                continue

            # don't check on ourself
            name = ipsec_elt.find("descr")
            if name is None:
                name = ""
            else:
                name = name.text

            if name == params["descr"]:
                continue

            # Valid interfaces are physical, virtual IPs, and gateway groups
            # TODO - handle gateway groups
            if params["interface"].lower().startswith("vip:"):
                if (
                    self.pfsense.get_virtual_ip_interface(params["interface"][4:])
                    is None
                ):
                    self.module.fail_json(
                        msg='Cannot find virtual IP "{0}".'.format(
                            params["interface"][4:]
                        )
                    )

            # two ikev2 can share the same gateway
            iketype_elt = ipsec_elt.find("iketype")
            if iketype_elt is None:
                continue

            if iketype_elt.text == "ikev2" and iketype_elt.text == params["iketype"]:
                continue

            # others can't share the same gateway
            rgw_elt = ipsec_elt.find("remote-gateway")
            if rgw_elt is None:
                continue

            if rgw_elt.text == params["remote_gateway"]:
                self.module.fail_json(
                    msg='The remote gateway "{0}" is already used by phase1 "{1}".'.format(
                        params["remote_gateway"], name
                    )
                )

    ##############################
    # run
    #
    def _update(self):
        """make the target pfsense reload"""
        return self.pfsense.apply_ipsec_changes()

    ##############################
    # Logging
    #
    def _log_fields(self, before=None):
        """generate pseudo-CLI command fields parameters to create an obj"""
        values = ""
        if before is None:
            values += self.format_cli_field(
                self.params, "disabled", fvalue=self.fvalue_bool
            )
            values += self.format_cli_field(self.diff["after"], "iketype")
            if self.diff["after"]["iketype"] != "ikev2":
                values += self.format_cli_field(self.diff["after"], "mode")

            values += self.format_cli_field(self.diff["after"], "protocol")
            values += self.format_cli_field(self.params, "interface")
            values += self.format_cli_field(
                self.diff["after"], "remote-gateway", fname="remote_gateway"
            )
            values += self.format_cli_field(self.diff["after"], "nattport")
            values += self.format_cli_field(self.diff["after"], "authentication_method")
            if self.diff["after"]["authentication_method"] == "rsasig":
                values += self.format_cli_field(self.params, "certificate")
                values += self.format_cli_field(self.params, "certificate_authority")
            else:
                values += self.format_cli_field(
                    self.diff["after"], "pre-shared-key", fname="preshared_key"
                )

            id_types = [
                "address",
                "fqdn",
                "user_fqdn",
                "asn1dn",
                "keyid tag",
                "dyn_dns",
            ]
            values += self.format_cli_field(self.diff["after"], "myid_type")
            if self.diff["after"]["myid_type"] in id_types:
                values += self.format_cli_field(self.diff["after"], "myid_data")

            values += self.format_cli_field(self.diff["after"], "peerid_type")
            if self.diff["after"]["peerid_type"] in id_types:
                values += self.format_cli_field(self.diff["after"], "peerid_data")

            values += self.format_cli_field(self.diff["after"], "lifetime")
            values += self.format_cli_field(self.diff["after"], "rekey_time")
            values += self.format_cli_field(self.diff["after"], "reauth_time")
            values += self.format_cli_field(self.diff["after"], "rand_time")

            if self.diff["after"]["iketype"] == "ikev2":
                values += self.format_cli_field(
                    self.diff["after"],
                    "reauth_enable",
                    fname="disable_reauth",
                    fvalue=self.fvalue_bool,
                )
                values += self.format_cli_field(self.diff["after"], "mobike")
                values += self.format_cli_field(
                    self.diff["after"], "splitconn", fvalue=self.fvalue_bool
                )

            values += self.format_cli_field(
                self.diff["after"], "gw_duplicates", fvalue=self.fvalue_bool
            )

            values += self.format_cli_field(self.params, "startaction")
            values += self.format_cli_field(self.params, "closeaction")
            values += self.format_cli_field(self.diff["after"], "nat_traversal")

            values += self.format_cli_field(
                self.params, "enable_dpd", fvalue=self.fvalue_bool
            )
            if self.params["enable_dpd"]:
                values += self.format_cli_field(self.diff["after"], "dpd_delay")
                values += self.format_cli_field(self.diff["after"], "dpd_maxfail")
        else:
            values += self.format_updated_cli_field(
                self.diff["after"],
                before,
                "disabled",
                add_comma=(values),
                fvalue=self.fvalue_bool,
            )
            values += self.format_updated_cli_field(
                self.diff["after"], before, "iketype", add_comma=(values)
            )
            if self.diff["after"]["iketype"] != "ikev2":
                values += self.format_updated_cli_field(
                    self.diff["after"], before, "mode", add_comma=(values)
                )
            values += self.format_updated_cli_field(
                self.diff["after"], before, "protocol", add_comma=(values)
            )
            values += self.format_updated_cli_field(
                self.diff["after"], before, "interface", add_comma=(values)
            )
            values += self.format_updated_cli_field(
                self.diff["after"],
                before,
                "remote-gateway",
                add_comma=(values),
                fname="remote_gateway",
            )
            values += self.format_updated_cli_field(
                self.diff["after"], before, "nattport", add_comma=(values)
            )
            values += self.format_updated_cli_field(
                self.diff["after"], before, "authentication_method", add_comma=(values)
            )
            if self.diff["after"]["authentication_method"] == "rsasig":
                values += self.format_updated_cli_field(
                    self.params, before, "certificate", add_comma=(values)
                )
                values += self.format_updated_cli_field(
                    self.params, before, "certificate_authority", add_comma=(values)
                )
            else:
                values += self.format_updated_cli_field(
                    self.diff["after"],
                    before,
                    "pre-shared-key",
                    add_comma=(values),
                    fname="preshared_key",
                )
            values += self.format_updated_cli_field(
                self.diff["after"], before, "myid_type", add_comma=(values)
            )
            id_types = [
                "address",
                "fqdn",
                "user_fqdn",
                "asn1dn",
                "keyid tag",
                "dyn_dns",
            ]
            if self.diff["after"]["myid_type"] in id_types:
                values += self.format_updated_cli_field(
                    self.diff["after"], before, "myid_data", add_comma=(values)
                )

            values += self.format_updated_cli_field(
                self.diff["after"], before, "peerid_type", add_comma=(values)
            )
            if self.diff["after"]["peerid_type"] in id_types:
                values += self.format_updated_cli_field(
                    self.diff["after"], before, "peerid_data", add_comma=(values)
                )

            values += self.format_updated_cli_field(
                self.diff["after"], before, "lifetime", add_comma=(values)
            )
            values += self.format_updated_cli_field(
                self.diff["after"], before, "rekey_time", add_comma=(values)
            )
            values += self.format_updated_cli_field(
                self.diff["after"], before, "reauth_time", add_comma=(values)
            )
            values += self.format_updated_cli_field(
                self.diff["after"], before, "rand_time", add_comma=(values)
            )

            if self.diff["after"]["iketype"] == "ikev2":
                values += self.format_updated_cli_field(
                    self.diff["after"],
                    before,
                    "reauth_enable",
                    add_comma=(values),
                    fname="disable_reauth",
                    fvalue=self.fvalue_bool,
                )
                values += self.format_updated_cli_field(
                    self.diff["after"], before, "mobike", add_comma=(values)
                )
                values += self.format_updated_cli_field(
                    self.diff["after"],
                    before,
                    "splitconn",
                    add_comma=(values),
                    fvalue=self.fvalue_bool,
                )

            values += self.format_updated_cli_field(
                self.diff["after"],
                before,
                "gw_duplicates",
                add_comma=(values),
                fvalue=self.fvalue_bool,
            )

            values += self.format_updated_cli_field(
                self.diff["after"], before, "startaction", add_comma=(values)
            )
            values += self.format_updated_cli_field(
                self.diff["after"], before, "closeaction", add_comma=(values)
            )
            values += self.format_updated_cli_field(
                self.diff["after"], before, "nat_traversal", add_comma=(values)
            )
            values += self.format_updated_cli_field(
                self.diff["after"],
                before,
                "enable_dpd",
                add_comma=(values),
                fvalue=self.fvalue_bool,
            )
            if self.params["enable_dpd"]:
                values += self.format_updated_cli_field(
                    self.diff["after"], before, "dpd_delay", add_comma=(values)
                )
                values += self.format_updated_cli_field(
                    self.diff["after"], before, "dpd_maxfail", add_comma=(values)
                )
        return values

    def _get_ref_names(self, before):
        """get cert and ca names"""
        if before["caref"] is not None and before["caref"] != "":
            elt = self.pfsense.find_ca_elt(before["caref"], "refid")
            if elt is not None:
                before["certificate_authority"] = elt.find("descr").text

        if before["certref"] is not None and before["certref"] != "":
            elt = self.pfsense.find_cert_elt(before["certref"], "refid")
            if elt is not None:
                before["certificate"] = elt.find("descr").text
