# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


# TODO - allow specifying type of cert, e.g. HTTPS
def validate_cert(self, cert):
    if self.pfsense.get_certref(cert) is None:
        raise ValueError(f"Unknown certificate '{cert}'.")
