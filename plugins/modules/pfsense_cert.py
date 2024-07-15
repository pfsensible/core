#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Carlos Rodrigues <cmarodrigues@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_cert
version_added: 0.5.0
author: Carlos Rodrigues (@cmarodrigues)
short_description: Manage pfSense certificates
description:
  - Manage pfSense certificates
notes:
options:
  name:
    description: The name of the certificate
    required: true
    type: str
  ca:
    description: The Certificate Authority
    type: str
  keytype:
    description: The type of key to generate
    default: 'RSA'
    choices: [ 'RSA', 'ECDSA' ]
    type: str
  digestalg:
    description: The digest method used when the certificate is signed
    default: 'sha256'
    choices: ['sha1', 'sha224', 'sha256', 'sha384', 'sha512']
    type: str
  ecname:
    description: The Elliptic Curve Name to use when generating a new ECDSA key
    default: 'prime256v1'
    choices: ['secp112r1', 'secp112r2', 'secp128r1', 'secp128r2', 'secp160k1', 'secp160r1', 'secp160r2', 'secp192k1', 'secp224k1', 'secp224r1',
        'secp256k1', 'secp384r1', 'secp521r1', 'prime192v1', 'prime192v2', 'prime192v3', 'prime239v1', 'prime239v2', 'prime239v3', 'prime256v1',
        'sect113r1', 'sect113r2', 'sect131r1', 'sect131r2', 'sect163k1', 'sect163r1', 'sect163r2', 'sect193r1', 'sect193r2', 'sect233k1', 'sect233r1',
        'sect239k1', 'sect283k1', 'sect283r1', 'sect409k1', 'sect409r1', 'sect571k1', 'sect571r1', 'c2pnb163v1', 'c2pnb163v2', 'c2pnb163v3', 'c2pnb176v1',
        'c2tnb191v1', 'c2tnb191v2', 'c2tnb191v3', 'c2pnb208w1', 'c2tnb239v1', 'c2tnb239v2', 'c2tnb239v3', 'c2pnb272w1', 'c2pnb304w1', 'c2tnb359v1',
        'c2pnb368w1', 'c2tnb431r1', 'wap-wsg-idm-ecid-wtls1', 'wap-wsg-idm-ecid-wtls3', 'wap-wsg-idm-ecid-wtls4', 'wap-wsg-idm-ecid-wtls5',
        'wap-wsg-idm-ecid-wtls6', 'wap-wsg-idm-ecid-wtls7', 'wap-wsg-idm-ecid-wtls8', 'wap-wsg-idm-ecid-wtls9', 'wap-wsg-idm-ecid-wtls10',
        'wap-wsg-idm-ecid-wtls11', 'wap-wsg-idm-ecid-wtls12', 'Oakley-EC2N-3', 'Oakley-EC2N-4', 'brainpoolP160r1', 'brainpoolP160t1', 'brainpoolP192r1',
        'brainpoolP192t1', 'brainpoolP224r1', 'brainpoolP224t1', 'brainpoolP256r1', 'brainpoolP256t1', 'brainpoolP320r1', 'brainpoolP320t1',
        'brainpoolP384r1', 'brainpoolP384t1', 'brainpoolP512r1', 'brainpoolP512t1', 'SM2']
    type: str
  keylen:
    description: The length to use when generating a new RSA key, in bits
    default: '2048'
    type: str
  lifetime:
    description: The length of time the signed certificate will be valid, in days
    default: '3650'
    type: str
  dn_country:
    description: The Country Code
    type: str
  dn_state:
    description: The State or Province
    type: str
  dn_city:
    description: The City
    type: str
  dn_organization:
    description: The Organization
    type: str
  dn_organizationalunit:
    description: The Organizational Unit
    type: str
  altnames:
    description:
      >
        The Alternative Names.  A list of aditional identifiers for the certificate.
        A comma separed values with format: DNS:hostname,IP:X.X.X.X,email:user@mail,URI:url
    type: str
  certificate:
    description:
      >
        The certificate to import.  This can be in PEM form or Base64
        encoded PEM as a single string (which is how pfSense stores it).
    type: str
  key:
    description:
      >
        The key to import.  This can be in PEM form or Base64
        encoded PEM as a single string (which is how pfSense stores it).
    type: str
  state:
    description: State in which to leave the certificate
    default: 'present'
    choices: [ 'present', 'absent' ]
    type: str
  method:
    description: Method of the certificate created
    default: 'internal'
    choices: [ 'internal', 'import' ]
    type: str
  certtype:
    description: Type of the certificate ('user' is a certificate for the user)
    default: 'user'
    choices: [ 'user', 'server' ]
    type: str
"""

EXAMPLES = """
- name: Generate new internal certificate
  pfsense_cert:
    method: "internal"
    name: "test"
    ca: "internal-ca"
    keytype: "RSA"
    keylen: 2048
    lifetime: 3650
    dn_country: "PT"
    dn_organization: "Dummy"
    certtype: "user"
    state: present

- name: Import certificate
  pfsense_cert:
    method: "import"
    name: "test"
    certificate: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUUxVENDQXIyZ0F3...
    key: |
      -----BEGIN PRIVATE KEY-----
      MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC4yY0SI8lWNN2B
      ...
      i0LiJ+QOek6Qy+51kMK3rXNsQQ==
      -----END PRIVATE KEY-----
    certtype: "user"
    state: present

- name: Remove certificate
  pfsense_cert:
    name: "test"
    state: absent
"""

RETURN = """

"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.cert import PFSenseCertModule, CERT_ARGUMENT_SPEC


def main():
    module = AnsibleModule(
        argument_spec=CERT_ARGUMENT_SPEC,
        supports_check_mode=True)

    pfmodule = PFSenseCertModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()

if __name__ == '__main__':
    main()
