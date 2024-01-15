# Copyright: (c) 2022, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import pytest
import sys

if sys.version_info < (2, 7):
    pytestmark = pytest.mark.skip("pfSense Ansible modules require Python >= 2.7")

from ansible_collections.pfsensible.core.plugins.modules import pfsense_ca
from .pfsense_module import TestPFSenseModule

CERTIFICATE = (
    "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tDQpNSUlFQ0RDQ0F2Q2dBd0lCQWdJSUZqRk9oczFuTXpRd0RRWUpLb1pJaHZjTkFRRUxCUUF3WERFVE1CRUdBMVVFDQpBeE1LYjNCbGJuWndiaTFqWVRF"
    "TE1Ba0dBMVVFQmhNQ1ZWTXhFVEFQQmdOVkJBZ1RDRU52Ykc5eVlXUnZNUkF3DQpEZ1lEVlFRSEV3ZENiM1ZzWkdWeU1STXdFUVlEVlFRS0V3cHdabE5sYm5OcFlteGxNQjRYRFRJeU1ESXhOREExDQpN"
    "RGd6TVZvWERUTXlNREl4TWpBMU1EZ3pNVm93WERFVE1CRUdBMVVFQXhNS2IzQmxiblp3YmkxallURUxNQWtHDQpBMVVFQmhNQ1ZWTXhFVEFQQmdOVkJBZ1RDRU52Ykc5eVlXUnZNUkF3RGdZRFZRUUhF"
    "d2RDYjNWc1pHVnlNUk13DQpFUVlEVlFRS0V3cHdabE5sYm5OcFlteGxNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDDQpBUUVBbXN2aUpNRTFFVGVkNGZPdGJrSHBGM2Q5ZU0r"
    "NjQwOFhQbmE4dEpHZEJxM1VBQ3hFem9hQktSdDJ5MWN0DQo2elFEZTVGRjRBQXZ0VjF1Y1pwc2w1bzREUy9JR1NibjZkM1lNaytqOGpBUTNFbXpSOEdPb2huZ2YxUTlBWEM2DQpvaDRyQlA1c1g0WTh1"
    "WThrSjNZclg1cVRwRlk1S0hMVTFBb1BleVE3eXlNWkhMb2t0OW5jK0ZGWnd3VTdSQ0dTDQpjTkxaaVZ4Q1FRSzVwOGs5bUE4Ymd4bHFZa2YwbUF5Qk53OU1BZlBVY1VrcUY2UDBnV1BIbElySFovdWhn"
    "N2RVDQorMjJhb2NLVUVOaXY5bXFhK0I2Y1VnTFRGVDZzMFZTRXNYL2RBZWg2MllMZ2ZtWEpnNmROSFFJK01nNlNrZWxwDQprOVZSVGVqaUVUSUVWOEpnZHYyTjdSU201d0lEQVFBQm80SE5NSUhLTUIw"
    "R0ExVWREZ1FXQkJSazVvQS8wcWEyDQpLUHdnb1hKcUtNdCtBb0tKZ1RDQmpRWURWUjBqQklHRk1JR0NnQlJrNW9BLzBxYTJLUHdnb1hKcUtNdCtBb0tKDQpnYUZncEY0d1hERVRNQkVHQTFVRUF4TUti"
    "M0JsYm5ad2JpMWpZVEVMTUFrR0ExVUVCaE1DVlZNeEVUQVBCZ05WDQpCQWdUQ0VOdmJHOXlZV1J2TVJBd0RnWURWUVFIRXdkQ2IzVnNaR1Z5TVJNd0VRWURWUVFLRXdwd1psTmxibk5wDQpZbXhsZ2dn"
    "V01VNkd6V2N6TkRBTUJnTlZIUk1FQlRBREFRSC9NQXNHQTFVZER3UUVBd0lCQmpBTkJna3Foa2lHDQo5dzBCQVFzRkFBT0NBUUVBVUg5S0NkbUpkb0FKbFUwd0JKSFl4akxyS2xsUFk2T05ienI1SmJo"
    "Q002OUh4eFlODQpCa2lpbXd1N09mRmFGZkZDT25NSjhvcStKVGxjMG9vREoxM2xCdHRONkdybnZrUTNQMXdZYkNFTmJuaWxPYVVCDQpUSXJpSHl0TkRRYW91TmEvS1dzN0ZhdW9iY3RCbDF3OWF0b0ha"
    "c041b2VoVDNyQVR2MUNDQXRqcGFUSklmSlIzDQowSVFPWWtlNG9ZNkRrSXdIcDJ2UFBtb29HZ0l0YlR3M1UrRTQxWVplN3FDbUUvN3pMVFNaa0lNMmx4NnpENDZqDQpEZjRyZ044TVVMNnhpd09Mbzly"
    "QUp5ckRNM2JEeTJ1QjY0QkVzRFFMa2huUE92ZWtETjQ1NnV6TmpYS0E3VnE4DQpoMS9nekRaSURpK1dYQ1lBY2JnTGhaVkJxdG42MnVtRnBNUkl1dz09DQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t"
    "DQo=")
CRL1 = (
    "LS0tLS1CRUdJTiBYNTA5IENSTC0tLS0tCk1JSUNkRENDQVZ3Q0FRRXdEUVlKS29aSWh2Y05BUUVGQlFBd1hERVRNQkVHQTFVRUF4TUtiM0JsYm5ad2JpMWoKWVRFTE1Ba0dBMVVFQmhNQ1ZWTXhFVEFQ"
    "QmdOVkJBZ1RDRU52Ykc5eVlXUnZNUkF3RGdZRFZRUUhFd2RDYjNWcwpaR1Z5TVJNd0VRWURWUVFLRXdwd1psTmxibk5wWW14bEZ3MHlNakF5TVRrd05UVXhNRFphRncwME9UQTNNRFl3Ck5UVXhNRFph"
    "TUNrd0p3SUlMdnhrNzExMkdwUVhEVEl5TURJeE9UQTFOVEV3TWxvd0REQUtCZ05WSFJVRUF3b0IKQmFDQm9EQ0JuVENCalFZRFZSMGpCSUdGTUlHQ2dCUms1b0EvMHFhMktQd2dvWEpxS010K0FvS0pn"
    "YUZncEY0dwpYREVUTUJFR0ExVUVBeE1LYjNCbGJuWndiaTFqWVRFTE1Ba0dBMVVFQmhNQ1ZWTXhFVEFQQmdOVkJBZ1RDRU52CmJHOXlZV1J2TVJBd0RnWURWUVFIRXdkQ2IzVnNaR1Z5TVJNd0VRWURW"
    "UVFLRXdwd1psTmxibk5wWW14bGdnZ1cKTVU2R3pXY3pOREFMQmdOVkhSUUVCQUlDSnhFd0RRWUpLb1pJaHZjTkFRRUZCUUFEZ2dFQkFGbXJ5cFUxU3p5dApNUUZCRWFZZk9waVpqRVhVajE5MVZuWENl"
    "b0tNMk83bVUzYW5HVXRZQUJMcG15dmN2YnU2ZkJCVEtYSTFEb0VvClJkV1VDTVMxbk5BTWwyU0N0ZmJ5RHNHNjZHczRiNnRZeXE1SW5LVFJJdldUeU5vS0JiUHc1OHZYV0ljNmVmUXgKSTYvZSt4U3di"
    "eE9MSFlRdGd4WTJOdk9xVGVnVE0rTHpIcmNJWmFPS09NbHNodTA4ajgzSnUxR0ttYlBKME1jZwpyVXNiYXRKcURUdWtQMi9VbmI0N1hwN21qUHVTY0Z5MjN2RGl2OHdvcjBYOEFSQW1ibTN4N2ZKeTlt"
    "V2d1OVhMCmpNV1lxN1BEaXhwWElqTVdhZzN2bVYxOC9IdDIybW1xS1RPM3prVnJLUDA1TEhCNVloM2ZZcEpWdEhkeENlTzUKdmlvbU53SzA3QUE9Ci0tLS0tRU5EIFg1MDkgQ1JMLS0tLS0=")
CRL2 = (
    "-----BEGIN X509 CRL-----\n"
    "MIICSDCCATACAQEwDQYJKoZIhvcNAQEFBQAwXDETMBEGA1UEAxMKb3BlbnZwbi1j\n"
    "YTELMAkGA1UEBhMCVVMxETAPBgNVBAgTCENvbG9yYWRvMRAwDgYDVQQHEwdCb3Vs\n"
    "ZGVyMRMwEQYDVQQKEwpwZlNlbnNpYmxlFw0yMzAxMDcyMzIzMDNaFw01MDA1MjQy\n"
    "MzIzMDNaoIGfMIGcMIGNBgNVHSMEgYUwgYKAFGTmgD/SprYo/CChcmooy34CgomB\n"
    "oWCkXjBcMRMwEQYDVQQDEwpvcGVudnBuLWNhMQswCQYDVQQGEwJVUzERMA8GA1UE\n"
    "CBMIQ29sb3JhZG8xEDAOBgNVBAcTB0JvdWxkZXIxEzARBgNVBAoTCnBmU2Vuc2li\n"
    "bGWCCBYxTobNZzM0MAoGA1UdFAQDAgECMA0GCSqGSIb3DQEBBQUAA4IBAQAxhuDn\n"
    "A7SJl760tXhQFSWMKTn7VndhiR86GRJzS8H3uyfRqesGrUIcVFlN+z6XqHsJsann\n"
    "+/fPvCf5Oo0+R5o4NDpByx5CO0mAy0WReds4bykoSKVUJXEVFXNHl14+Emh6mJtP\n"
    "m/Uzzq4cKEtAxZdqd9tbaTwTh4NbH1C7RmbUgRKjWma4CiC1Sofo5mIhx5cCv+ng\n"
    "Ny5w9dLF4s+6qFXjvfYmQ0FyeRcltUoF3kTabS1WCdkGjsUSeGHBFLM4NH2mJPMR\n"
    "0yfIGdipSonSTF51ICqgoUGAYPqObvlQZDMjFF+GFL3LNQ7gO+1R1OMMKAZ+96nX\n"
    "gwt+00UVYhQCCZ3k\n"
    "-----END X509 CRL-----\n")


class TestPFSenseCAModule(TestPFSenseModule):

    module = pfsense_ca

    def __init__(self, *args, **kwargs):
        super(TestPFSenseCAModule, self).__init__(*args, **kwargs)
        self.config_file = 'pfsense_ca_config.xml'
        self.pfmodule = pfsense_ca.PFSenseCAModule

    @staticmethod
    def runTest():
        """ dummy function needed to instantiate this test module from another in python 2.7 """
        pass

    def get_target_elt(self, obj, absent=False, module_result=None):
        """ return target elt from XML """
        root_elt = self.xml_result.getroot()
        result = root_elt.findall("ca[descr='{0}']".format(obj['name']))
        if len(result) == 1:
            return result[0]
        elif len(result) > 1:
            self.fail('Found multiple CAs for name {0}.'.format(obj['name']))
        else:
            return None

    def check_target_elt(self, obj, target_elt):
        """ check XML definition of target elt """

        self.check_param_equal(obj, target_elt, 'name', xml_field='descr')
        if 'trust' in obj:
            self.check_param_bool(obj, target_elt, 'trust', value_true='enabled', value_false='disabled')
        if 'randomserial' in obj:
            self.check_param_bool(obj, target_elt, 'randomserial', value_true='enabled', value_false='disabled')
        self.check_param_equal_or_present(obj, target_elt, 'serial')
        self.check_param_equal(obj, target_elt, 'certificate', xml_field='crt')

    ##############
    # tests
    #
    def test_ca_create(self):
        """ test creation of a new ca """
        obj = dict(name='ca1', certificate=CERTIFICATE)
        self.do_module_test(obj, command='create ca ca1')

    def test_ca_add_crl(self):
        """ test adding a CRL """
        obj = dict(name='ca1', certificate=CERTIFICATE, crl=CRL1)
        self.do_module_test(obj, command='create ca ca1')

    def test_ca_change_crl(self):
        """ test adding a CRL """
        obj = dict(name='ca1', certificate=CERTIFICATE, crl=CRL2)
        self.do_module_test(obj, command='create ca ca1')

    def test_ca_delete(self):
        """ test deletion of a ca """
        obj = dict(name='testdel')
        self.do_module_test(obj, command='delete ca testdel', delete=True)

    def test_ca_update_noop(self):
        """ test not updating a ca """
        obj = dict(name='testdel', certificate=CERTIFICATE)
        self.do_module_test(obj, changed=False)

    def test_ca_update_serial(self):
        """ test updating serial of a ca """
        obj = dict(name='testdel', certificate=CERTIFICATE, serial=10)
        self.do_module_test(obj, command='update ca testdel set ')

    def test_ca_update_trust(self):
        """ test updating trust of a ca """
        obj = dict(name='testdel', certificate=CERTIFICATE, trust=False)
        self.do_module_test(obj, command='update ca testdel set ')

    ##############
    # misc
    #
    def test_create_ca_invalid_serial(self):
        """ test creation of a new ca with invalid serial """
        obj = dict(name='ca1', certificate=CERTIFICATE, serial=-1)
        self.do_module_test(obj, failed=True, msg='serial must be greater than 0')

    def test_delete_nonexistent_ca(self):
        """ test deletion of an nonexistent ca """
        obj = dict(name='noca')
        self.do_module_test(obj, commmand=None, state='absent', changed=False)
