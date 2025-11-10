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
from ansible_collections.community.internal_test_tools.tests.unit.compat.mock import patch

CERTIFICATE = (
    "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUVDRENDQXZDZ0F3SUJBZ0lJRmpGT2hzMW5NelF3RFFZSktvWklodmNOQVFFTEJRQXdYREVUTUJFR0ExVUUKQXhNS2IzQmxiblp3YmkxallURUxN"
    "QWtHQTFVRUJoTUNWVk14RVRBUEJnTlZCQWdUQ0VOdmJHOXlZV1J2TVJBdwpEZ1lEVlFRSEV3ZENiM1ZzWkdWeU1STXdFUVlEVlFRS0V3cHdabE5sYm5OcFlteGxNQjRYRFRJeU1ESXhOREExCk1EZ3pN"
    "Vm9YRFRNeU1ESXhNakExTURnek1Wb3dYREVUTUJFR0ExVUVBeE1LYjNCbGJuWndiaTFqWVRFTE1Ba0cKQTFVRUJoTUNWVk14RVRBUEJnTlZCQWdUQ0VOdmJHOXlZV1J2TVJBd0RnWURWUVFIRXdkQ2Iz"
    "VnNaR1Z5TVJNdwpFUVlEVlFRS0V3cHdabE5sYm5OcFlteGxNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDCkFRRUFtc3ZpSk1FMUVUZWQ0Zk90YmtIcEYzZDllTSs2NDA4WFBu"
    "YTh0SkdkQnEzVUFDeEV6b2FCS1J0MnkxY3QKNnpRRGU1RkY0QUF2dFYxdWNacHNsNW80RFMvSUdTYm42ZDNZTWsrajhqQVEzRW16UjhHT29obmdmMVE5QVhDNgpvaDRyQlA1c1g0WTh1WThrSjNZclg1"
    "cVRwRlk1S0hMVTFBb1BleVE3eXlNWkhMb2t0OW5jK0ZGWnd3VTdSQ0dTCmNOTFppVnhDUVFLNXA4azltQThiZ3hscVlrZjBtQXlCTnc5TUFmUFVjVWtxRjZQMGdXUEhsSXJIWi91aGc3ZFUKKzIyYW9j"
    "S1VFTml2OW1xYStCNmNVZ0xURlQ2czBWU0VzWC9kQWVoNjJZTGdmbVhKZzZkTkhRSStNZzZTa2VscAprOVZSVGVqaUVUSUVWOEpnZHYyTjdSU201d0lEQVFBQm80SE5NSUhLTUIwR0ExVWREZ1FXQkJS"
    "azVvQS8wcWEyCktQd2dvWEpxS010K0FvS0pnVENCalFZRFZSMGpCSUdGTUlHQ2dCUms1b0EvMHFhMktQd2dvWEpxS010K0FvS0oKZ2FGZ3BGNHdYREVUTUJFR0ExVUVBeE1LYjNCbGJuWndiaTFqWVRF"
    "TE1Ba0dBMVVFQmhNQ1ZWTXhFVEFQQmdOVgpCQWdUQ0VOdmJHOXlZV1J2TVJBd0RnWURWUVFIRXdkQ2IzVnNaR1Z5TVJNd0VRWURWUVFLRXdwd1psTmxibk5wCllteGxnZ2dXTVU2R3pXY3pOREFNQmdO"
    "VkhSTUVCVEFEQVFIL01Bc0dBMVVkRHdRRUF3SUJCakFOQmdrcWhraUcKOXcwQkFRc0ZBQU9DQVFFQVVIOUtDZG1KZG9BSmxVMHdCSkhZeGpMcktsbFBZNk9OYnpyNUpiaENNNjlIeHhZTgpCa2lpbXd1"
    "N09mRmFGZkZDT25NSjhvcStKVGxjMG9vREoxM2xCdHRONkdybnZrUTNQMXdZYkNFTmJuaWxPYVVCClRJcmlIeXRORFFhb3VOYS9LV3M3RmF1b2JjdEJsMXc5YXRvSFpzTjVvZWhUM3JBVHYxQ0NBdGpw"
    "YVRKSWZKUjMKMElRT1lrZTRvWTZEa0l3SHAydlBQbW9vR2dJdGJUdzNVK0U0MVlaZTdxQ21FLzd6TFRTWmtJTTJseDZ6RDQ2agpEZjRyZ044TVVMNnhpd09MbzlyQUp5ckRNM2JEeTJ1QjY0QkVzRFFM"
    "a2huUE92ZWtETjQ1NnV6TmpYS0E3VnE4CmgxL2d6RFpJRGkrV1hDWUFjYmdMaFpWQnF0bjYydW1GcE1SSXV3PT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=")
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

    def setUp(self):
        """ mocking up """

        super(TestPFSenseCAModule, self).setUp()

        self.mock_php = patch('ansible_collections.pfsensible.core.plugins.module_utils.pfsense.PFSenseModule.php')
        self.php = self.mock_php.start()
        self.php.return_value = '12000'

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
        self.do_module_test(obj, command="create ca 'ca1'")

    def test_ca_add_crl(self):
        """ test adding a CRL """
        obj = dict(name='ca1', certificate=CERTIFICATE, crl=CRL1)
        self.do_module_test(obj, command="create ca 'ca1'")

    def test_ca_change_crl(self):
        """ test adding a CRL """
        obj = dict(name='ca1', certificate=CERTIFICATE, crl=CRL2)
        self.do_module_test(obj, command="create ca 'ca1'")

    def test_ca_delete(self):
        """ test deletion of a ca """
        obj = dict(name='testdel')
        self.do_module_test(obj, command="delete ca 'testdel'", delete=True)

    def test_ca_update_noop(self):
        """ test not updating a ca """
        obj = dict(name='testdel', certificate=CERTIFICATE)
        self.do_module_test(obj, changed=False)

    def test_ca_update_serial(self):
        """ test updating serial of a ca """
        obj = dict(name='testdel', certificate=CERTIFICATE, serial=10)
        self.do_module_test(obj, command="update ca 'testdel' set serial='10'")

    def test_ca_update_trust(self):
        """ test updating trust of a ca """
        obj = dict(name='testdel', certificate=CERTIFICATE, trust=False)
        self.do_module_test(obj, command="update ca 'testdel' set ")

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
