# Copyright: (c) 2022, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.community.internal_test_tools.tests.unit.compat.mock import (
    patch,
)
from ansible_collections.pfsensible.core.plugins.module_utils.pfsense import (
    PFSenseModule,
)
from ansible_collections.pfsensible.core.tests.unit.plugins.modules.pfsense_module import (
    TestPFSenseModule,
)


class TestPFSense(TestPFSenseModule):
    def __init__(self, *args, **kwargs):
        super(TestPFSense, self).__init__(*args, **kwargs)

    def setUp(self):
        super(TestPFSense, self).setUp()
        self.pfsense = PFSenseModule(None)
        self.mock_get_version = patch(
            "ansible_collections.pfsensible.core.plugins.module_utils.pfsense.PFSenseModule.get_version",
            wraps=self.my_get_version,
        )
        self.get_version = self.mock_get_version.start()

    def tearDown(self):
        super(TestPFSense, self).tearDown()
        self.mock_get_version.stop()

    def my_get_version(self):
        return self.version

    def test_is_version(self):
        self.pfsense.pfsense_version = None
        self.version = "2.6.0"
        assert self.pfsense.is_version([2, 5, 0])
        assert self.pfsense.is_version([2, 6, 0])
        assert not self.pfsense.is_version([2, 7, 0])
        assert not self.pfsense.is_version([22, 2])
        assert not self.pfsense.is_version([2, 5, 0], or_more=False)
        assert not self.pfsense.is_version([21, 2])
        self.pfsense.pfsense_version = None
        self.version = "22.02"
        assert not self.pfsense.is_version([2, 6, 0])
        assert not self.pfsense.is_version([2, 7, 0])
        assert self.pfsense.is_version([21, 1])
        assert self.pfsense.is_version([21, 3])
        assert self.pfsense.is_version([22, 2])
        assert not self.pfsense.is_version([22, 7])
        assert not self.pfsense.is_version([23, 1])
        assert not self.pfsense.is_version([21, 2], or_more=False)

    def test_is_at_least_2_5_0(self):
        self.pfsense.pfsense_version = None
        self.version = "2.6.0"
        assert self.pfsense.is_at_least_2_5_0()
        self.pfsense.pfsense_version = None
        self.version = "22.01"
        assert self.pfsense.is_at_least_2_5_0()
