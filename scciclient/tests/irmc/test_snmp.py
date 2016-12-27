#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""
Test class for snmp module.
"""


import mock
import testtools

from scciclient.irmc import snmp


class IRMCSnmpTestCase(testtools.TestCase):
    """Tests for SNMP module

    Unit Test Cases for getting information via snmp module
    """

    def setUp(self):
        super(IRMCSnmpTestCase, self).setUp()

    def test_get_irmc_firmware_version(self):
        snmp_client = mock.Mock()
        snmp_client.get.side_effect = ['iRMC S4', '7.82F']
        cmd1 = snmp.BMC_NAME_OID
        cmd2 = snmp.IRMC_FW_VERSION_OID
        actual_out = snmp.get_irmc_firmware_version(snmp_client)
        self.assertEqual('iRMC S4-7.82F', actual_out)
        snmp_client.get.assert_has_calls([mock.call(cmd1),
                                          mock.call(cmd2)])

    def test_get_irmc_firmware_version_BMC_only(self):
        snmp_client = mock.Mock()
        snmp_client.get.side_effect = ['iRMC S4', '']
        cmd1 = snmp.BMC_NAME_OID
        cmd2 = snmp.IRMC_FW_VERSION_OID
        actual_out = snmp.get_irmc_firmware_version(snmp_client)
        self.assertEqual('iRMC S4', actual_out)
        snmp_client.get.assert_has_calls([mock.call(cmd1),
                                          mock.call(cmd2)])

    def test_get_irmc_firmware_version_FW_only(self):
        snmp_client = mock.Mock()
        snmp_client.get.side_effect = ['', '7.82F']
        cmd1 = snmp.BMC_NAME_OID
        cmd2 = snmp.IRMC_FW_VERSION_OID
        actual_out = snmp.get_irmc_firmware_version(snmp_client)
        self.assertEqual('7.82F', actual_out)
        snmp_client.get.assert_has_calls([mock.call(cmd1),
                                          mock.call(cmd2)])

    def test_get_irmc_firmware_version_blank(self):
        snmp_client = mock.Mock()
        snmp_client.get.side_effect = ['', '']
        cmd1 = snmp.BMC_NAME_OID
        cmd2 = snmp.IRMC_FW_VERSION_OID
        actual_out = snmp.get_irmc_firmware_version(snmp_client)
        self.assertEqual('', actual_out)
        snmp_client.get.assert_has_calls([mock.call(cmd1),
                                          mock.call(cmd2)])

    def test_get_bios_firmware_version(self):
        snmp_client = mock.Mock()
        snmp_client.get.return_value = 'V4.6.5.4 R1.15.0 for D3099-B1x'
        cmd = snmp.BIOS_FW_VERSION_OID
        actual_out = snmp.get_bios_firmware_version(snmp_client)
        self.assertEqual('V4.6.5.4 R1.15.0 for D3099-B1x', actual_out)
        snmp_client.get.assert_called_once_with(cmd)

    def test_get_server_model(self):
        snmp_client = mock.Mock()
        snmp_client.get.return_value = 'TX2540M1F5'
        cmd = snmp.SERVER_MODEL_OID
        actual_out = snmp.get_server_model(snmp_client)
        self.assertEqual('TX2540M1F5', actual_out)
        snmp_client.get.assert_called_once_with(cmd)
