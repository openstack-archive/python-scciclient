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
Test class for IPMI Module.
"""

import mock
import testtools

from pyghmi import exceptions as ipmi_exception
from pyghmi.ipmi import command as ipmi_command

from scciclient.irmc import ipmi


@mock.patch.object(ipmi_command, 'Command', new=mock.Mock())
class IpmiTestCase(testtools.TestCase):
    """Tests for IPMI

    Unit Test Cases for getting information via ipmi raw command
    """

    def setUp(self):
        super(IpmiTestCase, self).setUp()

        self.info = {'irmc_address': "10.0.0.10",
                     'irmc_username': "admin",
                     'irmc_password': "admin",
                     }

    @mock.patch.object(ipmi, '_send_raw_command')
    def test_get_tpm_status_true(self, exec_mock):
        exec_mock.return_value = {'command': 0xF5, 'code': 0x00, 'netfn': 0x2F,
                                  'data': [0x80, 0x28, 0x00, 0xC0, 0xC0]}

        cmd = "0x2E 0xF5 0x80 0x28 0x00 0x81 0xC0"
        actual_out = ipmi.get_tpm_status(self.info)
        self.assertEqual(True, actual_out)
        exec_mock.assert_called_once_with(mock.ANY, cmd)

    @mock.patch.object(ipmi, '_send_raw_command')
    def test_get_tpm_status_false(self, exec_mock):
        exec_mock.return_value = {'command': 0xF5, 'code': 0x00, 'netfn': 0x2F,
                                  'data': [0x80, 0x28, 0x00, 0x80, 0x01]}
        cmd = "0x2E 0xF5 0x80 0x28 0x00 0x81 0xC0"

        actual_out = ipmi.get_tpm_status(self.info)
        self.assertEqual(False, actual_out)
        exec_mock.assert_called_once_with(mock.ANY, cmd)

    @mock.patch.object(ipmi, '_send_raw_command')
    def test_get_tpm_status_error_code(self, exec_mock):
        exec_mock.return_value = {'command': 0xF5, 'code': 0x01, 'netfn': 0x2F,
                                  'data': [0x80, 0x28, 0x00, 0x80, 0x01]}
        cmd = "0x2E 0xF5 0x80 0x28 0x00 0x81 0xC0"

        self.assertRaises(ipmi.IPMIFailure, ipmi.get_tpm_status, self.info)
        exec_mock.assert_called_once_with(mock.ANY, cmd)

    @mock.patch.object(ipmi, '_send_raw_command')
    def test_get_tpm_status_exception(self, exec_mock):
        exec_mock.side_effect = ipmi_exception.IpmiException

        cmd = "0x2E 0xF5 0x80 0x28 0x00 0x81 0xC0"

        self.assertRaises(ipmi.IPMIFailure, ipmi.get_tpm_status, self.info)
        exec_mock.assert_called_once_with(mock.ANY, cmd)

    @mock.patch.object(ipmi, '_send_raw_command')
    def test_get_gpu(self, exec_mock):
        gpu_ids = ['0x1000/0x0079', '0x2100/0x0080']

        exec_mock.side_effect = ({'command': 0xF1, 'code': 0x00, 'netfn': 0x2F,
                                  'data': [0x80, 0x28, 0x00, 0x00, 0x00, 0x05,
                                           0x00, 0x10, 0x79, 0x00, 0x34, 0x17,
                                           0x76, 0x11, 0x00, 0x04, 0x01]},
                                 {'command': 0xF1, 'code': 0xC9, 'netfn': 0x2F,
                                  'error': 'Parameter out of range',
                                  'data': [0x80, 0x28, 0x00]})

        cmd1 = "0x2E 0xF1 0x80 0x28 0x00 0x1A 0x1 0x00"
        cmd2 = "0x2E 0xF1 0x80 0x28 0x00 0x1A 0x2 0x00"
        actual_out = ipmi.get_gpu(self.info, gpu_ids)
        self.assertEqual(1, actual_out)
        exec_mock.assert_has_calls([mock.call(mock.ANY, cmd1),
                                    mock.call(mock.ANY, cmd2)])

    @mock.patch.object(ipmi, '_send_raw_command')
    def test_get_gpu_blank(self, exec_mock):
        gpu_ids = []

        actual_out = ipmi.get_gpu(self.info, gpu_ids)
        self.assertEqual(0, actual_out)
        self.assertTrue(exec_mock.called)

    @mock.patch.object(ipmi, '_send_raw_command')
    def test_get_gpu_not_found(self, exec_mock):
        gpu_ids = ['0x1111/0x1179', '0x2100/0x0080']

        exec_mock.side_effect = ({'command': 0xF1, 'code': 0x00, 'netfn': 0x2F,
                                  'data': [0x80, 0x28, 0x00, 0x00, 0x00, 0x05,
                                           0x00, 0x10, 0x79, 0x00, 0x34, 0x17,
                                           0x76, 0x11, 0x00, 0x04, 0x01]},
                                 {'command': 0xF1, 'code': 0xC9, 'netfn': 0x2F,
                                  'error': 'Parameter out of range',
                                  'data': [0x80, 0x28, 0x00]})
        cmd1 = "0x2E 0xF1 0x80 0x28 0x00 0x1A 0x1 0x00"
        cmd2 = "0x2E 0xF1 0x80 0x28 0x00 0x1A 0x2 0x00"
        actual_out = ipmi.get_gpu(self.info, gpu_ids)
        self.assertEqual(0, actual_out)
        exec_mock.assert_has_calls([mock.call(mock.ANY, cmd1),
                                    mock.call(mock.ANY, cmd2)])

    @mock.patch.object(ipmi, '_send_raw_command')
    def test_get_gpu_exception(self, exec_mock):
        gpu_ids = ['0x1111/0x1179', '0x2100/0x0080']

        exec_mock.side_effect = ipmi_exception.IpmiException('Error')

        cmd = "0x2E 0xF1 0x80 0x28 0x00 0x1A 0x1 0x00"

        e = self.assertRaises(ipmi.IPMIFailure,
                              ipmi.get_gpu,
                              self.info,
                              gpu_ids)
        exec_mock.assert_called_once_with(mock.ANY, cmd)
        self.assertEqual('IPMI operation \'GET GPU device quantity\' '
                         'failed: Error', str(e))
