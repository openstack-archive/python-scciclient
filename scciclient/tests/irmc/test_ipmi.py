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

import os
import stat
import tempfile
import time

import mock
import six
import testtools

from oslo_concurrency import processutils
from scciclient.irmc import ipmi


class IRMCIpmiTestCase(testtools.TestCase):
    """Tests for IPMI

    Unit Test Cases for getting information via ipmi raw command
    """

    def setUp(self):
        super(IRMCIpmiTestCase, self).setUp()

        self.info = {'irmc_address': "10.0.0.10",
                     'irmc_username': "admin",
                     'irmc_password': "admin",
                     'irmc_tempdir': "/tmp"
                     }

    @mock.patch.object(tempfile, 'NamedTemporaryFile', new=mock.MagicMock())
    @mock.patch.object(processutils, 'execute')
    def test_exec_ipmitool(self, exec_mock):
        exec_mock.return_value = ('Chassis Power is off\n', None)
        expected_output = 'Chassis Power is off\n'
        cmd = "chassis power status"
        actual_out = ipmi.exec_ipmitool(self.info, cmd)
        self.assertEqual(expected_output, actual_out)

    @mock.patch.object(tempfile, 'NamedTemporaryFile', new=mock.MagicMock())
    @mock.patch.object(processutils, 'execute')
    def test_exec_ipmitool_none(self, exec_mock):
        exec_mock.side_effect = processutils.ProcessExecutionError
        cmd = "fru print 0x2"
        actual_out = ipmi.exec_ipmitool(self.info, cmd)
        self.assertIsNone(actual_out)

    @mock.patch.object(ipmi, 'exec_ipmitool')
    def test_get_tpm_status_true(self, exec_mock):
        exec_mock.return_value = '123 C0 C0'
        cmd = "raw 0x2E 0xF5 0x80 0x28 0x00 0x81 0xC0"
        actual_out = ipmi.get_tpm_status(self.info)
        self.assertEqual(True, actual_out)
        exec_mock.assert_called_once_with(self.info, cmd)

    @mock.patch.object(ipmi, 'exec_ipmitool')
    def test_get_tpm_status_false(self, exec_mock):
        exec_mock.return_value = '123 C0 C1'
        cmd = "raw 0x2E 0xF5 0x80 0x28 0x00 0x81 0xC0"
        actual_out = ipmi.get_tpm_status(self.info)
        self.assertEqual(False, actual_out)
        exec_mock.assert_called_once_with(self.info, cmd)

    @mock.patch.object(ipmi, 'exec_ipmitool')
    def test_get_gpu_fpgas(self, exec_mock):
        gpu_ids = '0x1000/0x0079,0x2100/0x0080'
        fpga_ids = '0x1100/0x0181,0x2110/0x1254'
        exec_mock.side_effect = [
            '80 28 00 00 00 05 00 10 79 00 34 17 76 11 00 04\r\n01',
            None]
        cmd1 = "raw 0x2E 0xF1 0x80 0x28 0x00 0x1A 0x01 0x00"
        cmd2 = "raw 0x2E 0xF1 0x80 0x28 0x00 0x1A 0x02 0x00"
        actual_out = ipmi.get_gpu_fpgas(self.info, gpu_ids, fpga_ids)
        self.assertEqual((1, 0), actual_out)
        exec_mock.assert_has_calls([mock.call(self.info, cmd1),
                                    mock.call(self.info, cmd2)])

    @mock.patch.object(ipmi, 'exec_ipmitool')
    def test_get_gpu_fpgas_blank(self, exec_mock):
        gpu_ids = ''
        fpga_ids = ''

        actual_out = ipmi.get_gpu_fpgas(self.info, gpu_ids, fpga_ids)
        self.assertEqual((0, 0), actual_out)
        self.assertFalse(exec_mock.called)

    @mock.patch.object(ipmi, 'exec_ipmitool')
    def test_get_gpu_fpgas_not_found(self, exec_mock):
        gpu_ids = '0x1111/0x1179,0x2100/0x0080'
        fpga_ids = '0x1100/0x0181,0x2110/0x1254'
        exec_mock.side_effect = [
            '80 28 00 00 00 05 00 10 79 00 34 17 76 11 00 04\r\n01',
            None]
        cmd1 = "raw 0x2E 0xF1 0x80 0x28 0x00 0x1A 0x01 0x00"
        cmd2 = "raw 0x2E 0xF1 0x80 0x28 0x00 0x1A 0x02 0x00"
        actual_out = ipmi.get_gpu_fpgas(self.info, gpu_ids, fpga_ids)
        self.assertEqual((0, 0), actual_out)
        exec_mock.assert_has_calls([mock.call(self.info, cmd1),
                                    mock.call(self.info, cmd2)])


@mock.patch.object(time, 'sleep', autospec=True)
class IPMIPrivateMethodTestCase(testtools.TestCase):

    def setUp(self):
        super(IPMIPrivateMethodTestCase, self).setUp()

        self.info = {'irmc_address': "10.0.0.10",
                     'irmc_username': "admin",
                     'irmc_password': "admin",
                     'irmc_tempdir': "/tmp"
                     }

    def _test__make_password_file(self, mock_sleep, input_password,
                                  exception_to_raise=None):
        pw_file = None
        tempdir = self.info['irmc_tempdir']
        try:
            with ipmi._make_password_file(input_password, tempdir) as pw_file:
                if exception_to_raise is not None:
                    raise exception_to_raise
                self.assertTrue(os.path.isfile(pw_file))
                self.assertEqual(0o600, os.stat(pw_file)[stat.ST_MODE] & 0o777)
                with open(pw_file, "r") as f:
                    password = f.read()
                self.assertEqual(str(input_password), password)
        finally:
            if pw_file is not None:
                self.assertFalse(os.path.isfile(pw_file))

    def test__make_password_file_str_password(self, mock_sleep):
        self._test__make_password_file(mock_sleep, self.info['irmc_password'])

    def test__make_password_file_with_numeric_password(self, mock_sleep):
        self._test__make_password_file(mock_sleep, 12345)

    def test__make_password_file_caller_exception(self, mock_sleep):
        # Test caller raising exception
        result = self.assertRaises(
            ValueError,
            self._test__make_password_file,
            mock_sleep, 12345, ValueError('we should fail'))
        self.assertEqual('we should fail', six.text_type(result))

    @mock.patch.object(tempfile, 'NamedTemporaryFile',
                       new=mock.MagicMock(side_effect=OSError('Test Error')))
    def test__make_password_file_tempfile_known_exception(self, mock_sleep):
        # Test OSError exception in _make_password_file for
        # tempfile.NamedTemporaryFile
        self.assertRaises(
            ipmi.PasswordFileFailedToCreate,
            self._test__make_password_file, mock_sleep, 12345)

    @mock.patch.object(
        tempfile, 'NamedTemporaryFile',
        new=mock.MagicMock(side_effect=OverflowError('Test Error')))
    def test__make_password_file_tempfile_unknown_exception(self, mock_sleep):
        # Test exception in _make_password_file for tempfile.NamedTemporaryFile
        result = self.assertRaises(
            ipmi.PasswordFileFailedToCreate,
            self._test__make_password_file, mock_sleep, 12345)
        self.assertEqual('Failed to create the password file. Test Error',
                         six.text_type(result))

    def test__make_password_file_write_exception(self, mock_sleep):
        # Test exception in _make_password_file for write()
        mock_namedtemp = mock.mock_open(mock.MagicMock(name='JLV'))
        with mock.patch('tempfile.NamedTemporaryFile', mock_namedtemp):
            mock_filehandle = mock_namedtemp.return_value
            mock_write = mock_filehandle.write
            mock_write.side_effect = OSError('Test 2 Error')
            self.assertRaises(
                ipmi.PasswordFileFailedToCreate,
                self._test__make_password_file, mock_sleep, 12345)
