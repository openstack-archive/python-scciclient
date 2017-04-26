# Copyright 2017 FUJITSU LIMITED
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
Test class for iRMC eLCM functionality.
"""

import time

import mock
import testtools

from scciclient.irmc import elcm
from scciclient.irmc import scci
from scciclient.irmc.viom import elcm as viom_elcm


class ELCMViomClientTestCase(testtools.TestCase):
    """Test for ELCMViomClient."""

    def setUp(self):
        super(ELCMViomClientTestCase, self).setUp()

        self.irmc_info = {
            'irmc_address': '10.124.196.159',
            'irmc_username': 'admin',
            'irmc_password': 'admin0',
            'irmc_port': 80,
            'irmc_auth_method': 'basic',
            'irmc_client_timeout': 60,
        }
        self.client = viom_elcm.ElcmViomClient(self.irmc_info)
        self.session_id = '10'

    @staticmethod
    def _session_status_resp(id, status):
        return {'Session': {'Id': id,
                            'Status': status}}

    @staticmethod
    def _session_log_resp(id):
        return {'Sessionlog':
                {'Id': id,
                 'Entries':
                    {'Entry':
                        {'@date': '2017/04/24 18:06:27',
                         '#text': 'CreateSession: create'}}}}

    @mock.patch.object(elcm, 'elcm_session_get_status')
    @mock.patch.object(time, 'sleep')
    def test__wait_session(self, mock_sleep, mock_get_session):
        mock_get_session.side_effect = [
            self._session_status_resp(self.session_id, 'running'),
            self._session_status_resp(self.session_id, 'activated'),
            self._session_status_resp(self.session_id, 'terminated regularly')]

        self.assertEqual({}, self.client._wait_session(self.session_id))
        mock_get_session.assert_has_calls(
            [mock.call(self.irmc_info, self.session_id) for i in range(0, 3)])
        self.assertEqual(3, mock_get_session.call_count)
        self.assertEqual(2, mock_sleep.call_count)

    @mock.patch.object(elcm, 'elcm_session_get_status')
    @mock.patch.object(elcm, 'elcm_session_get_log')
    def test__wait_session_error(self, mock_get_log, mock_get_session):
        mock_get_session.return_value = (
            self._session_status_resp(self.session_id,
                                      'terminated with error'))
        mock_get_log.return_value = self._session_log_resp(self.session_id)

        self.assertRaises(scci.SCCIClientError,
                          self.client._wait_session,
                          self.session_id)
        mock_get_session.assert_called_once_with(self.irmc_info,
                                                 self.session_id)
        mock_get_log.assert_called_once_with(irmc_info=self.irmc_info,
                                             session_id=self.session_id)

    @mock.patch.object(elcm, 'elcm_session_get_status')
    @mock.patch.object(elcm, 'elcm_session_get_log')
    def test__wait_session_error_log_error(self, mock_get_log,
                                           mock_get_session):
        mock_get_session.return_value = (
            self._session_status_resp(self.session_id,
                                      'terminated with error'))
        mock_get_log.side_effect = scci.SCCIClientError(
            'got an error')

        self.assertRaises(scci.SCCIClientError,
                          self.client._wait_session,
                          self.session_id)
        mock_get_session.assert_called_once_with(self.irmc_info,
                                                 self.session_id)
        mock_get_log.assert_called_once_with(irmc_info=self.irmc_info,
                                             session_id=self.session_id)

    @mock.patch.object(elcm, 'elcm_session_get_status')
    @mock.patch.object(elcm, 'elcm_session_get_log')
    @mock.patch.object(time, 'time')
    @mock.patch.object(time, 'sleep')
    def test__wait_session_timeout(self, mock_sleep, mock_time, mock_get_log,
                                   mock_get_session):
        timeout = 1800
        mock_time.side_effect = [100, 101 + timeout]
        mock_get_session.return_value = (
            self._session_status_resp(self.session_id, 'running'))
        mock_get_log.return_value = self._session_log_resp(self.session_id)

        self.assertRaises(elcm.ELCMSessionTimeout,
                          self.client._wait_session,
                          self.session_id)
        mock_get_session.assert_called_once_with(self.irmc_info,
                                                 self.session_id)
        mock_get_log.assert_called_once_with(irmc_info=self.irmc_info,
                                             session_id=self.session_id)

    @mock.patch.object(elcm, 'elcm_session_get_status')
    @mock.patch.object(elcm, 'elcm_session_get_log')
    @mock.patch.object(time, 'time')
    @mock.patch.object(time, 'sleep')
    def test__wait_session_timeout_specified(self, mock_sleep, mock_time,
                                             mock_get_log, mock_get_session):
        timeout = 60
        mock_time.side_effect = [100, 101 + timeout]
        mock_get_session.return_value = (
            self._session_status_resp(self.session_id, 'running'))
        mock_get_log.return_value = self._session_log_resp(self.session_id)

        self.assertRaises(elcm.ELCMSessionTimeout,
                          self.client._wait_session,
                          self.session_id,
                          timeout=timeout)
        mock_get_session.assert_called_once_with(self.irmc_info,
                                                 self.session_id)
        mock_get_log.assert_called_once_with(irmc_info=self.irmc_info,
                                             session_id=self.session_id)

    @mock.patch.object(elcm, 'elcm_session_get_status')
    @mock.patch.object(elcm, 'elcm_session_get_log')
    @mock.patch.object(time, 'time')
    @mock.patch.object(time, 'sleep')
    def test__wait_session_timeout_log_error(self, mock_sleep, mock_time,
                                             mock_get_log, mock_get_session):
        timeout = 1800
        mock_time.side_effect = [100, 101 + timeout]
        mock_get_session.return_value = (
            self._session_status_resp(self.session_id, 'running'))
        mock_get_log.side_effect = scci.SCCIClientError('got an error')

        self.assertRaises(elcm.ELCMSessionTimeout,
                          self.client._wait_session,
                          self.session_id)
        mock_get_session.assert_called_once_with(self.irmc_info,
                                                 self.session_id)
        mock_get_log.assert_called_once_with(irmc_info=self.irmc_info,
                                             session_id=self.session_id)

    @mock.patch.object(elcm, 'elcm_profile_set')
    @mock.patch.object(viom_elcm.ElcmViomClient, '_wait_session',
                       return_value={})
    def test_set_profile(self, mock_wait, mock_set):
        adapter_config = {
            'ViomManage': {'Manage': True},
            'InitBoot': True}
        mock_set.return_value = self._session_status_resp(self.session_id,
                                                          'activated')
        self.assertIsNone(self.client.set_profile(adapter_config))
        mock_wait.assert_called_once_with(self.session_id)
        mock_set.assert_called_once_with(
            self.irmc_info,
            {'Server':
                {'AdapterConfigIrmc':
                    {'ViomManage': {'Manage': True},
                     'InitBoot': True,
                     '@Processing': 'execute'}}})

    @mock.patch.object(elcm, 'elcm_profile_create')
    @mock.patch.object(viom_elcm.ElcmViomClient, '_wait_session',
                       return_value={})
    @mock.patch.object(elcm, 'elcm_profile_get')
    def _test_get_profile(self, mock_get, mock_wait, mock_create):
        mock_create.return_value = self._session_status_resp(self.session_id,
                                                             'activated')
        adapter_data = {
            'Server': {
                'AdapterConfigIrmc':
                    {'ViomManage': {'Manage': True},
                     'InitBoot': True}}}
        mock_get.return_value = adapter_data
        self.assertEqual(adapter_data, self.client.get_profile())
        mock_create.assert_called_once_with(self.irmc_info,
                                            'Server/AdapterConfigIrmc')
        mock_wait.assert_called_once_with(self.session_id)
        mock_get.assert_called_once_with(self.irmc_info,
                                         'AdapterConfigIrmc')

    @mock.patch.object(elcm, 'elcm_profile_delete')
    def test_get_profile_with_delete(self, mock_delete):
        self._test_get_profile()
        mock_delete.assert_called_once_with(self.irmc_info,
                                            'AdapterConfigIrmc')

    @mock.patch.object(elcm, 'elcm_profile_delete')
    def test_get_profile_without_delete(self, mock_delete):
        mock_delete.side_effect = elcm.ELCMProfileNotFound('not found')
        self._test_get_profile()
        mock_delete.assert_called_once_with(self.irmc_info,
                                            'AdapterConfigIrmc')


class ViomTableTestCase(testtools.TestCase):
    """Test for VIOM table."""

    def setUp(self):
        super(ViomTableTestCase, self).setUp()

    def test_iscsi_target_no_auth(self):
        iscsi_boot = viom_elcm.IscsiTarget(
            iqn='iqn',
            ip='192.168.1.10')
        expected_json = {
            'DHCPUsage': False,
            'Name': 'iqn',
            'IPv4Address': '192.168.1.10',
            'PortNumber': 3260,
            'BootLUN': 0,
            'AuthenticationMethod': 'None',
        }
        self.assertEqual(expected_json, iscsi_boot.get_json())
