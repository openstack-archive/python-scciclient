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


class ELCMVIOMClientTestCase(testtools.TestCase):
    """Test for ELCMViomClient."""

    def setUp(self):
        super(ELCMVIOMClientTestCase, self).setUp()

        self.irmc_info = {
            'irmc_address': '10.124.196.159',
            'irmc_username': 'admin',
            'irmc_password': 'admin0',
            'irmc_port': 80,
            'irmc_auth_method': 'basic',
            'irmc_client_timeout': 60,
        }
        self.client = viom_elcm.ELCMVIOMClient(self.irmc_info)
        self.session_id = '10'

    @staticmethod
    def _session_status_resp(session_id, status):
        return {'Session': {'Id': session_id,
                            'Status': status}}

    @staticmethod
    def _session_log_resp(session_id):
        return {'Sessionlog':
                {'Id': session_id,
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
    @mock.patch.object(viom_elcm.ELCMVIOMClient, '_wait_session',
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
    @mock.patch.object(viom_elcm.ELCMVIOMClient, '_wait_session',
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


class VIOMTableTestCase(testtools.TestCase):
    """Test for VIOM table."""

    def setUp(self):
        super(VIOMTableTestCase, self).setUp()

    @staticmethod
    def _sample_manage_table():
        return viom_elcm.ManageTable(
            manage=True,
            identification='identity',
            force=True)

    @staticmethod
    def _sample_manage_table_json():
        return {
            'Manage': True,
            'Identification': 'identity',
            'Force': True,
        }

    @staticmethod
    def _add_sample_cards_to_slot(slot):
        slot.add_card(VIOMTableTestCase._sample_onboard_card())
        slot.add_card(VIOMTableTestCase._sample_addon_card())

    @staticmethod
    def _sample_slot_json():
        return {
            '@SlotIdx': 0,
            'OnboardControllers': {
                'OnboardController': [
                    VIOMTableTestCase._sample_onboard_card_json()
                ]
            },
            'AddOnCards': {
                'AddOnCard': [
                    VIOMTableTestCase._sample_addon_card_json()
                ]
            }
        }

    @staticmethod
    def _sample_onboard_card():
        onboard_card = viom_elcm.OnboardCard(1, viom_elcm.LANAdapter())
        onboard_card.add_port(VIOMTableTestCase._sample_lan_port(1))
        return onboard_card

    @staticmethod
    def _sample_onboard_card_json():
        return {
            '@OnboardControllerIdx': 1,
            'LANAdapter': {
                'Ports': {
                    'Port': [
                        VIOMTableTestCase._sample_lan_port_json(1),
                    ]
                }
            }
        }

    @staticmethod
    def _sample_addon_card():
        addon_card = viom_elcm.AddOnCard(2, viom_elcm.FCAdapter())
        addon_card.add_port(VIOMTableTestCase._sample_fc_port(1))
        return addon_card

    @staticmethod
    def _sample_addon_card_json():
        return {
            '@AddOnCardIdx': 2,
            'FCAdapter': {
                'Ports': {
                    'Port': [
                        VIOMTableTestCase._sample_fc_port_json(1),
                    ]
                }
            }
        }

    @staticmethod
    def _sample_lan_port(port_id=1):
        return viom_elcm.LANPort(port_id)

    @staticmethod
    def _sample_lan_port_json(port_id=1):
        return {
            '@PortIdx': port_id,
            'PortEnable': True,
            'BootProtocol': 'None',
            'BootPriority': 1,
        }

    @staticmethod
    def _sample_fc_port(port_id=1):
        return viom_elcm.FCPort(
            port_id, boot=VIOMTableTestCase._sample_fc_boot())

    @staticmethod
    def _sample_fc_port_json(port_id=1):
        sample = {
            '@PortIdx': port_id,
            'PortEnable': True,
            'BootProtocol': 'FC',
            'BootPriority': 1,
        }
        sample.update(
            VIOMTableTestCase._sample_fc_boot_json())
        return sample

    @staticmethod
    def _sample_cna_port(port_id=1):
        cna_port = viom_elcm.CNAPort(port_id)
        cna_port.add_function(
            VIOMTableTestCase._sample_lan_function())
        cna_port.add_function(
            VIOMTableTestCase._sample_iscsi_function())
        return cna_port

    @staticmethod
    def _sample_cna_port_json(port_id=1):
        return {
            '@PortIdx': port_id,
            'PortEnable': True,
            'Functions': {
                'Function': [
                    VIOMTableTestCase._sample_lan_function_json(),
                    VIOMTableTestCase._sample_iscsi_function_json()
                ]
            }
        }

    @staticmethod
    def _sample_lan_function():
        return viom_elcm.LANFunction(1, function_enable=False)

    @staticmethod
    def _sample_lan_function_json():
        return {
            '@FunctionIdx': 1,
            'LANFunction': {
                'FunctionEnable': False,
                'BootProtocol': 'None',
                'BootPriority': 1,
            }
        }

    @staticmethod
    def _sample_fcoe_function():
        return viom_elcm.FCoEFunction(
            2, boot=VIOMTableTestCase._sample_fc_boot())

    @staticmethod
    def _sample_fcoe_function_json():
        sample = {
            '@FunctionIdx': 2,
            'FCoEFunction': {
                'FunctionEnable': True,
                'BootProtocol': 'FC',
                'BootPriority': 1,
            },
        }
        sample['FCoEFunction'].update(
            VIOMTableTestCase._sample_fc_boot_json())
        return sample

    @staticmethod
    def _sample_iscsi_function():
        return viom_elcm.ISCSIFunction(
            3, boot=VIOMTableTestCase._sample_iscsi_boot())

    @staticmethod
    def _sample_iscsi_function_json():
        sample = {
            '@FunctionIdx': 3,
            'ISCSIFunction': {
                'FunctionEnable': True,
                'BootProtocol': 'ISCSI',
                'BootPriority': 1,
            },
        }
        sample['ISCSIFunction'].update(
            VIOMTableTestCase._sample_iscsi_boot_json())
        return sample

    @staticmethod
    def _sample_fc_boot(boot_prio=None):
        if boot_prio:
            fc_boot = viom_elcm.FCBoot(boot_prio=boot_prio)
        else:
            fc_boot = viom_elcm.FCBoot()
        fc_boot.add_target(VIOMTableTestCase._sample_fc_target())
        return fc_boot

    @staticmethod
    def _sample_fc_boot_json():
        return {
            'FCBootEnvironment': {
                'FCTargets': {
                    'FCTarget': [VIOMTableTestCase._sample_fc_target_json()]
                },
                'FCLinkSpeed': 'auto',
                'FCTopology': 'auto_loop',
            }
        }

    @staticmethod
    def _sample_fc_target(wwpn='11:22:33:44:55'):
        return viom_elcm.FCTarget(wwpn)

    @staticmethod
    def _sample_fc_target_json(target_idx=1, wwpn='11:22:33:44:55'):
        return {'@FCTargetIdx': target_idx,
                'TargetWWPN': wwpn,
                'TargetLUN': 0}

    @staticmethod
    def _sample_iscsi_boot(boot_prio=None):
        if boot_prio:
            return viom_elcm.ISCSIBoot(
                VIOMTableTestCase._sample_iscsi_initiator(),
                VIOMTableTestCase._sample_iscsi_target(),
                boot_prio=boot_prio)
        else:
            return viom_elcm.ISCSIBoot(
                VIOMTableTestCase._sample_iscsi_initiator(),
                VIOMTableTestCase._sample_iscsi_target())

    @staticmethod
    def _sample_iscsi_boot_json():
        return {
            'ISCSIBootEnvironment': {
                'ISCSIInitiator':
                    VIOMTableTestCase._sample_iscsi_initiator_json(),
                'ISCSITarget':
                    VIOMTableTestCase._sample_iscsi_target_json()
            }
        }

    @staticmethod
    def _sample_iscsi_initiator():
        return viom_elcm.ISCSIInitiator(
            iqn='iqn-2017-04.com.fujitsu:001',
            ip='192.168.1.11',
            subnet='255.255.255.0',
            gateway='192.168.1.1')

    @staticmethod
    def _sample_iscsi_initiator_json():
        return {
            'DHCPUsage': False,
            'Name': 'iqn-2017-04.com.fujitsu:001',
            'IPv4Address': '192.168.1.11',
            'SubnetMask': '255.255.255.0',
            'GatewayIPv4Address': '192.168.1.1',
            'VLANId': 0,
        }

    @staticmethod
    def _sample_iscsi_target():
        return viom_elcm.ISCSITarget(
            iqn='iqn-2017-04.com.fujitsu:101',
            ip='192.168.2.22',
            auth_method='CHAP',
            chap_user='chap_user',
            chap_secret='chap_secret')

    @staticmethod
    def _sample_iscsi_target_json():
        return {
            'DHCPUsage': False,
            'Name': 'iqn-2017-04.com.fujitsu:101',
            'IPv4Address': '192.168.2.22',
            'PortNumber': 3260,
            'BootLUN': 0,
            'AuthenticationMethod': 'CHAP',
            'ChapUserName': 'chap_user',
            'ChapSecret': 'chap_secret',
        }

    def test_root(self):
        root = viom_elcm.VIOMTable(
            viom_boot_enable=True,
            init_boot=True,
            processing='execute',
            mode='new')
        root.set_manage_table(VIOMTableTestCase._sample_manage_table())
        self.assertEqual(None, root.get_slot(0, create=False))
        slot = root.get_slot(0)
        VIOMTableTestCase._add_sample_cards_to_slot(slot)
        self.assertEqual(slot, root.get_slot(0))
        expected_json = {
            'VIOMManage': VIOMTableTestCase._sample_manage_table_json(),
            'InitBoot': True,
            'VIOMBootEnable': True,
            '@Processing': 'execute',
            'Mode': 'new',
            'Slots': {
                'Slot': [
                    VIOMTableTestCase._sample_slot_json()
                ]
            },
        }
        self.assertEqual(expected_json, root.get_json())

    def test_root_empty(self):
        root = viom_elcm.VIOMTable()
        self.assertEqual({}, root.get_json())

    def test_root_detail(self):
        root = viom_elcm.VIOMTable(
            use_virtual_addresses=True,
            viom_boot_enable=True,
            boot_menu_enable=False,
            sriov=False,
            smux='None',
            init_boot=True,
            processing='execute',
            mode='modify')
        root.set_manage_table(VIOMTableTestCase._sample_manage_table())
        VIOMTableTestCase._add_sample_cards_to_slot(root.get_slot(0))
        expected_json = {
            'VIOMManage': VIOMTableTestCase._sample_manage_table_json(),
            'UseVirtualAddresses': True,
            'VIOMBootEnable': True,
            'BootMenuEnable': False,
            'SRIOV': False,
            'Smux': 'None',
            'InitBoot': True,
            '@Processing': 'execute',
            'Mode': 'modify',
            'Slots': {
                'Slot': [
                    VIOMTableTestCase._sample_slot_json()
                ]
            },
        }
        self.assertEqual(expected_json, root.get_json())

    def test_manage_table(self):
        manage_table = viom_elcm.ManageTable(
            manage=True,
            identification='identity',
            force=True)
        expected_json = {
            'Manage': True,
            'Identification': 'identity',
            'Force': True,
        }
        self.assertEqual(expected_json, manage_table.get_json())

    def test_manage_table_detail(self):
        manage_table = viom_elcm.ManageTable(
            manage=True,
            identification='identity',
            force=False,
            trap_destination='192.168.3.33',
            preferred_version='2.6')
        expected_json = {
            'Manage': True,
            'Identification': 'identity',
            'Force': False,
            'TrapDestination': '192.168.3.33',
            'PreferredInventoryVersion': '2.6',
        }
        self.assertEqual(expected_json, manage_table.get_json())

    def test_slot(self):
        slot = viom_elcm.Slot(0)
        onboard_card = VIOMTableTestCase._sample_onboard_card()
        slot.add_card(onboard_card)
        addon_card = VIOMTableTestCase._sample_addon_card()
        slot.add_card(addon_card)
        expected_json = {
            '@SlotIdx': 0,
            'OnboardControllers': {
                'OnboardController': [
                    VIOMTableTestCase._sample_onboard_card_json()
                ]
            },
            'AddOnCards': {
                'AddOnCard': [
                    VIOMTableTestCase._sample_addon_card_json()
                ]
            }
        }
        self.assertEqual(expected_json, slot.get_json())
        self.assertEqual(onboard_card, slot.get_onboard_card(1))
        self.assertEqual(addon_card, slot.get_addon_card(2))

    def test_slot_only_onboard(self):
        slot = viom_elcm.Slot(1)
        card = VIOMTableTestCase._sample_onboard_card()
        slot.add_card(card)
        expected_json = {
            '@SlotIdx': 1,
            'OnboardControllers': {
                'OnboardController': [
                    VIOMTableTestCase._sample_onboard_card_json()
                ]
            },
        }
        self.assertEqual(expected_json, slot.get_json())
        self.assertEqual(card, slot.get_onboard_card(1))

    def test_slot_only_addon(self):
        slot = viom_elcm.Slot(2)
        card = VIOMTableTestCase._sample_addon_card()
        slot.add_card(card)
        expected_json = {
            '@SlotIdx': 2,
            'AddOnCards': {
                'AddOnCard': [
                    VIOMTableTestCase._sample_addon_card_json()
                ]
            }
        }
        self.assertEqual(expected_json, slot.get_json())
        self.assertEqual(card, slot.get_addon_card(2))

    def test_onboard_card(self):
        onboard_card = viom_elcm.OnboardCard(1, viom_elcm.LANAdapter())
        port1 = VIOMTableTestCase._sample_lan_port(1)
        port2 = VIOMTableTestCase._sample_lan_port(2)
        onboard_card.add_port(port1)
        onboard_card.add_port(port2)
        expected_json = {
            '@OnboardControllerIdx': 1,
            'LANAdapter': {
                'Ports': {
                    'Port': [
                        VIOMTableTestCase._sample_lan_port_json(1),
                        VIOMTableTestCase._sample_lan_port_json(2)
                    ]
                }
            }
        }
        self.assertEqual(expected_json, onboard_card.get_json())
        self.assertEqual(port1, onboard_card.get_port(1))
        self.assertEqual(port2, onboard_card.get_port(2))

    def test_addon_card(self):
        addon_card = viom_elcm.AddOnCard(2, viom_elcm.FCAdapter())
        port1 = VIOMTableTestCase._sample_fc_port(1)
        port2 = VIOMTableTestCase._sample_fc_port(2)
        addon_card.add_port(port1)
        addon_card.add_port(port2)
        expected_json = {
            '@AddOnCardIdx': 2,
            'FCAdapter': {
                'Ports': {
                    'Port': [
                        VIOMTableTestCase._sample_fc_port_json(1),
                        VIOMTableTestCase._sample_fc_port_json(2)
                    ]
                }
            }
        }
        self.assertEqual(expected_json, addon_card.get_json())
        self.assertEqual(port1, addon_card.get_port(1))
        self.assertEqual(port2, addon_card.get_port(2))

    def test_lan_adapter(self):
        lan_adapter = viom_elcm.LANAdapter()
        port1 = VIOMTableTestCase._sample_lan_port(1)
        port2 = VIOMTableTestCase._sample_lan_port(2)
        lan_adapter.add_port(port1)
        lan_adapter.add_port(port2)
        expected_json = {
            'LANAdapter': {
                'Ports': {
                    'Port': [
                        VIOMTableTestCase._sample_lan_port_json(1),
                        VIOMTableTestCase._sample_lan_port_json(2)
                    ]
                }
            }
        }
        self.assertEqual(expected_json, lan_adapter.get_json())
        self.assertEqual(port1, lan_adapter.get_port(1))
        self.assertEqual(port2, lan_adapter.get_port(2))

    def test_fc_adapter(self):
        fc_adapter = viom_elcm.FCAdapter()
        port1 = VIOMTableTestCase._sample_fc_port(1)
        port2 = VIOMTableTestCase._sample_fc_port(2)
        fc_adapter.add_port(port1)
        fc_adapter.add_port(port2)
        expected_json = {
            'FCAdapter': {
                'Ports': {
                    'Port': [
                        VIOMTableTestCase._sample_fc_port_json(1),
                        VIOMTableTestCase._sample_fc_port_json(2)
                    ]
                }
            }
        }
        self.assertEqual(expected_json, fc_adapter.get_json())
        self.assertEqual(port1, fc_adapter.get_port(1))
        self.assertEqual(port2, fc_adapter.get_port(2))

    def test_cna_adapter(self):
        cna_adapter = viom_elcm.CNAAdapter()
        port1 = VIOMTableTestCase._sample_cna_port(1)
        port2 = VIOMTableTestCase._sample_cna_port(2)
        cna_adapter.add_port(port1)
        cna_adapter.add_port(port2)
        expected_json = {
            'CNAAdapter': {
                'Ports': {
                    'Port': [
                        VIOMTableTestCase._sample_cna_port_json(1),
                        VIOMTableTestCase._sample_cna_port_json(2)
                    ]
                }
            }
        }
        self.assertEqual(expected_json, cna_adapter.get_json())
        self.assertEqual(port1, cna_adapter.get_port(1))
        self.assertEqual(port2, cna_adapter.get_port(2))

    def test_lan_port(self):
        lan_port = viom_elcm.LANPort(1)
        expected_json = {
            '@PortIdx': 1,
            'PortEnable': True,
            'BootProtocol': 'None',
            'BootPriority': 1,
        }
        self.assertEqual(expected_json, lan_port.get_json())

    def test_lan_port_pxe_boot(self):
        lan_port = viom_elcm.LANPort(
            2, boot=viom_elcm.PXEBoot(boot_prio=3))
        expected_json = {
            '@PortIdx': 2,
            'PortEnable': True,
            'BootProtocol': 'PXE',
            'BootPriority': 3,
        }
        self.assertEqual(expected_json, lan_port.get_json())

    def test_lan_port_virtualize_mac(self):
        lan_port = viom_elcm.LANPort(
            3, use_virtual_addresses=True, mac='11:22:33:44:55')
        expected_json = {
            '@PortIdx': 3,
            'PortEnable': True,
            'BootProtocol': 'None',
            'BootPriority': 1,
            'UseVirtualAddresses': True,
            'VirtualAddress': {
                'MAC': '11:22:33:44:55'
            }
        }
        self.assertEqual(expected_json, lan_port.get_json())

    def test_lan_port_detail(self):
        lan_port = viom_elcm.LANPort(4, port_enable=False, sriov=True)
        expected_json = {
            '@PortIdx': 4,
            'PortEnable': False,
            'BootProtocol': 'None',
            'BootPriority': 1,
            'SRIOV': True,
        }
        self.assertEqual(expected_json, lan_port.get_json())

    def test_fc_port(self):
        fc_port = viom_elcm.FCPort(
            1, boot=VIOMTableTestCase._sample_fc_boot())
        expected_json = {
            '@PortIdx': 1,
            'PortEnable': True,
            'BootProtocol': 'FC',
            'BootPriority': 1,
        }
        expected_json.update(
            VIOMTableTestCase._sample_fc_boot_json())
        self.assertEqual(expected_json, fc_port.get_json())

    def test_fc_port_boot_priority(self):
        fc_port = viom_elcm.FCPort(
            2, boot=VIOMTableTestCase._sample_fc_boot(boot_prio=3))
        expected_json = {
            '@PortIdx': 2,
            'PortEnable': True,
            'BootProtocol': 'FC',
            'BootPriority': 3,
        }
        expected_json.update(
            VIOMTableTestCase._sample_fc_boot_json())
        self.assertEqual(expected_json, fc_port.get_json())

    def test_fc_port_virtualize_wwn(self):
        fc_port = viom_elcm.FCPort(
            3, boot=VIOMTableTestCase._sample_fc_boot(),
            use_virtual_addresses=True,
            wwnn='11:22:33:44:55', wwpn='66:77:88:99:00')
        expected_json = {
            '@PortIdx': 3,
            'PortEnable': True,
            'BootProtocol': 'FC',
            'BootPriority': 1,
            'UseVirtualAddresses': True,
            'VirtualAddress': {
                'WWNN': '11:22:33:44:55',
                'WWPN': '66:77:88:99:00'
            },
        }
        expected_json.update(
            VIOMTableTestCase._sample_fc_boot_json())
        self.assertEqual(expected_json, fc_port.get_json())

    def test_fc_port_detail(self):
        fc_port = viom_elcm.FCPort(
            4, boot=VIOMTableTestCase._sample_fc_boot(),
            port_enable=False, sriov=True)
        expected_json = {
            '@PortIdx': 4,
            'PortEnable': False,
            'BootProtocol': 'FC',
            'BootPriority': 1,
            'SRIOV': True,
        }
        expected_json.update(
            VIOMTableTestCase._sample_fc_boot_json())
        self.assertEqual(expected_json, fc_port.get_json())

    def test_cna_port_fcoe(self):
        cna_port = viom_elcm.CNAPort(1)
        lan_function = VIOMTableTestCase._sample_lan_function()
        fcoe_function = VIOMTableTestCase._sample_fcoe_function()
        cna_port.add_function(lan_function)
        cna_port.add_function(fcoe_function)
        expected_json = {
            '@PortIdx': 1,
            'PortEnable': True,
            'Functions': {
                'Function': [
                    VIOMTableTestCase._sample_lan_function_json(),
                    VIOMTableTestCase._sample_fcoe_function_json()
                ]
            }
        }
        self.assertEqual(expected_json, cna_port.get_json())
        self.assertEqual(lan_function, cna_port.get_function(1))
        self.assertEqual(fcoe_function, cna_port.get_function(2))

    def test_cna_port_iscsi(self):
        cna_port = viom_elcm.CNAPort(2)
        cna_port.add_function(
            VIOMTableTestCase._sample_lan_function())
        cna_port.add_function(
            VIOMTableTestCase._sample_iscsi_function())
        expected_json = {
            '@PortIdx': 2,
            'PortEnable': True,
            'Functions': {
                'Function': [
                    VIOMTableTestCase._sample_lan_function_json(),
                    VIOMTableTestCase._sample_iscsi_function_json()
                ]
            }
        }
        self.assertEqual(expected_json, cna_port.get_json())

    def test_cna_port_disable(self):
        cna_port = viom_elcm.CNAPort(3, port_enable=False)
        cna_port.add_function(
            VIOMTableTestCase._sample_lan_function())
        cna_port.add_function(
            VIOMTableTestCase._sample_iscsi_function())
        expected_json = {
            '@PortIdx': 3,
            'PortEnable': False,
            'Functions': {
                'Function': [
                    VIOMTableTestCase._sample_lan_function_json(),
                    VIOMTableTestCase._sample_iscsi_function_json()
                ]
            }
        }
        self.assertEqual(expected_json, cna_port.get_json())

    def test_lan_function(self):
        lan_function = viom_elcm.LANFunction(1)
        expected_json = {
            '@FunctionIdx': 1,
            'LANFunction': {
                'FunctionEnable': True,
                'BootProtocol': 'None',
                'BootPriority': 1,
            }
        }
        self.assertEqual(expected_json, lan_function.get_json())

    def test_lan_function_pxe_boot(self):
        lan_function = viom_elcm.LANFunction(
            2, boot=viom_elcm.PXEBoot(boot_prio=3))
        expected_json = {
            '@FunctionIdx': 2,
            'LANFunction': {
                'FunctionEnable': True,
                'BootProtocol': 'PXE',
                'BootPriority': 3,
            }
        }
        self.assertEqual(expected_json, lan_function.get_json())

    def test_lan_function_virtualize_mac(self):
        lan_function = viom_elcm.LANFunction(
            3, use_virtual_addresses=True, mac='11:22:33:44:55')
        expected_json = {
            '@FunctionIdx': 3,
            'LANFunction': {
                'FunctionEnable': True,
                'BootProtocol': 'None',
                'BootPriority': 1,
                'UseVirtualAddresses': True,
                'VirtualAddress': {
                    'MAC': '11:22:33:44:55'
                },
            }
        }
        self.assertEqual(expected_json, lan_function.get_json())

    def test_lan_function_detail(self):
        lan_function = viom_elcm.LANFunction(
            4, function_enable=False, vlan_id=123, bandwidth=50,
            rate_limit=100, sriov=True)
        expected_json = {
            '@FunctionIdx': 4,
            'LANFunction': {
                'FunctionEnable': False,
                'BootProtocol': 'None',
                'BootPriority': 1,
                'VLANId': 123,
                'Bandwidth': 50,
                'RateLimit': 100,
                'SRIOV': True,
            }
        }
        self.assertEqual(expected_json, lan_function.get_json())

    def test_fcoe_function(self):
        fcoe_function = viom_elcm.FCoEFunction(
            1, boot=VIOMTableTestCase._sample_fc_boot())
        expected_json = {
            '@FunctionIdx': 1,
            'FCoEFunction': {
                'FunctionEnable': True,
                'BootProtocol': 'FC',
                'BootPriority': 1,
            },
        }
        expected_json['FCoEFunction'].update(
            VIOMTableTestCase._sample_fc_boot_json())
        self.assertEqual(expected_json, fcoe_function.get_json())

    def test_fcoe_function_boot_priority(self):
        fcoe_function = viom_elcm.FCoEFunction(
            2, boot=VIOMTableTestCase._sample_fc_boot(boot_prio=3))
        expected_json = {
            '@FunctionIdx': 2,
            'FCoEFunction': {
                'FunctionEnable': True,
                'BootProtocol': 'FC',
                'BootPriority': 3,
            },
        }
        expected_json['FCoEFunction'].update(
            VIOMTableTestCase._sample_fc_boot_json())
        self.assertEqual(expected_json, fcoe_function.get_json())

    def test_fcoe_function_virtualize_wwn(self):
        fcoe_function = viom_elcm.FCoEFunction(
            3, boot=VIOMTableTestCase._sample_fc_boot(),
            use_virtual_addresses=True,
            wwnn='11:22:33:44:55', wwpn='66:77:88:99:00')
        expected_json = {
            '@FunctionIdx': 3,
            'FCoEFunction': {
                'FunctionEnable': True,
                'BootProtocol': 'FC',
                'BootPriority': 1,
                'UseVirtualAddresses': True,
                'VirtualAddress': {
                    'WWNN': '11:22:33:44:55',
                    'WWPN': '66:77:88:99:00'
                },
            },
        }
        expected_json['FCoEFunction'].update(
            VIOMTableTestCase._sample_fc_boot_json())
        self.assertEqual(expected_json, fcoe_function.get_json())

    def test_fcoe_function_virtualize_mac(self):
        fcoe_function = viom_elcm.FCoEFunction(
            4, boot=VIOMTableTestCase._sample_fc_boot(),
            use_virtual_addresses=True, mac='aa:bb:cc:dd:ee')
        expected_json = {
            '@FunctionIdx': 4,
            'FCoEFunction': {
                'FunctionEnable': True,
                'BootProtocol': 'FC',
                'BootPriority': 1,
                'UseVirtualAddresses': True,
                'VirtualAddress': {
                    'MAC': 'aa:bb:cc:dd:ee'
                },
            },
        }
        expected_json['FCoEFunction'].update(
            VIOMTableTestCase._sample_fc_boot_json())
        self.assertEqual(expected_json, fcoe_function.get_json())

    def test_fcoe_function_detail(self):
        fcoe_function = viom_elcm.FCoEFunction(
            5, boot=VIOMTableTestCase._sample_fc_boot(),
            function_enable=False, vlan_id=123, bandwidth=50, rate_limit=100,
            sriov=True)
        expected_json = {
            '@FunctionIdx': 5,
            'FCoEFunction': {
                'FunctionEnable': False,
                'BootProtocol': 'FC',
                'BootPriority': 1,
                'VLANId': 123,
                'Bandwidth': 50,
                'RateLimit': 100,
                'SRIOV': True,
            },
        }
        expected_json['FCoEFunction'].update(
            VIOMTableTestCase._sample_fc_boot_json())
        self.assertEqual(expected_json, fcoe_function.get_json())

    def test_iscsi_function(self):
        iscsi_function = viom_elcm.ISCSIFunction(
            1, boot=VIOMTableTestCase._sample_iscsi_boot())
        expected_json = {
            '@FunctionIdx': 1,
            'ISCSIFunction': {
                'FunctionEnable': True,
                'BootProtocol': 'ISCSI',
                'BootPriority': 1,
            },
        }
        expected_json['ISCSIFunction'].update(
            VIOMTableTestCase._sample_iscsi_boot_json())
        self.assertEqual(expected_json, iscsi_function.get_json())

    def test_iscsi_function_boot_priority(self):
        iscsi_function = viom_elcm.ISCSIFunction(
            2, boot=VIOMTableTestCase._sample_iscsi_boot(boot_prio=3))
        expected_json = {
            '@FunctionIdx': 2,
            'ISCSIFunction': {
                'FunctionEnable': True,
                'BootProtocol': 'ISCSI',
                'BootPriority': 3,
            },
        }
        expected_json['ISCSIFunction'].update(
            VIOMTableTestCase._sample_iscsi_boot_json())
        self.assertEqual(expected_json, iscsi_function.get_json())

    def test_iscsi_functon_virtulaize_mac(self):
        iscsi_function = viom_elcm.ISCSIFunction(
            3, boot=VIOMTableTestCase._sample_iscsi_boot(),
            use_virtual_addresses=True, mac='12:34:56:78:90')
        expected_json = {
            '@FunctionIdx': 3,
            'ISCSIFunction': {
                'FunctionEnable': True,
                'BootProtocol': 'ISCSI',
                'BootPriority': 1,
                'UseVirtualAddresses': True,
                'VirtualAddress': {
                    'MAC': '12:34:56:78:90'
                },
            },
        }
        expected_json['ISCSIFunction'].update(
            VIOMTableTestCase._sample_iscsi_boot_json())
        self.assertEqual(expected_json, iscsi_function.get_json())

    def test_iscsi_functon_detail(self):
        iscsi_function = viom_elcm.ISCSIFunction(
            4, boot=VIOMTableTestCase._sample_iscsi_boot(),
            function_enable=False, vlan_id=123, bandwidth=50, rate_limit=100,
            sriov=True)
        expected_json = {
            '@FunctionIdx': 4,
            'ISCSIFunction': {
                'FunctionEnable': False,
                'BootProtocol': 'ISCSI',
                'BootPriority': 1,
                'VLANId': 123,
                'Bandwidth': 50,
                'RateLimit': 100,
                'SRIOV': True,
            },
        }
        expected_json['ISCSIFunction'].update(
            VIOMTableTestCase._sample_iscsi_boot_json())
        self.assertEqual(expected_json, iscsi_function.get_json())

    def test_none_boot(self):
        none_boot = viom_elcm.NoneBoot()
        self.assertEqual({}, none_boot.get_json())

    def test_pxe_boot(self):
        pxe_boot = viom_elcm.PXEBoot()
        self.assertEqual({}, pxe_boot.get_json())

    def test_fc_boot(self):
        fc_boot = viom_elcm.FCBoot()
        fc_boot.add_target(VIOMTableTestCase._sample_fc_target())
        expected_json = {
            'FCBootEnvironment': {
                'FCTargets': {
                    'FCTarget': [VIOMTableTestCase._sample_fc_target_json()]
                },
                'FCLinkSpeed': 'auto',
                'FCTopology': 'auto_loop',
            }
        }
        self.assertEqual(expected_json, fc_boot.get_json())

    def test_fc_boot_detail(self):
        fc_boot = viom_elcm.FCBoot(
            link_speed='auto',
            topology='auto_PtP',
            boot_enable=False)
        fc_boot.add_target(VIOMTableTestCase._sample_fc_target())
        expected_json = {
            'FCBootEnvironment': {
                'FCTargets': {
                    'FCTarget': [VIOMTableTestCase._sample_fc_target_json()]
                },
                'FCLinkSpeed': 'auto',
                'FCTopology': 'auto_PtP',
                'SANBootEnable': False,
            }
        }
        self.assertEqual(expected_json, fc_boot.get_json())

    def test_fc_boot_mulit_targets(self):
        fc_boot = viom_elcm.FCBoot()
        fc_boot.add_target(VIOMTableTestCase._sample_fc_target())
        fc_boot.add_target(
            VIOMTableTestCase._sample_fc_target('aa:bb:cc:dd:ee:ff'))
        expected_json = {
            'FCBootEnvironment': {
                'FCTargets': {
                    'FCTarget': [
                        VIOMTableTestCase._sample_fc_target_json(),
                        VIOMTableTestCase._sample_fc_target_json(
                            target_idx=2, wwpn='aa:bb:cc:dd:ee:ff')
                    ]
                },
                'FCLinkSpeed': 'auto',
                'FCTopology': 'auto_loop',
            }
        }
        self.assertEqual(expected_json, fc_boot.get_json())

    def test_fc_target(self):
        fc_target = viom_elcm.FCTarget('11:22:33:44:55')
        expected_json = {
            '@FCTargetIdx': 1,
            'TargetWWPN': '11:22:33:44:55',
            'TargetLUN': 0,
        }
        self.assertEqual(expected_json, fc_target.get_json())

    def test_fc_target_lun(self):
        fc_target = viom_elcm.FCTarget('11:22:33:44:55', lun=1)
        expected_json = {
            '@FCTargetIdx': 1,
            'TargetWWPN': '11:22:33:44:55',
            'TargetLUN': 1,
        }
        self.assertEqual(expected_json, fc_target.get_json())

    def test_iscsi_boot(self):
        iscsi_boot = viom_elcm.ISCSIBoot(
            VIOMTableTestCase._sample_iscsi_initiator(),
            VIOMTableTestCase._sample_iscsi_target())
        expected_json = {
            'ISCSIBootEnvironment': {
                'ISCSIInitiator':
                    VIOMTableTestCase._sample_iscsi_initiator_json(),
                'ISCSITarget':
                    VIOMTableTestCase._sample_iscsi_target_json()
            }
        }
        self.assertEqual(expected_json, iscsi_boot.get_json())

    def test_iscsi_initiator(self):
        iscsi_initiator = viom_elcm.ISCSIInitiator(
            iqn='iqn-2017-04.com.fujitsu:001',
            ip='192.168.1.11',
            subnet='255.255.255.0',
            gateway='192.168.1.1'
            )
        expected_json = {
            'DHCPUsage': False,
            'Name': 'iqn-2017-04.com.fujitsu:001',
            'IPv4Address': '192.168.1.11',
            'SubnetMask': '255.255.255.0',
            'GatewayIPv4Address': '192.168.1.1',
            'VLANId': 0,
        }
        self.assertEqual(expected_json, iscsi_initiator.get_json())

    def test_iscsi_initiator_vlan(self):
        iscsi_initiator = viom_elcm.ISCSIInitiator(
            iqn='iqn-2017-04.com.fujitsu:001',
            ip='192.168.1.11',
            subnet='255.255.255.0',
            gateway='192.168.1.1',
            vlan_id=123
            )
        expected_json = {
            'DHCPUsage': False,
            'Name': 'iqn-2017-04.com.fujitsu:001',
            'IPv4Address': '192.168.1.11',
            'SubnetMask': '255.255.255.0',
            'GatewayIPv4Address': '192.168.1.1',
            'VLANId': 123,
        }
        self.assertEqual(expected_json, iscsi_initiator.get_json())

    def test_iscsi_initiator_dhcp(self):
        iscsi_initiator = viom_elcm.ISCSIInitiator(
            dhcp_usage=True,
            iqn='iqn-2017-04.com.fujitsu:001',
            ip='192.168.1.11',
            subnet='255.255.255.0',
            )
        expected_json = {
            'DHCPUsage': True,
            'Name': 'iqn-2017-04.com.fujitsu:001',
        }
        self.assertEqual(expected_json, iscsi_initiator.get_json())

    def test_iscsi_target_no_auth(self):
        iscsi_target = viom_elcm.ISCSITarget(
            iqn='iqn-2017-04.com.fujitsu:101',
            ip='192.168.2.22')
        expected_json = {
            'DHCPUsage': False,
            'Name': 'iqn-2017-04.com.fujitsu:101',
            'IPv4Address': '192.168.2.22',
            'PortNumber': 3260,
            'BootLUN': 0,
            'AuthenticationMethod': 'None',
        }
        self.assertEqual(expected_json, iscsi_target.get_json())

    def test_iscsi_target_chap(self):
        iscsi_target = viom_elcm.ISCSITarget(
            iqn='iqn-2017-04.com.fujitsu:101',
            ip='192.168.2.22',
            port=12345,
            lun=3,
            auth_method='CHAP',
            chap_user='chap_user',
            chap_secret='chap_secret')
        expected_json = {
            'DHCPUsage': False,
            'Name': 'iqn-2017-04.com.fujitsu:101',
            'IPv4Address': '192.168.2.22',
            'PortNumber': 12345,
            'BootLUN': 3,
            'AuthenticationMethod': 'CHAP',
            'ChapUserName': 'chap_user',
            'ChapSecret': 'chap_secret',
        }
        self.assertEqual(expected_json, iscsi_target.get_json())

    def test_iscsi_target_mutualchap(self):
        iscsi_target = viom_elcm.ISCSITarget(
            iqn='iqn-2017-04.com.fujitsu:101',
            ip='192.168.2.22',
            auth_method='MutualCHAP',
            chap_user='chap_user',
            chap_secret='chap_secret',
            mutual_chap_secret='chap_secret_second')
        expected_json = {
            'DHCPUsage': False,
            'Name': 'iqn-2017-04.com.fujitsu:101',
            'IPv4Address': '192.168.2.22',
            'PortNumber': 3260,
            'BootLUN': 0,
            'AuthenticationMethod': 'MutualCHAP',
            'ChapUserName': 'chap_user',
            'ChapSecret': 'chap_secret',
            'MutualChapSecret': 'chap_secret_second',
        }
        self.assertEqual(expected_json, iscsi_target.get_json())

    def test_iscsi_target_dhcp(self):
        iscsi_target = viom_elcm.ISCSITarget(
            dhcp_usage=True,
            iqn='iqn-2017-04.com.fujitsu:101',
            ip='192.168.2.22',
            auth_method='CHAP',
            chap_user='chap_user',
            chap_secret='chap_secret')
        expected_json = {
            'DHCPUsage': True,
            'AuthenticationMethod': 'CHAP',
            'ChapUserName': 'chap_user',
            'ChapSecret': 'chap_secret',
        }
        self.assertEqual(expected_json, iscsi_target.get_json())
