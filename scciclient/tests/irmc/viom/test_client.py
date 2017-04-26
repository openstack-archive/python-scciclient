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

import mock
import testtools

from scciclient.irmc import scci
from scciclient.irmc.viom import client as viom_client
from scciclient.irmc.viom import elcm as viom_elcm


class VIOMConfigurationTestCase(testtools.TestCase):

    def setUp(self):
        super(VIOMConfigurationTestCase, self).setUp()

        self.irmc_info = {
            'irmc_address': '10.124.196.159',
            'irmc_username': 'admin',
            'irmc_password': 'admin0',
            'irmc_port': 80,
            'irmc_auth_method': 'basic',
            'irmc_client_timeout': 60,
        }
        self.identification = 'viom_identification'
        self.configurator = viom_client.VIOMConfiguration(
            self.irmc_info, self.identification)

    @mock.patch.object(viom_elcm.ELCMVIOMClient, 'set_profile')
    def _test_terminate(self, mock_set, reboot=None):
        if reboot is None:
            self.configurator.terminate()
            reboot = False
        else:
            self.configurator.terminate(reboot=reboot)
        expected_json = {
            'VIOMManage': {
                'Manage': False,
                'Identification': 'viom_identification',
            },
            'InitBoot': reboot,
            'Mode': 'delete',
        }
        mock_set.assert_called_once_with(expected_json)

    def test_terminate(self):
        self._test_terminate()

    def test_terminate_reboot_true(self):
        self._test_terminate(reboot=True)

    def test_terminate_reboot_false(self):
        self._test_terminate(reboot=False)

    @staticmethod
    def _create_json_for_apply(slot_json, init_boot=False):
        return {
            'UseVirtualAddresses': True,
            'Mode': 'new',
            'InitBoot': init_boot,
            'VIOMManage': {
                'Manage': True,
                'Identification': 'viom_identification'
            },
            'Slots': {
                'Slot': [slot_json]
            }
        }

    @staticmethod
    def _create_json_before_apply(slot_json):
        return {
            'VIOMManage': {
                'Identification': 'viom_identification'
            },
            'Slots': {
                'Slot': [slot_json]
            }
        }

    @staticmethod
    def _create_json_slot_onbaord_lan(lan_port):
        lan_ports = []
        for port_idx in range(1, lan_port['@PortIdx']):
            lan_ports.append(
                {'@PortIdx': port_idx,
                 'BootPriority': 1,
                 'BootProtocol': 'None',
                 'PortEnable': True,
                 'UseVirtualAddresses': False})
        lan_ports.append(lan_port)
        return {
            '@SlotIdx': 0,
            'OnboardControllers': {
                'OnboardController': [
                    {'@OnboardControllerIdx': 1,
                     'LANAdapter': {
                         'Ports': {
                             'Port': lan_ports
                         }
                     }}
                ]
            }
        }

    @staticmethod
    def _create_json_slot_with_cna_lan(card_idx, port_idx, lan_function):
        return {
            '@SlotIdx': 0,
            'AddOnCards': {
                'AddOnCard': [
                    {'@AddOnCardIdx': card_idx,
                     'CNAAdapter': {
                         'Ports': {
                             'Port': [
                                 {'@PortIdx': port_idx,
                                  'PortEnable': True,
                                  'Functions': {
                                      'Function': [
                                          {'@FunctionIdx': 1,
                                           'LANFunction': lan_function},
                                      ]
                                  }}
                             ]
                         }
                     }}
                ]
            }
        }

    @staticmethod
    def _create_json_slot_with_cna_iscsi(card_idx, port_idx, iscsi_function,
                                         lan_function=None):
        if not lan_function:
            lan_function = {
                'FunctionEnable': False,
                'BootProtocol': 'None',
                'BootPriority': 1,
            }
        return {
            '@SlotIdx': 0,
            'AddOnCards': {
                'AddOnCard': [
                    {'@AddOnCardIdx': card_idx,
                     'CNAAdapter': {
                         'Ports': {
                             'Port': [
                                 {'@PortIdx': port_idx,
                                  'PortEnable': True,
                                  'Functions': {
                                      'Function': [
                                          {'@FunctionIdx': 1,
                                           'LANFunction': lan_function},
                                          {'@FunctionIdx': 3,
                                           'ISCSIFunction': iscsi_function}
                                      ]
                                  }}
                             ]
                         }
                     }}
                ]
            }
        }

    @staticmethod
    def _create_json_slot_with_fc(card_idx, fc_port):
        return {
            '@SlotIdx': 0,
            'AddOnCards': {
                'AddOnCard': [
                    {'@AddOnCardIdx': card_idx,
                     'FCAdapter': {
                         'Ports': {
                             'Port': [
                                 fc_port
                             ]
                         }
                     }}
                ]
            }
        }

    @staticmethod
    def _create_json_slot_with_cna_fcoe(card_idx, port_idx, fcoe_function,
                                        lan_function=None):
        if not lan_function:
            lan_function = {
                'FunctionEnable': False,
                'BootProtocol': 'None',
                'BootPriority': 1,
            }
        return {
            '@SlotIdx': 0,
            'AddOnCards': {
                'AddOnCard': [
                    {'@AddOnCardIdx': card_idx,
                     'CNAAdapter': {
                         'Ports': {
                             'Port': [
                                 {'@PortIdx': port_idx,
                                  'PortEnable': True,
                                  'Functions': {
                                      'Function': [
                                          {'@FunctionIdx': 1,
                                           'LANFunction': lan_function},
                                          {'@FunctionIdx': 2,
                                           'FCoEFunction': fcoe_function}
                                      ]
                                  }}
                             ]
                         }
                     }}
                ]
            }
        }

    @mock.patch.object(viom_elcm.ELCMVIOMClient, 'set_profile')
    def test_set_lan_port_to_onboard(self, mock_set):
        self.configurator.set_lan_port('LAN0-1')
        port = {
            '@PortIdx': 1,
            'PortEnable': True,
            'BootProtocol': 'None',
            'BootPriority': 1,
            'UseVirtualAddresses': False,
        }
        slot = VIOMConfigurationTestCase._create_json_slot_onbaord_lan(port)
        self.assertEqual(
            VIOMConfigurationTestCase._create_json_before_apply(slot),
            self.configurator.dump_json())
        self.configurator.apply()
        mock_set.assert_called_once_with(
            VIOMConfigurationTestCase._create_json_for_apply(slot))

    @mock.patch.object(viom_elcm.ELCMVIOMClient, 'set_profile')
    def test_set_lan_port_to_onboard_with_virtual_mac(self, mock_set):
        self.configurator.set_lan_port('LAN0-9', mac='aa:bb:cc:dd:ee')
        port = {
            '@PortIdx': 9,
            'PortEnable': True,
            'BootProtocol': 'None',
            'BootPriority': 1,
            'UseVirtualAddresses': True,
            'VirtualAddress': {
                'MAC': 'aa:bb:cc:dd:ee'
            }
        }
        slot = VIOMConfigurationTestCase._create_json_slot_onbaord_lan(port)
        self.assertEqual(
            VIOMConfigurationTestCase._create_json_before_apply(slot),
            self.configurator.dump_json())
        self.configurator.apply(reboot=True)
        mock_set.assert_called_once_with(
            VIOMConfigurationTestCase._create_json_for_apply(slot,
                                                             init_boot=True))

    @mock.patch.object(viom_elcm.ELCMVIOMClient, 'set_profile')
    def test_set_lan_port_to_cna(self, mock_set):
        self.configurator.set_lan_port('CNA5-6')
        function = {
            'FunctionEnable': True,
            'BootProtocol': 'None',
            'BootPriority': 1,
            'UseVirtualAddresses': False,
        }
        slot = VIOMConfigurationTestCase._create_json_slot_with_cna_lan(
            5, 6, function)
        self.assertEqual(
            VIOMConfigurationTestCase._create_json_before_apply(slot),
            self.configurator.dump_json())
        self.configurator.apply()
        mock_set.assert_called_once_with(
            VIOMConfigurationTestCase._create_json_for_apply(slot))

    @mock.patch.object(viom_elcm.ELCMVIOMClient, 'set_profile')
    def test_set_lan_port_to_cna_with_virtual_mac(self, mock_set):
        self.configurator.set_lan_port('CNA9-1', mac='12:34:56:78:90')
        function = {
            'FunctionEnable': True,
            'BootProtocol': 'None',
            'BootPriority': 1,
            'UseVirtualAddresses': True,
            'VirtualAddress': {
                'MAC': '12:34:56:78:90'
            }
        }
        slot = VIOMConfigurationTestCase._create_json_slot_with_cna_lan(
            9, 1, function)
        self.assertEqual(
            VIOMConfigurationTestCase._create_json_before_apply(slot),
            self.configurator.dump_json())
        self.configurator.apply()
        mock_set.assert_called_once_with(
            VIOMConfigurationTestCase._create_json_for_apply(slot))

    @mock.patch.object(viom_elcm.ELCMVIOMClient, 'set_profile')
    def test_set_iscsi_volume_to_onboard_lan(self, mock_set):
        self.configurator.set_iscsi_volume(
            'LAN0-9',
            'iqn-2017-04.com.fujitsu:01',
            initiator_ip='192.168.11.11',
            initiator_netmask=24,
            target_iqn='iqn-2017-04.com.fujitsu:11',
            target_ip='192.168.22.22')
        port = {
            '@PortIdx': 9,
            'PortEnable': True,
            'BootProtocol': 'ISCSI',
            'BootPriority': 1,
            'ISCSIBootEnvironment': {
                'ISCSIInitiator': {
                    'DHCPUsage': False,
                    'Name': 'iqn-2017-04.com.fujitsu:01',
                    'IPv4Address': '192.168.11.11',
                    'SubnetMask': '255.255.255.0',
                    'VLANId': 0,
                },
                'ISCSITarget': {
                    'DHCPUsage': False,
                    'Name': 'iqn-2017-04.com.fujitsu:11',
                    'IPv4Address': '192.168.22.22',
                    'PortNumber': 3260,
                    'BootLUN': 0,
                    'AuthenticationMethod': 'None'
                }
            }
        }
        slot = VIOMConfigurationTestCase._create_json_slot_onbaord_lan(port)
        self.assertEqual(
            VIOMConfigurationTestCase._create_json_before_apply(slot),
            self.configurator.dump_json())
        self.configurator.apply()
        mock_set.assert_called_once_with(
            VIOMConfigurationTestCase._create_json_for_apply(slot))

    @mock.patch.object(viom_elcm.ELCMVIOMClient, 'set_profile')
    def test_set_iscsi_volume_to_cna_card(self, mock_set):
        self.configurator.set_iscsi_volume(
            'CNA1-2',
            'iqn-2017-04.com.fujitsu:01',
            initiator_ip='192.168.11.11',
            initiator_netmask=16,
            target_iqn='iqn-2017-04.com.fujitsu:11',
            target_ip='192.168.22.22')
        iscsi_function = {
            'FunctionEnable': True,
            'BootProtocol': 'ISCSI',
            'BootPriority': 1,
            'ISCSIBootEnvironment': {
                'ISCSIInitiator': {
                    'DHCPUsage': False,
                    'Name': 'iqn-2017-04.com.fujitsu:01',
                    'IPv4Address': '192.168.11.11',
                    'SubnetMask': '255.255.0.0',
                    'VLANId': 0,
                },
                'ISCSITarget': {
                    'DHCPUsage': False,
                    'Name': 'iqn-2017-04.com.fujitsu:11',
                    'IPv4Address': '192.168.22.22',
                    'PortNumber': 3260,
                    'BootLUN': 0,
                    'AuthenticationMethod': 'None'
                }
            }
        }
        slot = VIOMConfigurationTestCase._create_json_slot_with_cna_iscsi(
            1, 2, iscsi_function)
        self.assertEqual(
            VIOMConfigurationTestCase._create_json_before_apply(slot),
            self.configurator.dump_json())
        self.configurator.apply()
        mock_set.assert_called_once_with(
            VIOMConfigurationTestCase._create_json_for_apply(slot))

    @mock.patch.object(viom_elcm.ELCMVIOMClient, 'set_profile')
    def test_set_iscsi_volume_to_cna_card_chap(self, mock_set):
        self.configurator.set_iscsi_volume(
            'CNA9-9',
            'iqn-2017-04.com.fujitsu:01',
            initiator_ip='192.168.11.11',
            initiator_netmask=30,
            target_iqn='iqn-2017-04.com.fujitsu:11',
            target_ip='192.168.22.22',
            chap_user='chap-user',
            chap_secret='chap-secret')
        iscsi_function = {
            'FunctionEnable': True,
            'BootProtocol': 'ISCSI',
            'BootPriority': 1,
            'ISCSIBootEnvironment': {
                'ISCSIInitiator': {
                    'DHCPUsage': False,
                    'Name': 'iqn-2017-04.com.fujitsu:01',
                    'IPv4Address': '192.168.11.11',
                    'SubnetMask': '255.255.255.252',
                    'VLANId': 0,
                },
                'ISCSITarget': {
                    'DHCPUsage': False,
                    'Name': 'iqn-2017-04.com.fujitsu:11',
                    'IPv4Address': '192.168.22.22',
                    'PortNumber': 3260,
                    'BootLUN': 0,
                    'AuthenticationMethod': 'CHAP',
                    'ChapUserName': 'chap-user',
                    'ChapSecret': 'chap-secret'
                }
            }
        }
        slot = VIOMConfigurationTestCase._create_json_slot_with_cna_iscsi(
            9, 9, iscsi_function)
        self.assertEqual(
            VIOMConfigurationTestCase._create_json_before_apply(slot),
            self.configurator.dump_json())
        self.configurator.apply()
        mock_set.assert_called_once_with(
            VIOMConfigurationTestCase._create_json_for_apply(slot))

    @mock.patch.object(viom_elcm.ELCMVIOMClient, 'set_profile')
    def test_set_iscsi_volume_to_cna_card_mutual_chap(self, mock_set):
        self.configurator.set_iscsi_volume(
            'CNA2-1',
            'iqn-2017-04.com.fujitsu:01',
            initiator_ip='192.168.11.11',
            initiator_netmask=8,
            target_iqn='iqn-2017-04.com.fujitsu:11',
            target_ip='192.168.22.22',
            boot_prio=2,
            target_lun=3,
            chap_user='chap-user',
            chap_secret='chap-secret',
            mutual_chap_secret='mutual-secret')
        iscsi_function = {
            'FunctionEnable': True,
            'BootProtocol': 'ISCSI',
            'BootPriority': 2,
            'ISCSIBootEnvironment': {
                'ISCSIInitiator': {
                    'DHCPUsage': False,
                    'Name': 'iqn-2017-04.com.fujitsu:01',
                    'IPv4Address': '192.168.11.11',
                    'SubnetMask': '255.0.0.0',
                    'VLANId': 0,
                },
                'ISCSITarget': {
                    'DHCPUsage': False,
                    'Name': 'iqn-2017-04.com.fujitsu:11',
                    'IPv4Address': '192.168.22.22',
                    'PortNumber': 3260,
                    'BootLUN': 3,
                    'AuthenticationMethod': 'MutualCHAP',
                    'ChapUserName': 'chap-user',
                    'ChapSecret': 'chap-secret',
                    'MutualChapSecret': 'mutual-secret',
                }
            }
        }
        slot = VIOMConfigurationTestCase._create_json_slot_with_cna_iscsi(
            2, 1, iscsi_function)
        self.assertEqual(
            VIOMConfigurationTestCase._create_json_before_apply(slot),
            self.configurator.dump_json())
        self.configurator.apply()
        mock_set.assert_called_once_with(
            VIOMConfigurationTestCase._create_json_for_apply(slot))

    @mock.patch.object(viom_elcm.ELCMVIOMClient, 'set_profile')
    def test_set_iscsi_volume_to_cna_card_initiator_dhcp(self, mock_set):
        self.configurator.set_iscsi_volume(
            'CNA1-2',
            'iqn-2017-04.com.fujitsu:01',
            initiator_dhcp=True,
            target_iqn='iqn-2017-04.com.fujitsu:11',
            target_ip='192.168.22.22')
        iscsi_function = {
            'FunctionEnable': True,
            'BootProtocol': 'ISCSI',
            'BootPriority': 1,
            'ISCSIBootEnvironment': {
                'ISCSIInitiator': {
                    'DHCPUsage': True,
                    'Name': 'iqn-2017-04.com.fujitsu:01',
                },
                'ISCSITarget': {
                    'DHCPUsage': False,
                    'Name': 'iqn-2017-04.com.fujitsu:11',
                    'IPv4Address': '192.168.22.22',
                    'PortNumber': 3260,
                    'BootLUN': 0,
                    'AuthenticationMethod': 'None'
                }
            }
        }
        slot = VIOMConfigurationTestCase._create_json_slot_with_cna_iscsi(
            1, 2, iscsi_function)
        self.assertEqual(
            VIOMConfigurationTestCase._create_json_before_apply(slot),
            self.configurator.dump_json())
        self.configurator.apply()
        mock_set.assert_called_once_with(
            VIOMConfigurationTestCase._create_json_for_apply(slot))

    @mock.patch.object(viom_elcm.ELCMVIOMClient, 'set_profile')
    def test_set_iscsi_volume_to_cna_card_target_dhcp(self, mock_set):
        self.configurator.set_iscsi_volume(
            'CNA1-2',
            'iqn-2017-04.com.fujitsu:01',
            initiator_ip='192.168.11.11',
            initiator_netmask=16,
            target_dhcp=True)
        iscsi_function = {
            'FunctionEnable': True,
            'BootProtocol': 'ISCSI',
            'BootPriority': 1,
            'ISCSIBootEnvironment': {
                'ISCSIInitiator': {
                    'DHCPUsage': False,
                    'Name': 'iqn-2017-04.com.fujitsu:01',
                    'IPv4Address': '192.168.11.11',
                    'SubnetMask': '255.255.0.0',
                    'VLANId': 0,
                },
                'ISCSITarget': {
                    'DHCPUsage': True,
                    'AuthenticationMethod': 'None'
                }
            }
        }
        slot = VIOMConfigurationTestCase._create_json_slot_with_cna_iscsi(
            1, 2, iscsi_function)
        self.assertEqual(
            VIOMConfigurationTestCase._create_json_before_apply(slot),
            self.configurator.dump_json())
        self.configurator.apply()
        mock_set.assert_called_once_with(
            VIOMConfigurationTestCase._create_json_for_apply(slot))

    @mock.patch.object(viom_elcm.ELCMVIOMClient, 'set_profile')
    def test_set_lan_and_iscsi_volume_to_cna_card(self, mock_set):
        self.configurator.set_lan_port('CNA1-2')
        self.configurator.set_iscsi_volume(
            'CNA1-2',
            'iqn-2017-04.com.fujitsu:01',
            initiator_ip='192.168.11.11',
            initiator_netmask=1,
            target_iqn='iqn-2017-04.com.fujitsu:11',
            target_ip='192.168.22.22')
        lan_function = {
            'FunctionEnable': True,
            'BootProtocol': 'None',
            'BootPriority': 1,
            'UseVirtualAddresses': False,
        }
        iscsi_function = {
            'FunctionEnable': True,
            'BootProtocol': 'ISCSI',
            'BootPriority': 1,
            'ISCSIBootEnvironment': {
                'ISCSIInitiator': {
                    'DHCPUsage': False,
                    'Name': 'iqn-2017-04.com.fujitsu:01',
                    'IPv4Address': '192.168.11.11',
                    'SubnetMask': '128.0.0.0',
                    'VLANId': 0,
                },
                'ISCSITarget': {
                    'DHCPUsage': False,
                    'Name': 'iqn-2017-04.com.fujitsu:11',
                    'IPv4Address': '192.168.22.22',
                    'PortNumber': 3260,
                    'BootLUN': 0,
                    'AuthenticationMethod': 'None'
                }
            }
        }
        slot = VIOMConfigurationTestCase._create_json_slot_with_cna_iscsi(
            1, 2, iscsi_function, lan_function=lan_function)
        self.assertEqual(
            VIOMConfigurationTestCase._create_json_before_apply(slot),
            self.configurator.dump_json())
        self.configurator.apply()
        mock_set.assert_called_once_with(
            VIOMConfigurationTestCase._create_json_for_apply(slot))

    @mock.patch.object(viom_elcm.ELCMVIOMClient, 'set_profile')
    def test_set_fc_volume_to_fc_card(self, mock_set):
        self.configurator.set_fc_volume('FC1-1', '11:22:33:44:55')
        port = {
            '@PortIdx': 1,
            'UseVirtualAddresses': False,
            'PortEnable': True,
            'BootProtocol': 'FC',
            'BootPriority': 1,
            'FCBootEnvironment': {
                'FCTargets': {
                    'FCTarget': [
                        {'@FCTargetIdx': 1,
                         'TargetWWPN': '11:22:33:44:55',
                         'TargetLUN': 0}
                    ]
                },
                'FCLinkSpeed': 'auto',
                'FCTopology': 'auto_loop',
                'SANBootEnable': True,
            }
        }
        slot = VIOMConfigurationTestCase._create_json_slot_with_fc(1, port)
        self.assertEqual(
            VIOMConfigurationTestCase._create_json_before_apply(slot),
            self.configurator.dump_json())
        self.configurator.apply()
        mock_set.assert_called_once_with(
            VIOMConfigurationTestCase._create_json_for_apply(slot))

    @mock.patch.object(viom_elcm.ELCMVIOMClient, 'set_profile')
    def test_set_fc_volume_to_fc_card_with_virtual_wwn(self, mock_set):
        self.configurator.set_fc_volume('FC2-1', '11:22:33:44:55',
                                        boot_prio=3, target_lun=2,
                                        initiator_wwnn='aa:bb:cc:dd:ee',
                                        initiator_wwpn='12:34:56:78:90')
        port = {
            '@PortIdx': 1,
            'UseVirtualAddresses': True,
            'VirtualAddress': {
                'WWNN': 'aa:bb:cc:dd:ee',
                'WWPN': '12:34:56:78:90'
            },
            'PortEnable': True,
            'BootProtocol': 'FC',
            'BootPriority': 3,
            'FCBootEnvironment': {
                'FCTargets': {
                    'FCTarget': [
                        {'@FCTargetIdx': 1,
                         'TargetWWPN': '11:22:33:44:55',
                         'TargetLUN': 2}
                    ]
                },
                'FCLinkSpeed': 'auto',
                'FCTopology': 'auto_loop',
                'SANBootEnable': True,
            }
        }
        slot = VIOMConfigurationTestCase._create_json_slot_with_fc(2, port)
        self.assertEqual(
            VIOMConfigurationTestCase._create_json_before_apply(slot),
            self.configurator.dump_json())
        self.configurator.apply()
        mock_set.assert_called_once_with(
            VIOMConfigurationTestCase._create_json_for_apply(slot))

    @mock.patch.object(viom_elcm.ELCMVIOMClient, 'set_profile')
    def test_set_fc_volume_to_cna_card(self, mock_set):
        self.configurator.set_fc_volume('CNA2-1', '11:22:33:44:55')
        fcoe_function = {
            'UseVirtualAddresses': False,
            'FunctionEnable': True,
            'BootProtocol': 'FC',
            'BootPriority': 1,
            'FCBootEnvironment': {
                'FCTargets': {
                    'FCTarget': [
                        {'@FCTargetIdx': 1,
                         'TargetWWPN': '11:22:33:44:55',
                         'TargetLUN': 0}
                    ]
                },
                'FCLinkSpeed': 'auto',
                'FCTopology': 'auto_loop',
                'SANBootEnable': True,
            }
        }
        slot = VIOMConfigurationTestCase._create_json_slot_with_cna_fcoe(
            2, 1, fcoe_function)
        self.assertEqual(
            VIOMConfigurationTestCase._create_json_before_apply(slot),
            self.configurator.dump_json())
        self.configurator.apply()
        mock_set.assert_called_once_with(
            VIOMConfigurationTestCase._create_json_for_apply(slot))

    @mock.patch.object(viom_elcm.ELCMVIOMClient, 'set_profile')
    def test_set_fc_volume_to_cna_card_with_virtual_wwn(self, mock_set):
        self.configurator.set_fc_volume('CNA9-9', '11:22:33:44:55',
                                        boot_prio=2, target_lun=3,
                                        initiator_wwnn='aa:bb:cc:dd:ee',
                                        initiator_wwpn='12:34:56:78:90')
        fcoe_function = {
            'UseVirtualAddresses': True,
            'VirtualAddress': {
                'WWNN': 'aa:bb:cc:dd:ee',
                'WWPN': '12:34:56:78:90'
            },
            'FunctionEnable': True,
            'BootProtocol': 'FC',
            'BootPriority': 2,
            'FCBootEnvironment': {
                'FCTargets': {
                    'FCTarget': [
                        {'@FCTargetIdx': 1,
                         'TargetWWPN': '11:22:33:44:55',
                         'TargetLUN': 3}
                    ]
                },
                'FCLinkSpeed': 'auto',
                'FCTopology': 'auto_loop',
                'SANBootEnable': True,
            }
        }
        slot = VIOMConfigurationTestCase._create_json_slot_with_cna_fcoe(
            9, 9, fcoe_function)
        self.assertEqual(
            VIOMConfigurationTestCase._create_json_before_apply(slot),
            self.configurator.dump_json())
        self.configurator.apply()
        mock_set.assert_called_once_with(
            VIOMConfigurationTestCase._create_json_for_apply(slot))

    @mock.patch.object(viom_elcm.ELCMVIOMClient, 'set_profile')
    def test_set_lan_and_fc_volume_to_cna_card(self, mock_set):
        self.configurator.set_lan_port('CNA2-1')
        self.configurator.set_fc_volume('CNA2-1', '11:22:33:44:55')
        lan_function = {
            'FunctionEnable': True,
            'BootProtocol': 'None',
            'BootPriority': 1,
            'UseVirtualAddresses': False,
        }
        fcoe_function = {
            'UseVirtualAddresses': False,
            'FunctionEnable': True,
            'BootProtocol': 'FC',
            'BootPriority': 1,
            'FCBootEnvironment': {
                'FCTargets': {
                    'FCTarget': [
                        {'@FCTargetIdx': 1,
                         'TargetWWPN': '11:22:33:44:55',
                         'TargetLUN': 0}
                    ]
                },
                'FCLinkSpeed': 'auto',
                'FCTopology': 'auto_loop',
                'SANBootEnable': True,
            }
        }
        slot = VIOMConfigurationTestCase._create_json_slot_with_cna_fcoe(
            2, 1, fcoe_function, lan_function=lan_function)
        self.assertEqual(
            VIOMConfigurationTestCase._create_json_before_apply(slot),
            self.configurator.dump_json())
        self.configurator.apply()
        mock_set.assert_called_once_with(
            VIOMConfigurationTestCase._create_json_for_apply(slot))

    def test_set_lan_port_to_onboard_overwrite(self):
        self.configurator.set_lan_port('LAN0-9')
        self.test_set_lan_port_to_onboard_with_virtual_mac()

    def test_set_lan_port_to_cna_overwrite(self):
        self.configurator.set_lan_port('CNA5-6', mac='12:34:56:78:90')
        self.test_set_lan_port_to_cna()

    def test_set_iscsi_volume_to_onboard_lan_overwrite(self):
        self.configurator.set_iscsi_volume(
            'LAN0-9',
            'iqn-initiator',
            initiator_ip='192.168.99.99',
            initiator_netmask=32,
            target_iqn='iqn-target',
            target_ip='192.168.88.88')
        self.test_set_iscsi_volume_to_onboard_lan()

    def test_set_iscsi_volume_to_cna_card_overwrite(self):
        self.configurator.set_iscsi_volume(
            'CNA1-2',
            'iqn-initiator',
            initiator_ip='192.168.99.99',
            initiator_netmask=16,
            target_iqn='iqn-target',
            target_ip='192.168.88.88')
        self.test_set_iscsi_volume_to_cna_card()

    def test_set_fc_volume_to_fc_card_overwrite(self):
        self.configurator.set_fc_volume('FC2-1', '11:22:33:44:55')
        self.test_set_fc_volume_to_fc_card_with_virtual_wwn()

    def test_set_fc_volume_to_cna_card_overwrite(self):
        self.configurator.set_fc_volume('CNA2-1', '11:22:33:44:55',
                                        boot_prio=2, target_lun=3,
                                        initiator_wwnn='aa:bb:cc:dd:ee',
                                        initiator_wwpn='12:34:56:78:90')
        self.test_set_fc_volume_to_cna_card()


class PhysicalPortIDParseTestCase(testtools.TestCase):

    def _validate_handler(self, handler, handler_class, slot_type, card_type,
                          slot_idx, card_idx, port_idx):
        self.assertTrue(isinstance(handler, handler_class))
        self.assertEqual(slot_type, handler.slot_type)
        self.assertEqual(card_type, handler.card_type)
        self.assertEqual(slot_idx, handler.slot_idx)
        self.assertEqual(card_idx, handler.card_idx)
        self.assertEqual(port_idx, handler.port_idx)

    def test_lan_onboard(self):
        handler = viom_client._parse_physical_port_id('LAN0-1')
        self._validate_handler(handler, viom_client._LANPortHandler,
                               viom_client.ONBOARD, viom_client.LAN,
                               0, 1, 1)

    def test_lan_onboard_lower(self):
        handler = viom_client._parse_physical_port_id('lan0-2')
        self._validate_handler(handler, viom_client._LANPortHandler,
                               viom_client.ONBOARD, viom_client.LAN,
                               0, 1, 2)

    def test_lan_onboard_cammel(self):
        handler = viom_client._parse_physical_port_id('Lan0-9')
        self._validate_handler(handler, viom_client._LANPortHandler,
                               viom_client.ONBOARD, viom_client.LAN,
                               0, 1, 9)

    def test_lan_addon(self):
        handler = viom_client._parse_physical_port_id('LAN1-3')
        self._validate_handler(handler, viom_client._LANPortHandler,
                               viom_client.ADDON, viom_client.LAN,
                               0, 1, 3)

    def test_fc_addon(self):
        handler = viom_client._parse_physical_port_id('FC2-5')
        self._validate_handler(handler, viom_client._FCPortHandler,
                               viom_client.ADDON, viom_client.FC,
                               0, 2, 5)

    def test_cna_addon(self):
        handler = viom_client._parse_physical_port_id('CNA9-2')
        self._validate_handler(handler, viom_client._CNAPortHandler,
                               viom_client.ADDON, viom_client.CNA,
                               0, 9, 2)

    def test_unkown_card(self):
        self.assertRaises(scci.SCCIInvalidInputError,
                          viom_client._parse_physical_port_id, 'HCA1-1')

    def test_slot_out_of_range(self):
        self.assertRaises(scci.SCCIInvalidInputError,
                          viom_client._parse_physical_port_id, 'CNA10-9')

    def test_port_out_of_range_min(self):
        self.assertRaises(scci.SCCIInvalidInputError,
                          viom_client._parse_physical_port_id, 'FC0-0')

    def test_port_out_of_range_max(self):
        self.assertRaises(scci.SCCIInvalidInputError,
                          viom_client._parse_physical_port_id, 'FC9-10')

    def test_public_validation(self):
        self.assertIsNone(viom_client.validate_physical_port_id('LAN0-2'))

    def test_public_validation_error(self):
        self.assertRaises(scci.SCCIInvalidInputError,
                          viom_client.validate_physical_port_id, 'CNA1-0')


class ConvertNetMaskTestCase(testtools.TestCase):
    def test_convert_zero(self):
        self.assertEqual('0.0.0.0',
                         viom_client._convert_netmask(0))

    def test_convert_max(self):
        self.assertEqual('255.255.255.255',
                         viom_client._convert_netmask(32))

    def test_convert_nagative(self):
        self.assertRaises(scci.SCCIInvalidInputError,
                          viom_client._convert_netmask, -1)

    def test_convert_too_large(self):
        self.assertRaises(scci.SCCIInvalidInputError,
                          viom_client._convert_netmask, 33)
