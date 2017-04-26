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

import abc
import json
import time

import six

from scciclient.irmc import elcm
from scciclient.irmc import scci


PROFILE_NAME = 'AdapterConfigIrmc'
PARAM_PATH = 'Server/AdapterConfigIrmc'


class ELCMVIOMClient(object):
    """Client calling eLCM REST APIs for VIOM feature"""

    def __init__(self, irmc_info):
        self.irmc_info = irmc_info

    def _wait_session(self, session_id, timeout=1800):
        session_expiration = time.time() + timeout

        while True:
            resp = elcm.elcm_session_get_status(self.irmc_info, session_id)

            status = resp['Session']['Status']
            if status == 'running' or status == 'activated':
                # Sleep a bit
                time.sleep(5)
            elif status == 'terminated regularly':
                return {}
            else:
                # Error occurred, get session log to see what happened
                try:
                    session_log = elcm.elcm_session_get_log(
                        irmc_info=self.irmc_info, session_id=session_id)
                except scci.SCCIClientError as e:
                    raise scci.SCCIClientError(
                        ('Operation Failed. Session %(session_id)s state is '
                         '%(session_state)s. Session log collection failed: '
                         '%(reason)s' %
                         {'session_id': session_id,
                          'session_state': resp['Session']['Status'],
                          'reason': e}))

                raise scci.SCCIClientError(
                    ('Operation failed. Session %(session_id)s state is '
                     '%(session_state)s. Session log is: "%(session_log)s".' %
                     {'session_id': session_id,
                      'session_state': resp['Session']['Status'],
                      'session_log': json.dumps(session_log)}))

            # Check for timeout
            if time.time() > session_expiration:
                # Timeout occurred, get session log to see what happened
                try:
                    session_log = elcm.elcm_session_get_log(
                        irmc_info=self.irmc_info, session_id=session_id)
                except scci.SCCIClientError as e:
                    raise elcm.ELCMSessionTimeout(
                        'Operation timed out. Session %(session_id)s has not '
                        'finished in %(timeout)d seconds. Session log '
                        'collection failed: %(reason)s' %
                        {'session_id': session_id,
                         'timeout': timeout,
                         'reason': e})

                raise elcm.ELCMSessionTimeout(
                    'Operation timed out. Session %(session_id)s has not '
                    'finished in %(timeout)d seconds. Session log is: '
                    '"%(session_log)s.' %
                    {'session_id': session_id,
                     'timeout': timeout,
                     'session_log': json.dumps(session_log)})

    def set_profile(self, adapter_config):
        _adapter_config = dict(adapter_config)
        _adapter_config.update({'@Processing': 'execute'})
        req = {'Server': {'AdapterConfigIrmc': _adapter_config}}
        resp = elcm.elcm_profile_set(self.irmc_info, req)
        self._wait_session(resp['Session']['Id'])

    def get_profile(self):

        # delete old one
        try:
            elcm.elcm_profile_delete(self.irmc_info, PROFILE_NAME)
        except elcm.ELCMProfileNotFound:
            pass

        resp = elcm.elcm_profile_create(self.irmc_info, PARAM_PATH)
        self._wait_session(resp['Session']['Id'])
        resp = elcm.elcm_profile_get(self.irmc_info, PROFILE_NAME)
        return resp


class VIOMAttribute(object):
    """Attribute in VIOM Element.

    This class is used for conversion between Python class and JSON table.
    """
    def __init__(self, name, key, init=None):
        self.name = name
        self.key = key
        self.init = init


@six.add_metaclass(abc.ABCMeta)
class VIOMElement(object):
    """Element in VIOM table."""
    def __init__(self, **kwargs):
        for attr in self.__class__._BASIC_ATTRIBUTES:
            setattr(self, attr.name, kwargs.get(attr.name, attr.init))

    def get_basic_json(self):
        table = {}
        for attr in self.__class__._BASIC_ATTRIBUTES:
            value = getattr(self, attr.name)
            if value is not None:
                table[attr.key] = value
        return table


class VIOMTable(VIOMElement):
    """Root class of VIOM table"""
    _BASIC_ATTRIBUTES = [
        VIOMAttribute('use_virtual_addresses', 'UseVirtualAddresses'),
        VIOMAttribute('viom_boot_enable', 'VIOMBootEnable'),
        VIOMAttribute('boot_menu_enable', 'BootMenuEnable'),
        VIOMAttribute('sriov', 'SRIOV'),
        VIOMAttribute('smux', 'Smux'),
        VIOMAttribute('boot_mode', 'BootMode'),
        VIOMAttribute('init_boot', 'InitBoot'),
        VIOMAttribute('processing', '@Processing'),
        VIOMAttribute('mode', 'Mode')
    ]

    def __init__(self, **kwargs):
        super(VIOMTable, self).__init__(**kwargs)
        self.slots = {}
        self.manage = None

    def get_slot(self, slot_idx, create=True):
        slot = self.slots.get(slot_idx)
        if slot or not create:
            return slot
        slot = Slot(slot_idx)
        self.slots[slot_idx] = slot
        return slot

    def set_manage_table(self, manage):
        self.manage = manage

    def get_json(self):
        """Create JSON data for AdapterConfig.

        :returns: JSON data as follows:

            {
                "VIOMManage":{
                },
                "InitBoot":{
                },
                "UseVirtualAddresses":{
                },
                "BootMenuEnable":{
                },
                "SmuxSetting":{
                },
                "Slots":{
                }
            }
        """
        viom_table = self.get_basic_json()
        if self.slots:
            viom_table['Slots'] = {
                'Slot': [s.get_json() for s in self.slots.values()]
            }
        if self.manage:
            viom_table['VIOMManage'] = self.manage.get_json()
        return viom_table


class ManageTable(VIOMElement):
    """Class for ViomManage element."""

    _BASIC_ATTRIBUTES = [
        VIOMAttribute('manage', 'Manage'),
        VIOMAttribute('identification', 'Identification'),
        VIOMAttribute('trap_destination', 'TrapDestination'),
        VIOMAttribute('force', 'Force'),
        VIOMAttribute('preferred_version', 'PreferredInventoryVersion')
    ]

    def __init__(self, **kwargs):
        super(ManageTable, self).__init__(**kwargs)

    def get_json(self):
        """Create JSON data for ViomManage.

        :returns: JSON data for ViomManage as follows:

            {
                "Manage":{
                },
                "Force":{
                },
                "Identification":{
                },
                "TrapDestination":{
                },
                "PreferredInventoryVersion":{
                }
            }
        """
        return self.get_basic_json()


class Slot(VIOMElement):
    """Class for Slot element."""

    _BASIC_ATTRIBUTES = [
        VIOMAttribute('slot_idx', '@SlotIdx', 0),
    ]

    def __init__(self, slot_idx, **kwargs):
        super(Slot, self).__init__(slot_idx=slot_idx, **kwargs)
        self.onboard_cards = {}
        self.addon_cards = {}

    def add_card(self, card):
        if isinstance(card, OnboardCard):
            self.onboard_cards[card.card_idx] = card
        else:
            self.addon_cards[card.card_idx] = card

    def get_onboard_card(self, card_idx):
        return self.onboard_cards.get(card_idx)

    def get_addon_card(self, card_idx):
        return self.addon_cards.get(card_idx)

    def get_json(self):
        """Create JSON data for slot.

        :returns: JSON data for slot as follows:

            {
                "@SlotIdx":0,
                "OnboardControllers":{
                    "OnboardController": [
                    ]
                },
                "AddOnCards":{
                    "AddOnCard": [
                    ]
                }
            }
        """
        json = self.get_basic_json()
        if self.onboard_cards:
            json['OnboardControllers'] = {
                'OnboardController':
                    [c.get_json() for c in self.onboard_cards.values()]
            }
        if self.addon_cards:
            json['AddOnCards'] = {
                'AddOnCard': [c.get_json() for c in self.addon_cards.values()]
            }
        return json


@six.add_metaclass(abc.ABCMeta)
class PCICard(object):
    "Abstract class for PCI cards."
    def __init__(self, card_idx, adapter):
        self.card_idx = card_idx
        self.adapter = adapter

    def add_port(self, port):
        self.adapter.add_port(port)

    def get_port(self, port_idx):
        return self.adapter.get_port(port_idx)

    def get_json(self):
        """Create JSON data for PCI card element.

        :returns: JSON data for PCI card.
        Data for onboard card is as follows:

            {
                "@OnboardControllerIdx":1,
                "LANAdapter":{
                },
                "CNAAdapter":{
                }
            }

        Data for add-on card is as follows:

            {
                "@AddOnCardIdx":1,
                "LANAdapter":{
                },
                "FCAdapter":{
                },
                "CNAAdapter":{
                }
            }
        """
        json = {self.INDEX_KEY: self.card_idx}
        json.update(self.adapter.get_json())
        return json


class OnboardCard(PCICard):
    """Class for onboard Card."""
    INDEX_KEY = '@OnboardControllerIdx'


class AddOnCard(PCICard):
    """Class for add on card."""
    INDEX_KEY = '@AddOnCardIdx'


@six.add_metaclass(abc.ABCMeta)
class Adapter(object):
    """Abstract class for adapters.

    Adapter represents type of PCI card.
    """

    def __init__(self):
        self.ports = {}

    def add_port(self, port):
        self.ports[port.port_idx] = port

    def get_port(self, port_idx):
        return self.ports.get(port_idx)

    def get_json(self):
        """Create JSON data for adapter

        :returns: JSON data for adapter as follows:

            {
                "LANAdapter":{
                    "Ports":{
                        "Port": [
                        ]
                    }
                }
            }
        """
        return {
            self.ADAPTER_NAME: {
                'Ports': {
                    'Port': [p.get_json() for p in self.ports.values()]
                }
            }
        }


class LANAdapter(Adapter):
    """LAN adapter."""
    ADAPTER_NAME = 'LANAdapter'


class FCAdapter(Adapter):
    """FC adapter."""
    ADAPTER_NAME = 'FCAdapter'


class CNAAdapter(Adapter):
    """CNA adatper."""
    ADAPTER_NAME = 'CNAAdapter'


@six.add_metaclass(abc.ABCMeta)
class AdapterPort(VIOMElement):
    """Port in adapters."""

    def __init__(self, port_idx, **kwargs):
        super(AdapterPort, self).__init__(port_idx=port_idx, **kwargs)


class LANPort(AdapterPort):
    """LAN Port."""
    _BASIC_ATTRIBUTES = [
        VIOMAttribute('port_idx', '@PortIdx', 1),
        VIOMAttribute('port_enable', 'PortEnable'),
        VIOMAttribute('sriov', 'SRIOV'),
        VIOMAttribute('use_virtual_addresses', 'UseVirtualAddresses'),
    ]

    def __init__(self, port_idx, port_enable=True, mac=None, boot=None,
                 **kwargs):
        super(LANPort, self).__init__(port_idx, port_enable=port_enable,
                                      **kwargs)
        self.mac = mac
        self.boot = boot if boot else NoneBoot()

    def get_json(self):
        """Create JSON data for LANPort.

        :returns: JSON data as follows:

            {
              "@PortIdx":1,
              "PortEnable":{
              },
              "UseVirtualAddresses":{
              },
              "BootProtocol":{
              },
              "VirtualAddress":{
                "MAC":{
                }
              },
              "BootPriority":{
              },
              "ISCSIBootEnvironment":{
              }
            }
        """

        port = self.get_basic_json()
        port.update({
            'BootProtocol': self.boot.BOOT_PROTOCOL,
            'BootPriority': self.boot.boot_prio,
        })
        boot_env = self.boot.get_json()
        if boot_env:
            port.update(boot_env)
        if self.use_virtual_addresses and self.mac:
            port['VirtualAddress'] = {'MAC': self.mac}
        return port


class FCPort(AdapterPort):
    """FC Port."""
    _BASIC_ATTRIBUTES = [
        VIOMAttribute('port_idx', '@PortIdx', 1),
        VIOMAttribute('port_enable', 'PortEnable'),
        VIOMAttribute('sriov', 'SRIOV'),
        VIOMAttribute('use_virtual_addresses', 'UseVirtualAddresses'),
    ]

    def __init__(self, port_idx, port_enable=True, wwnn=None, wwpn=None,
                 boot=None, **kwargs):
        super(FCPort, self).__init__(port_idx, port_enable=port_enable,
                                     **kwargs)
        self.wwnn = wwnn
        self.wwpn = wwpn
        self.boot = boot if boot else NoneBoot()

    def get_json(self):
        """Create FC port.

        :returns: JSON for FC port as follows:
            {
                "@PortIdx":1,
                "PortEnable":{
                },
                "UseVirtualAddresses":{
                },
                "VirtualAddress":{
                    "WWNN":{
                    },
                    "WWPN":{
                    },
                    "MAC":{
                    }
                },
                "BootProtocol":{
                },
                "BootPriority":{
                },
                "FCBootEnvironment":{
                }
            }

        """
        port = self.get_basic_json()
        port.update({
            'BootProtocol': self.boot.BOOT_PROTOCOL,
            'BootPriority': self.boot.boot_prio,
        })
        boot_env = self.boot.get_json()
        if boot_env:
            port.update(boot_env)
        if self.use_virtual_addresses:
            addresses = {}
            if self.wwnn:
                addresses['WWNN'] = self.wwnn
            if self.wwpn:
                addresses['WWPN'] = self.wwpn
            if addresses:
                port['VirtualAddress'] = addresses
        return port


class CNAPort(AdapterPort):
    """CNA port."""
    _BASIC_ATTRIBUTES = [
        VIOMAttribute('port_idx', '@PortIdx', 1),
        VIOMAttribute('port_enable', 'PortEnable'),
    ]

    def __init__(self, port_idx, port_enable=True):
        super(CNAPort, self).__init__(port_idx, port_enable=port_enable)
        self.functions = {}

    def add_function(self, function):
        self.functions[function.func_idx] = function

    def get_function(self, func_idx):
        return self.functions.get(func_idx)

    def get_json(self):
        """Create JSON for CNA port.

        :returns: JSON for CNA port as follows:
            {
                "@PortIdx":1,
                "PortEnable":{
                },
                "Functions":{
                }
            }
        """
        port = self.get_basic_json()
        port['Functions'] = {
            'Function': [f.get_json() for f in self.functions.values()]
        }
        return port


@six.add_metaclass(abc.ABCMeta)
class CNAFunction(VIOMElement):
    """Abstract class for Functions for CNA card"""
    _BASIC_ATTRIBUTES = [
        VIOMAttribute('function_enable', 'FunctionEnable'),
        VIOMAttribute('vlan_id', 'VLANId'),
        VIOMAttribute('sriov', 'SRIOV'),
        VIOMAttribute('use_virtual_addresses', 'UseVirtualAddresses'),
        VIOMAttribute('bandwidth', 'Bandwidth'),
        VIOMAttribute('rate_limit', 'RateLimit'),
    ]

    def __init__(self, func_idx, function_enable=True, boot=None, **kwargs):
        super(CNAFunction, self).__init__(**kwargs)
        self.func_idx = func_idx
        self.boot = boot if boot else NoneBoot()
        self.function_enable = function_enable

    def _get_virtual_addresses_json(self, json):
        return None

    def get_json(self):
        """Create JSON for CNA function.

        :returns: JSON for CNA function.
            * LANFunction creates the following JSON:

                {
                    "LANFunction":{
                        "FunctionEnable":{
                        },
                        "BootProtocol":{
                        },
                        "UseVirtualAddresses":{
                        },
                        "BootPriority":{
                        },
                        "Bandwidth":{
                        },
                        "RateLimit":{
                        },
                        "VLANId":{
                        },
                        "VirtualAddress":{
                            "MAC":{
                            }
                        }
                    }
                }

            * FCoEFunction creates the following JSON:

                {
                    "FCoEFunction":{
                        "FunctionEnable":{
                        },
                        "BootProtocol":{
                        },
                        "UseVirtualAddresses":{
                        },
                        "BootPriority":{
                        },
                        "Bandwidth":{
                        },
                        "RateLimit":{
                        },
                        "VLANId":{
                        },
                        "VirtualAddress":{
                            "WWNN":{
                            },
                            "WWPN":{
                            },
                            "MAC":{
                            }
                        },
                        "FCBootEnvironment":{
                        }
                    }
                }

            * ISCSIFunction creates the following JSON:

                {
                    "@FunctionIdx": 1,
                    "ISCSIFunction":{
                        "FunctionEnable":{
                        },
                        "BootProtocol":{
                        },
                        "UseVirtualAddresses":{
                        },
                        "BootPriority":{
                        },
                        "Bandwidth":{
                        },
                        "RateLimit":{
                        },
                        "VLANId":{
                        },
                        "VirtualAddress":{
                            "MAC":{
                            }
                        },
                        "ISCSIBootEnvironment":{
                        }
                    }
                }
        """
        function = self.get_basic_json()
        function['BootProtocol'] = self.boot.BOOT_PROTOCOL
        function['BootPriority'] = self.boot.boot_prio
        if self.use_virtual_addresses:
            virtual_addresses = self._get_virtual_addresses_json()
            if virtual_addresses:
                function['VirtualAddress'] = virtual_addresses
        boot_env = self.boot.get_json()
        if boot_env:
            function.update(boot_env)
        return {'@FunctionIdx': self.func_idx,
                self.FUNCTION_NAME: function}


class LANFunction(CNAFunction):
    """LAN function for CNA card"""
    FUNCTION_NAME = 'LANFunction'

    def __init__(self, func_idx, function_enable=True, boot=None, mac=None,
                 **kwargs):
        super(LANFunction, self).__init__(
            func_idx, function_enable=function_enable, boot=boot, **kwargs)
        self.mac = mac

    def _get_virtual_addresses_json(self):
        return {'MAC': self.mac} if self.mac else None


class FCoEFunction(CNAFunction):
    """FCoE Function for CNA card."""
    FUNCTION_NAME = 'FCoEFunction'

    def __init__(self, func_idx, function_enable=True, boot=None, wwnn=None,
                 wwpn=None, mac=None, **kwargs):
        super(FCoEFunction, self).__init__(
            func_idx, function_enable=function_enable, boot=boot, **kwargs)
        self.wwnn = wwnn
        self.wwpn = wwpn
        self.mac = mac

    def _get_virtual_addresses_json(self):
        virtual_addresses = {}
        if self.mac:
            virtual_addresses['MAC'] = self.mac
        if self.wwnn:
            virtual_addresses['WWNN'] = self.wwnn
        if self.wwpn:
            virtual_addresses['WWPN'] = self.wwpn
        return virtual_addresses


class ISCSIFunction(CNAFunction):
    """iSCSI Function for CNA card."""
    FUNCTION_NAME = 'ISCSIFunction'

    def __init__(self, func_idx, function_enable=True, boot=None, mac=None,
                 **kwargs):
        super(ISCSIFunction, self).__init__(
            func_idx, function_enable=function_enable, boot=boot, **kwargs)
        self.mac = mac

    def _get_virtual_addresses_json(self):
        return {'MAC': self.mac} if self.mac else None


@six.add_metaclass(abc.ABCMeta)
class Boot(VIOMElement):
    """Abstract class for BootProtocol"""
    _BASIC_ATTRIBUTES = []

    def __init__(self, boot_prio=1, **kwargs):
        super(Boot, self).__init__(**kwargs)
        self.boot_prio = boot_prio

    def get_json(self):
        return {}


class NoneBoot(Boot):
    """None BootProtocol."""
    BOOT_PROTOCOL = 'None'


class PXEBoot(Boot):
    """PXE BootProtocol."""
    BOOT_PROTOCOL = 'PXE'


class FCBoot(Boot):
    """FC BootProtocol with FCBootEnvironment elemnt."""
    BOOT_PROTOCOL = 'FC'

    _BASIC_ATTRIBUTES = [
        VIOMAttribute('link_speed', 'FCLinkSpeed', 'auto'),
        VIOMAttribute('topology', 'FCTopology', 'auto_loop'),
        VIOMAttribute('boot_enable', 'SANBootEnable'),
    ]

    def __init__(self, boot_prio=1, **kwargs):
        super(FCBoot, self).__init__(boot_prio, **kwargs)
        self.targets = []

    def add_target(self, target):
        self.targets.append(target)

    def get_json(self):
        """Create JSON for FCBootEnvironment.

        :returns: JSON for FCBootEnvironment as follows:

            {
                "FCBootEnvironment":{
                    "FCTargets":{
                        "FCTarget":[
                        ]
                    },
                    "FCLinkSpeed":{
                    },
                    "SANBootEnable":{
                    },
                    "FCTopology":{
                    }
                }
            }
        """
        json = self.get_basic_json()
        for i in range(len(self.targets)):
            # @FCTargetIdx starts from 1.
            self.targets[i].set_index(i + 1)
        json['FCTargets'] = {
            'FCTarget': [t.get_json() for t in self.targets]
        }
        return {'FCBootEnvironment': json}


class FCTarget(VIOMElement):
    """FC Target."""
    _BASIC_ATTRIBUTES = [
        VIOMAttribute('index', '@FCTargetIdx', 1),
        VIOMAttribute('wwpn', 'TargetWWPN'),
        VIOMAttribute('lun', 'TargetLUN')
    ]

    def __init__(self, wwpn, lun=0, **kwargs):
        super(FCTarget, self).__init__(wwpn=wwpn, lun=lun)

    def set_index(self, index):
        self.index = index

    def get_json(self):
        """Create JSON for FCTarget.

        :returns: JSON data for FCTarget as follows:
            {
                "@FCTargetIdx":1,
                "TargetWWPN":{
                  },
                "TargetLUN":{
                }
            }
        """
        return self.get_basic_json()


class ISCSIBoot(Boot):
    """iSCSI BootProtocol with ISCSIBootEnvironment elment."""
    BOOT_PROTOCOL = 'ISCSI'

    def __init__(self, initiator, target, boot_prio=1):
        super(ISCSIBoot, self).__init__(boot_prio)
        self.initiator = initiator
        self.target = target

    def get_json(self):
        """Create JSON for ISCSIBoot.

        :returns: JSON data for ISCSIBoot as follows:
            {
                "ISCSIBootEnvironment":{
                    "ISCSIInitiator":{
                    },
                    "ISCSITarget":{
                    }
                }
            }
        """
        return {
            'ISCSIBootEnvironment': {
                'ISCSIInitiator': self.initiator.get_json(),
                'ISCSITarget': self.target.get_json()
            }
        }


class ISCSIInitiator(VIOMElement):
    """iSCSIInitiator."""
    _BASIC_ATTRIBUTES = [
        VIOMAttribute('dhcp_usage', 'DHCPUsage', False),
        VIOMAttribute('iqn', 'Name'),
        VIOMAttribute('ip', 'IPv4Address'),
        VIOMAttribute('subnet', 'SubnetMask'),
        VIOMAttribute('gateway', 'GatewayIPv4Address'),
        VIOMAttribute('vlan_id', 'VLANId', 0),
    ]

    def __init__(self, **kwargs):
        super(ISCSIInitiator, self).__init__(**kwargs)

    def get_json(self):
        """Create JSON data for iSCSI initiator.

        :returns: JSON data for iSCSI initiator as follows:

            {
                "DHCPUsage":{
                },
                "Name":{
                },
                "IPv4Address":{
                },
                "SubnetMask":{
                },
                "GatewayIPv4Address":{
                },
                "VLANId":{
                }
            }
        """
        if self.dhcp_usage:
            return {'DHCPUsage': self.dhcp_usage,
                    'Name': self.iqn}
        else:
            return self.get_basic_json()


class ISCSITarget(VIOMElement):
    """iSCSI target."""
    _BASIC_ATTRIBUTES = [
        VIOMAttribute('dhcp_usage', 'DHCPUsage', False),
        VIOMAttribute('iqn', 'Name'),
        VIOMAttribute('ip', 'IPv4Address'),
        VIOMAttribute('port', 'PortNumber', 3260),
        VIOMAttribute('lun', 'BootLUN', 0),
        VIOMAttribute('auth_method', 'AuthenticationMethod', 'None'),
        VIOMAttribute('chap_user', 'ChapUserName'),
        VIOMAttribute('chap_secret', 'ChapSecret'),
        VIOMAttribute('mutual_chap_secret', 'MutualChapSecret'),
    ]

    def __init__(self, **kwargs):
        super(ISCSITarget, self).__init__(**kwargs)

    def get_json(self):
        """Create JSON data for iSCSI target.

        :returns: JSON data for iSCSI target as follows:

            {
                "DHCPUsage":{
                },
                "Name":{
                },
                "IPv4Address":{
                },
                "PortNumber":{
                },
                "BootLUN":{
                },
                "AuthenticationMethod":{
                },
                "ChapUserName":{
                },
                "ChapSecret":{
                },
                "MutualChapSecret":{
                }
            }
        """
        json = {
            'DHCPUsage': self.dhcp_usage,
            'AuthenticationMethod': self.auth_method,
        }
        if not self.dhcp_usage:
            json['Name'] = self.iqn
            json['IPv4Address'] = self.ip
            json['PortNumber'] = self.port
            json['BootLUN'] = self.lun
        if self.chap_user:
            json['ChapUserName'] = self.chap_user
        if self.chap_secret:
            json['ChapSecret'] = self.chap_secret
        if self.mutual_chap_secret:
            json['MutualChapSecret'] = self.mutual_chap_secret
        return json
