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
import logging
import time

import six

from scciclient.irmc import elcm
from scciclient.irmc import scci


LOG = logging.getLogger(__name__)
PROFILE_NAME = 'AdapterConfigIrmc'
PARAM_PATH = 'Server/AdapterConfigIrmc'


class ElcmViomClient(object):
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


class ViomAttribute(object):
    """Attribute in VIOM Element.

    This class is used for conversion between Python class and JSON table.
    """
    def __init__(self, name, key, init=None):
        self.name = name
        self.key = key
        self.init = init


@six.add_metaclass(abc.ABCMeta)
class ViomElement(object):
    """Element in VIOM table."""
    def __init__(self, **kwargs):
        for attr in self.basic_attributes:
            setattr(self, attr.name, kwargs.get(attr.name, attr.init))

    def get_basic_json(self):
        table = {}
        for attr in self.basic_attributes:
            value = getattr(self, attr.name)
            if value is not None:
                table[attr.key] = value
        return table


class ViomTable(ViomElement):
    """Root class of VIOM table"""
    basic_attributes = [
        ViomAttribute('use_virtual_addresses', 'UseVirtualAddresses'),
        ViomAttribute('viom_boot_enable', 'VIOMBootEnable'),
        ViomAttribute('boot_menu_enable', 'BootMenuEnable'),
        ViomAttribute('sriov', 'SRIOV'),
        ViomAttribute('smux', 'Smux'),
        ViomAttribute('boot_mode', 'BootMode'),
        ViomAttribute('init_boot', 'InitBoot'),
        ViomAttribute('processing', '@Processing'),
        ViomAttribute('mode', 'Mode')
    ]

    def __init__(self, **kwargs):
        super(ViomTable, self).__init__(**kwargs)
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


class ManageTable(ViomElement):
    """Class for ViomManage element."""

    basic_attributes = [
        ViomAttribute('manage', 'Manage'),
        ViomAttribute('identification', 'Identification'),
        ViomAttribute('trapDestination', 'TrapDestination'),
        ViomAttribute('force', 'Force'),
        ViomAttribute('preferred_version', 'PreferredInventoryVersion')
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


class Slot(ViomElement):
    """Class for Slot element."""

    basic_attributes = [
        ViomAttribute('slot_idx', '@SlotIdx', 0),
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
                },
                "AddOnCards":{
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
class PciCard(object):
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


class OnboardCard(PciCard):
    """Class for onboard Card."""
    INDEX_KEY = '@OnboardControllerIdx'


class AddOnCard(PciCard):
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


class LanAdapter(Adapter):
    """LAN adapter."""
    ADAPTER_NAME = 'LANAdapter'


class FcAdapter(Adapter):
    """FC adapter."""
    ADAPTER_NAME = 'FCAdatper'


class CnaAdapter(Adapter):
    """CNA adatper."""
    ADAPTER_NAME = 'CNAAdapter'


@six.add_metaclass(abc.ABCMeta)
class AdapterPort(ViomElement):
    """Port in adapters."""

    def __init__(self, port_idx, **kwargs):
        super(AdapterPort, self).__init__(port_idx=port_idx, **kwargs)


class LanPort(AdapterPort):
    """LAN Port."""
    basic_attributes = [
        ViomAttribute('port_idx', '@PortIdx', 1),
        ViomAttribute('port_enable', 'PortEnable'),
        ViomAttribute('sriov', 'SRIOV'),
        ViomAttribute('use_virtual_addresses', 'UseVirtualAddresses'),
    ]

    def __init__(self, port_idx, mac=None, boot=None, **kwargs):
        super(LanPort, self).__init__(port_idx, **kwargs)
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


class FcPort(AdapterPort):
    """FC Port."""
    basic_attributes = [
        ViomAttribute('port_idx', '@PortIdx', 1),
        ViomAttribute('port_enable', 'PortEnable'),
        ViomAttribute('sriov', 'SRIOV'),
        ViomAttribute('use_virtual_addresses', 'UseVirtualAddresses'),
    ]

    def __init__(self, port_idx, wwnn=None, wwpn=None, boot=None, **kwargs):
        super(FcPort, self).__init__(port_idx, **kwargs)
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


class CnaPort(AdapterPort):
    """CNA port."""
    basic_attributes = [
        ViomAttribute('port_idx', '@PortIdx', 1),
        ViomAttribute('port_enable', 'PortEnable'),
    ]

    def __init__(self, port_idx, port_enable=True):
        super(CnaPort, self).__init__(port_idx, port_enable=port_enable)
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
class CnaFunction(ViomElement):
    """Abstract class for Functions for CNA card"""
    basic_attributes = [
        ViomAttribute('function_enable', 'FunctionEnable'),
        ViomAttribute('vlan_id', 'VLANId'),
        ViomAttribute('sriov', 'SRIOV'),
        ViomAttribute('use_virtual_addresses', 'UseVirtualAddresses'),
        ViomAttribute('bandwidth', 'Bandwidth'),
        ViomAttribute('rate_limit', 'RateLimit'),
    ]

    def __init__(self, func_idx, function_enable=True, boot=None, **kwargs):
        super(CnaFunction, self).__init__(**kwargs)
        self.func_idx = func_idx
        self.boot = boot if boot else NoneBoot()
        self.function_enable = True

    def _get_virtual_addresses_json(self, json):
        return None

    def get_json(self):
        """Create JSON for CNA function.

        :returns: JSONf for CNA function.
            * LanFunction creates the following JSON:

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

            * IscsiFunction creates the following JSON:

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


class LanFunction(CnaFunction):
    """LAN function for CNA card"""
    FUNCTION_NAME = 'LANFunction'

    def __init__(self, func_idx, function_enable=True, boot=None, mac=None,
                 **kwargs):
        super(LanFunction, self).__init__(
            func_idx, function_enable=function_enable, boot=boot, **kwargs)
        self.mac = mac

    def _get_virtual_addresses_json(self):
        return {'MAC': self.mac} if self.mac else None


class FcoeFunction(CnaFunction):
    """FCoE Function for CNA card."""
    FUNCTION_NAME = 'FCoEFunction'

    def __init__(self, func_idx, function_enable=True, boot=None, wwnn=None,
                 wwpn=None, mac=None, **kwargs):
        super(FcoeFunction, self).__init__(
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


class IscsiFunction(CnaFunction):
    """iSCSI Function for CNA card."""
    FUNCTION_NAME = 'ISCSIFunction'

    def __init__(self, func_idx, function_enable=True, boot=None, mac=None,
                 **kwargs):
        super(IscsiFunction, self).__init__(
            func_idx, function_enable=function_enable, boot=boot, **kwargs)
        self.mac = mac

    def _get_virtual_addresses_json(self):
        return {'MAC': self.mac} if self.mac else None


@six.add_metaclass(abc.ABCMeta)
class Boot(ViomElement):
    """Abstract class for BootProtocol"""
    basic_attributes = []

    def __init__(self, boot_prio=1, **kwargs):
        super(Boot, self).__init__(**kwargs)
        self.boot_prio = boot_prio

    def get_json(self):
        return {}


class NoneBoot(Boot):
    """None BootProtocol."""
    BOOT_PROTOCOL = 'None'


class PxeBoot(Boot):
    """PXE BootProtocol."""
    BOOT_PROTOCOL = 'PXE'


class FcBoot(Boot):
    """FC BootProtocol with FCBootEnvironment elemnt."""
    BOOT_PROTOCOL = 'FC'

    basic_attributes = [
        ViomAttribute('link_speed', 'FCLinkSpeed', 'auto'),
        ViomAttribute('topology', 'FCTopology', 'auto_loop'),
        ViomAttribute('boot_enable', 'SANBootEnable', False),
    ]

    def __init__(self, boot_prio=1, **kwargs):
        super(FcBoot, self).__init__(boot_prio, **kwargs)
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
            self.targets[i].set_index(i)
        json['FCTarget'] = [t.get_json() for t in self.targets.values()]
        return {'FCBootEnvironment': json}


class FcTarget(ViomElement):
    """FC Target."""
    basic_attributes = [
        ViomAttribute('index', '@FCTargetIdx', 1),
        ViomAttribute('wwpn', 'TargetWWPN'),
        ViomAttribute('lun', 'TargetLUN')
    ]

    def __init__(self, wwpn, lun=0, **kwargs):
        super(FcTarget, self).__init__(wwpn=wwpn, lun=lun)

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


class IscsiBoot(Boot):
    """iSCSI BootProtocol with ISCSIBootEnvironment elment."""
    BOOT_PROTOCOL = 'ISCSI'

    def __init__(self, initiator, target, boot_prio=1):
        super(IscsiBoot, self).__init__(boot_prio)
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


class IscsiInitiator(ViomElement):
    """iSCSIInitiator."""
    basic_attributes = [
        ViomAttribute('dhcp_usage', 'DHCPUsage', False),
        ViomAttribute('iqn', 'Name'),
        ViomAttribute('ip', 'IPv4Address'),
        ViomAttribute('subnet', 'SubnetMask'),
        ViomAttribute('gateway', 'GatewayIPv4Address'),
        ViomAttribute('vlan_id', 'VLANId', 0),
    ]

    def __init__(self, **kwargs):
        super(IscsiInitiator, self).__init__(**kwargs)

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


class IscsiTarget(ViomElement):
    """iSCSI target."""
    basic_attributes = [
        ViomAttribute('dhcp_usage', 'DHCPUsage', False),
        ViomAttribute('iqn', 'Name'),
        ViomAttribute('ip', 'IPv4Address'),
        ViomAttribute('port', 'PortNumber', 3260),
        ViomAttribute('lun', 'BootLUN', 0),
        ViomAttribute('auth_method', 'AuthenticationMethod', 'None'),
        ViomAttribute('chap_user', 'ChapUserName'),
        ViomAttribute('chap_secret', 'ChapSecret'),
        ViomAttribute('mutal_chap_secret', 'MutalChapSecret'),
    ]

    def __init__(self, **kwargs):
        super(IscsiTarget, self).__init__(**kwargs)

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
        if self.mutal_chap_secret:
            json['MutalChapSecret'] = self.mutal_chap_secret
        return json
