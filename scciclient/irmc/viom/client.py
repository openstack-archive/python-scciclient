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
import re
import six
import socket
import struct

from scciclient.irmc import scci
from scciclient.irmc.viom import elcm


ONBOARD = 'onboard'
ADDON = 'addon'
_CARD_DICT = {
    ONBOARD: elcm.OnboardCard,
    ADDON: elcm.AddOnCard}

LAN = 'LAN'
FC = 'FC'
CNA = 'CNA'
_ADAPTER_DICT = {
    LAN: elcm.LANAdapter,
    FC: elcm.FCAdapter,
    CNA: elcm.CNAAdapter
}
_POSSIBLE_CARD_TYPE = _ADAPTER_DICT.keys()

_CNA_LAN_FUNC_IDX = 1
_CNA_FCOE_FUNC_IDX = 2
_CNA_ISCSI_FUNC_IDX = 3


@six.add_metaclass(abc.ABCMeta)
class _PortHandler(object):
    """VIOM Configurator with physical port information"""

    def __init__(self, slot_type, card_type, slot_idx, card_idx, port_idx):
        self.slot_type = slot_type
        self.card_type = card_type
        self.slot_idx = slot_idx
        self.card_idx = card_idx
        self.port_idx = port_idx

    def need_padding(self):
        return False

    def create_card(self):
        return _CARD_DICT[self.slot_type](
            self.card_idx, _ADAPTER_DICT[self.card_type]())

    def create_lan_port(self, mac=None, port_enable=True):
        raise NotImplementedError()

    def set_lan_port(self, port, mac=None):
        raise NotImplementedError()

    def set_iscsi_port(self, port, iscsi_boot):
        raise NotImplementedError()

    def create_iscsi_port(self, iscsi_boot):
        raise NotImplementedError()

    def set_fc_port(self, port, fc_boot, wwnn=None, wwpn=None):
        raise NotImplementedError()

    def create_fc_port(self, fc_boot, wwnn=None, wwpn=None):
        raise NotImplementedError()


class _LANPortHandler(_PortHandler):
    """Configurator for LAN card."""

    def need_padding(self):
        return True if self.slot_type == ONBOARD else False

    def create_lan_port(self, mac=None, port_enable=True):
        return elcm.LANPort(self.port_idx,
                            port_enable=port_enable,
                            use_virtual_addresses=bool(mac),
                            mac=mac)

    def set_lan_port(self, port, mac=None):
        port.port_enable = True
        port.mac = mac
        port.use_virtual_addresses = bool(mac)

    def set_iscsi_port(self, port, iscsi_boot):
        port.boot = iscsi_boot

    def create_iscsi_port(self, iscsi_boot):
        return elcm.LANPort(self.port_idx, boot=iscsi_boot, port_enable=True)


class _FCPortHandler(_PortHandler):
    """Configurator for FC card."""

    def set_fc_port(self, port, fc_boot, wwnn=None, wwpn=None):
        port.boot = fc_boot
        port.port_enable = True
        port.use_virtual_addresses = bool(wwnn or wwpn)
        port.wwnn = wwnn
        port.wwpn = wwpn

    def create_fc_port(self, fc_boot, wwnn=None, wwpn=None):
        return elcm.FCPort(self.port_idx, boot=fc_boot, wwnn=wwnn, wwpn=wwpn,
                           use_virtual_addresses=bool(wwnn or wwpn),
                           port_enable=True)


class _CNAPortHandler(_PortHandler):
    """Configurator for CNA card."""

    def _create_port(self, function):
        cna_port = elcm.CNAPort(self.port_idx)
        if not isinstance(function, elcm.LANFunction):
            # LanFunction is must
            cna_port.add_function(
                elcm.LANFunction(_CNA_LAN_FUNC_IDX, function_enable=False,
                                 boot=None))
        cna_port.add_function(function)
        return cna_port

    def create_lan_port(self, mac=None, port_enable=True):
        function = elcm.LANFunction(_CNA_LAN_FUNC_IDX,
                                    function_enable=port_enable,
                                    use_virtual_addresses=bool(mac),
                                    mac=mac)
        return self._create_port(function)

    def set_lan_port(self, port, mac=None):
        function = port.get_function(_CNA_LAN_FUNC_IDX)
        # Lan Function is always created when port is created.
        function.function_enable = True
        function.mac = mac
        function.use_virtual_addresses = bool(mac)

    def set_iscsi_port(self, port, iscsi_boot):
        function = port.get_function(_CNA_ISCSI_FUNC_IDX)
        if function:
            function.boot = iscsi_boot
        else:
            function = elcm.ISCSIFunction(_CNA_ISCSI_FUNC_IDX, boot=iscsi_boot,
                                          function_enable=True)
            port.add_function(function)

    def create_iscsi_port(self, iscsi_boot):
        function = elcm.ISCSIFunction(_CNA_ISCSI_FUNC_IDX, boot=iscsi_boot)
        return self._create_port(function)

    def set_fc_port(self, port, fc_boot, wwnn=None, wwpn=None):
        function = port.get_function(_CNA_FCOE_FUNC_IDX)
        if function:
            function.boot = fc_boot
            function.use_virtual_addresses = bool(wwnn or wwpn)
            function.wwnn = wwnn
            function.wwpn = wwpn
        else:
            function = elcm.FCoEFunction(
                _CNA_FCOE_FUNC_IDX, boot=fc_boot, function_enable=True,
                use_virtual_addresses=bool(wwnn or wwpn), wwnn=wwnn, wwpn=wwpn)
            port.add_function(function)

    def create_fc_port(self, fc_boot, wwnn=None, wwpn=None):
        function = elcm.FCoEFunction(
            _CNA_FCOE_FUNC_IDX, boot=fc_boot, function_enable=True,
            use_virtual_addresses=bool(wwnn or wwpn), wwnn=wwnn, wwpn=wwpn)
        return self._create_port(function)


_PORT_HANDLERS = {
    LAN: _LANPortHandler,
    FC: _FCPortHandler,
    CNA: _CNAPortHandler,
}


def _parse_physical_port_id(port_id):

    message = ('Physical port ID should follow the format: '
               '<card-type><slot-idx>-<port-idx> like CNA1-1. '
               '<card-type> must be chosen from CNA, FC, or LAN. '
               '<slot-idx> should be 0 for onboard slot or 1-9 for addon '
               'slot. <port-idx> should be 1-9.')

    m = re.match('^([a-zA-Z]+)([0-9])-([1-9])$', port_id)
    if not m:
        raise scci.SCCIInvalidInputError(message)

    card_type = m.group(1).upper()
    if card_type not in _POSSIBLE_CARD_TYPE:
        raise scci.SCCIInvalidInputError(message)

    slot_idx = 0
    if int(m.group(2)) == 0:
        slot_type = ONBOARD
        card_idx = 1
    else:
        slot_type = ADDON
        card_idx = int(m.group(2))
    port_idx = int(m.group(3))

    return _PORT_HANDLERS[card_type](slot_type, card_type, slot_idx, card_idx,
                                     port_idx)


def _create_iscsi_boot(initiator_iqn,
                       initiator_dhcp=False, initiator_ip=None,
                       initiator_netmask=None,
                       target_dhcp=False, target_iqn=None, target_ip=None,
                       target_port=None, target_lun=None, boot_prio=1,
                       chap_user=None, chap_secret=None,
                       mutual_chap_secret=None):
    iscsi_initiator = elcm.ISCSIInitiator(dhcp_usage=initiator_dhcp,
                                          iqn=initiator_iqn,
                                          ip=initiator_ip,
                                          subnet=initiator_netmask)
    if chap_user and chap_secret:
        auth_method = 'MutualCHAP' if mutual_chap_secret else 'CHAP'
    else:
        auth_method = 'None'
    iscsi_target = elcm.ISCSITarget(dhcp_usage=target_dhcp,
                                    iqn=target_iqn,
                                    ip=target_ip,
                                    port=target_port,
                                    lun=target_lun,
                                    auth_method=auth_method,
                                    chap_user=chap_user,
                                    chap_secret=chap_secret,
                                    mutual_chap_secret=mutual_chap_secret)
    iscsi_boot = elcm.ISCSIBoot(iscsi_initiator,
                                iscsi_target,
                                boot_prio=boot_prio)
    return iscsi_boot


def _convert_netmask(mask):
    """Convert netmask from CIDR format(integer) to doted decimal string."""
    if mask not in range(0, 33):
        raise scci.SCCIInvalidInputError(
            'Netmask value is invalid.')

    return socket.inet_ntoa(struct.pack(
        '!L', int('1' * mask + '0' * (32 - mask), 2)))


class VIOMConfiguration(object):
    """VIOM Configurator for volume boot"""

    def __init__(self, irmc_info, identification):
        self.client = elcm.ELCMVIOMClient(irmc_info)
        self.root = elcm.VIOMTable()
        self.root.set_manage_table(
            elcm.ManageTable(identification=identification))

    def apply(self, reboot=False):
        """Apply the configuration to iRMC."""
        self.root.use_virtual_addresses = True
        self.root.manage.manage = True
        self.root.mode = 'new'
        self.root.init_boot = reboot

        self.client.set_profile(self.root.get_json())

    def terminate(self, reboot=False):
        """Delete VIOM configuration from iRMC."""
        self.root.manage.manage = False
        self.root.mode = 'delete'
        self.root.init_boot = reboot
        self.client.set_profile(self.root.get_json())

    def _find_card(self, port_handler):
        slot = self.root.get_slot(port_handler.slot_idx, create=False)
        if not slot:
            return None
        if port_handler.slot_type == ONBOARD:
            return slot.get_onboard_card(port_handler.card_idx)
        else:
            return slot.get_addon_card(port_handler.card_idx)

    def _get_card(self, port_handler):
        card = self._find_card(port_handler)
        if card:
            return card
        card = port_handler.create_card()
        self.root.get_slot(port_handler.slot_idx).add_card(card)
        return card

    def _find_port(self, port_handler):
        card = self._find_card(port_handler)
        if not card:
            return None
        return card.get_port(port_handler.port_idx)

    def _add_port(self, port_handler, port):
        self._pad_former_ports(port_handler)
        card = self._get_card(port_handler)
        card.add_port(port)

    def set_lan_port(self, port_id, mac=None):
        """Set LAN port information to configuration.

        :param port_id: Physical port ID.
        :param mac: virtual MAC address if virtualization is necessary.
        """
        port_handler = _parse_physical_port_id(port_id)
        port = self._find_port(port_handler)
        if port:
            port_handler.set_lan_port(port, mac)
        else:
            self._add_port(port_handler, port_handler.create_lan_port(mac))

    def set_iscsi_volume(self, port_id,
                         initiator_iqn, initiator_dhcp=False,
                         initiator_ip=None, initiator_netmask=None,
                         target_dhcp=False, target_iqn=None, target_ip=None,
                         target_port=3260, target_lun=0, boot_prio=1,
                         chap_user=None, chap_secret=None,
                         mutual_chap_secret=None):
        """Set iSCSI volume information to configuration.

        :param port_id: Physical port ID.
        :param initiator_iqn: IQN of initiator.
        :param initiator_dhcp: True if DHCP is used in the iSCSI network.
        :param initiator_ip: IP address of initiator. None if DHCP is used.
        :param initiator_netmask: Netmask of initiator as integer. None if
               DHCP is used.
        :param target_dhcp: True if DHCP is used for iSCSI target.
        :param target_iqn: IQN of target. None if DHCP is used.
        :param target_ip: IP address of target. None if DHCP is used.
        :param target_port: Port number of target.  None if DHCP is used.
        :param target_lun: LUN number of target. None if DHCP is used,
        :param boot_prio: Boot priority of the volume. 1 indicates the highest
            priority.
        """

        initiator_netmask = (_convert_netmask(initiator_netmask)
                             if initiator_netmask else None)

        port_handler = _parse_physical_port_id(port_id)
        iscsi_boot = _create_iscsi_boot(
            initiator_iqn,
            initiator_dhcp=initiator_dhcp,
            initiator_ip=initiator_ip,
            initiator_netmask=initiator_netmask,
            target_dhcp=target_dhcp,
            target_iqn=target_iqn,
            target_ip=target_ip,
            target_port=target_port,
            target_lun=target_lun,
            boot_prio=boot_prio,
            chap_user=chap_user,
            chap_secret=chap_secret,
            mutual_chap_secret=mutual_chap_secret)

        port = self._find_port(port_handler)
        if port:
            port_handler.set_iscsi_port(port, iscsi_boot)
        else:
            port = port_handler.create_iscsi_port(iscsi_boot)
            self._add_port(port_handler, port)

    def set_fc_volume(self, port_id,
                      target_wwn, target_lun=0, boot_prio=1,
                      initiator_wwnn=None, initiator_wwpn=None):
        """Set FibreChannel volume information to configuration.

        :param port_id: Physical port ID.
        :param target_wwn: WWN of target.
        :param target_lun: LUN number of target.
        :param boot_prio: Boot priority of the volume. 1 indicates the highest
               priority.
        :param initiator_wwnn: Virtual WWNN for initiator if necessary.
        :param initiator_wwpn: Virtual WWPN for initiator if necessary.
        """
        port_handler = _parse_physical_port_id(port_id)
        fc_target = elcm.FCTarget(target_wwn, target_lun)
        fc_boot = elcm.FCBoot(boot_prio=boot_prio, boot_enable=True)
        fc_boot.add_target(fc_target)

        port = self._find_port(port_handler)
        if port:
            port_handler.set_fc_port(port, fc_boot,
                                     wwnn=initiator_wwnn, wwpn=initiator_wwpn)
        else:
            port = port_handler.create_fc_port(fc_boot,
                                               wwnn=initiator_wwnn,
                                               wwpn=initiator_wwpn)
            self._add_port(port_handler, port)

    def dump_json(self):
        """Create JSON profile based on current configuration.

        :returns: JSON data created from current configurtion. It can be
                  logged by a caller.
        """
        return self.root.get_json()

    def _pad_former_ports(self, port_handler):
        """Create ports with former port index.

        :param port_handler: Port information to be registered.

        Depending on slot type and card type, it is necessary to register
        LAN ports with former index to VIOM table.
        """
        if not port_handler.need_padding():
            return
        for port_idx in range(1, port_handler.port_idx):
            pad_handler = port_handler.__class__(
                port_handler.slot_type,
                port_handler.card_type,
                port_handler.slot_idx,
                port_handler.card_idx,
                port_idx)
            if not self._find_port(pad_handler):
                self._add_port(pad_handler,
                               pad_handler.create_lan_port())


def validate_physical_port_id(port_id):
    """Validate physical port ID.

    Physical port ID is required for configure interfaces with VIOM API. The
    format is:
        <Card type><Slot Idx>-<Port Idx>

    * Card type is chosen from CNA, FC or LAN.
    * Slot Idx should be 0, which indecates on-board slot or 1-9, which
      specify add-on slot index.
    * Port Idx should be 1-9, which indicate port number.

    :param port_id: Physical port ID following the format.
    """
    _parse_physical_port_id(port_id)
