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
    LAN: elcm.LanAdapter,
    FC: elcm.FcAdapter,
    CNA: elcm.CnaAdapter
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

    def create_card(self):
        return _CARD_DICT[self.slot_type](
            self.card_idx, _ADAPTER_DICT[self.card_type]())

    def create_lan_port(self, mac=None):
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


class _LanPortHandler(_PortHandler):
    """Configurator for LAN card."""

    def create_lan_port(self, mac=None):
        return elcm.LanPort(self.port_idx,
                            port_enable=True,
                            use_virtual_addresses=bool(mac),
                            mac=mac)

    def set_lan_port(self, port, mac=None):
        if mac:
            port.port_enable = True
            port.mac = mac
            port.use_virtual_addresses = True

    def set_iscsi_port(self, port, iscsi_boot):
        port.boot = iscsi_boot

    def create_iscsi_port(self, iscsi_boot):
        return elcm.LanPort(self.port_idx, boot=iscsi_boot, port_enable=True)


class _FcPortHandler(_PortHandler):
    """Configurator for FC card."""

    def set_fc_port(self, port, fc_boot, wwnn=None, wwpn=None):
        port.boot = fc_boot
        port.port_enable = True
        if wwnn or wwpn:
            port.use_virtual_addresses = True
            port.wwnn = wwnn
            port.wwpn = wwpn

    def create_fc_port(self, fc_boot, wwnn=None, wwpn=None):
        return elcm.FcPort(self.port_idx, boot=fc_boot, wwnn=wwnn, wwpn=wwpn,
                           use_virtual_addresses=bool(wwnn or wwpn),
                           port_enable=True)


class _CnaPortHandler(_PortHandler):
    """Configurator for CNA card."""

    def _create_port(self, function):
        cna_port = elcm.CnaPort(self.port_idx)
        if not isinstance(function, elcm.LanFunction):
            # LanFunction is must
            cna_port.add_function(
                elcm.LanFunction(_CNA_LAN_FUNC_IDX, function_enable=False,
                                 boot=None))
        cna_port.add_function(function)
        return cna_port

    def create_lan_port(self, mac=None):
        function = elcm.LanFunction(_CNA_LAN_FUNC_IDX,
                                    function_enable=True,
                                    use_virtual_addresses=bool(mac),
                                    mac=mac)
        return self._create_port(function)

    def set_lan_port(self, port, mac=None):
        if not mac:
            return
        function = port.get_function(_CNA_LAN_FUNC_IDX)
        if function:
            function.mac = mac
            function.use_virtual_addresses = True
        else:
            function = elcm.LanFunction(_CNA_LAN_FUNC_IDX, mac=mac,
                                        use_virtual_addresses=True,
                                        function_enable=True)

    def set_iscsi_port(self, port, iscsi_boot):
        function = port.get_function(_CNA_ISCSI_FUNC_IDX)
        if function:
            function.boot = iscsi_boot
        else:
            function = elcm.IscsiFunction(_CNA_ISCSI_FUNC_IDX, boot=iscsi_boot,
                                          function_enable=True)
            port.add_function(function)

    def create_iscsi_port(self, iscsi_boot):
        function = elcm.IscsiFunction(_CNA_ISCSI_FUNC_IDX, boot=iscsi_boot)
        return self._create_port(function)

    def set_fc_port(self, port, fc_boot):
        function = port.get_function(_CNA_FCOE_FUNC_IDX)
        if function:
            function.boot = fc_boot
        else:
            function = elcm.FcoeFunction(_CNA_FCOE_FUNC_IDX, boot=fc_boot,
                                         function_enable=True)
            port.add_function(function)

    def create_fc_port(self, fc_boot):
        function = elcm.FcoeFunction(self, _CNA_FCOE_FUNC_IDX, boot=fc_boot,
                                     function_enable=True)
        return self._create_port(function)


_PORT_HANDLERS = {
    LAN: _LanPortHandler,
    FC: _FcPortHandler,
    CNA: _CnaPortHandler,
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


def _create_iscsi_boot(initiator_iqn, initiator_ip, initiator_netmask,
                       target_iqn, target_ip, target_port, target_lun,
                       boot_prio=1):
    iscsi_initiator = elcm.IscsiInitiator(iqn=initiator_iqn,
                                          ip=initiator_ip,
                                          subnet=initiator_netmask)
    iscsi_target = elcm.IscsiTarget(iqn=target_iqn,
                                    ip=target_ip,
                                    port=target_port,
                                    lun=target_lun)
    iscsi_boot = elcm.IscsiBoot(iscsi_initiator,
                                iscsi_target,
                                boot_prio=boot_prio)
    return iscsi_boot


class ViomConfiguration(object):
    """VIOM Configurator for volume boot"""

    def __init__(self, irmc_info, identification):
        self.client = elcm.ElcmViomClient(irmc_info)
        self.root = elcm.ViomTable()
        self.root.set_manage_table(
            elcm.ManageTable(identification=identification))

    def apply(self):
        """Apply the configuration to iRMC."""
        self.root.use_virtual_addresses = True
        self.root.manage.manage = True
        self.root.mode = 'new'
        self.root.init_boot = True

        self.client.set_profile(self.root.get_json())

    def terminate(self):
        """Delete VIOM configuration from iRMC."""
        self.root.manage.manage = False
        self.root.mode = 'delete'
        self.root.init_boot = True
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
                         initiator_iqn, initiator_ip, initiator_netmask,
                         target_iqn, target_ip, target_port=3260,
                         target_lun=0, boot_prio=1):
        """Set iSCSI volume information to configuration.

        :param port_id: Physical port ID.
        :param initiator_iqn: IQN of initiator.
        :param initiator_ip: IP address of initiator.
        :param initiator_netmask: Netmask of initiator like '255.255.255.0'.
        :param target_iqn: IQN of target.
        :param target_ip: IP address of target.
        :param target_port: Port numger of target.
        :param target_lun: LUN number of target.
        :param boot_prio: Boot priority of the volume. 1 indicates the highest
            priority.
        """

        port_handler = _parse_physical_port_id(port_id)
        iscsi_boot = _create_iscsi_boot(initiator_iqn, initiator_ip,
                                        initiator_netmask,
                                        target_iqn, target_ip,
                                        target_port, target_lun, boot_prio)

        port = self._find_port(port_handler)
        if port:
            port_handler.set_iscsi_port(port, iscsi_boot)
        else:
            port = port_handler.create_iscsi_port(iscsi_boot)
            card = self._get_card(port_handler)
            card.add_port(port)

    def set_fc_volume(self, port_id,
                      target_wwn, target_lun=0, boot_prio=1):
        """Set FibreChannel volume information to configuration.

        :param port_id: Physical port ID.
        :param target_wwn: WWN of target.
        :param target_lun: LUN number of target.
        :param boot_prio: Boot priority of the volume. 1 indicates the highest
            priority.
        """
        port_handler = _parse_physical_port_id(port_id)
        fc_target = elcm.FcTarget(target_wwn, target_lun)
        fc_boot = elcm.FcBoot(boot_prio=boot_prio)
        fc_boot.add_target(fc_target)

        port = self._find_port(port_handler)
        if port:
            port_handler.set_iscsi_port(port, fc_boot)
        else:
            port = port_handler.create_iscsi_port(fc_boot)
            card = self._get_card(port_handler)
            card.add_port(port)

    def dump_json(self):
        """Create JSON profile based on current configuration.

        :returns: JSON data created from current configurtion. It can be
        logged by a caller.
        """
        return self.root.get_json()


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
