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

import six

from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp import error as snmp_error

BMC_NAME_OID = '1.3.6.1.4.1.231.2.10.2.2.10.3.4.1.3.1.1'
IRMC_FW_VERSION_OID = '1.3.6.1.4.1.231.2.10.2.2.10.3.4.1.4.1.1'
BIOS_FW_VERSION_OID = '1.3.6.1.4.1.231.2.10.2.2.10.4.1.1.11.1'
SERVER_MODEL_OID = '1.3.6.1.4.1.231.2.10.2.2.10.2.3.1.4.1'

SNMP_V1 = '1'
SNMP_V2C = '2c'
SNMP_V3 = '3'

SNMP_FAILURE_MSG = "SNMP operation '%s' failed: %s"


class SNMPFailure(Exception):
    """SNMP Failure

    This exception is used when invalid inputs are passed to
    the APIs exposed by this module.
    """
    def __init__(self, message):
        super(SNMPFailure, self).__init__(message)


class SNMPIRMCFirmwareFailure(SNMPFailure):
    """SNMP iRMC Firmware Failure

    This exception is used when error occurs when collecting iRMC firmware.
    """
    def __init__(self, message):
        super(SNMPIRMCFirmwareFailure, self).__init__(message)


class SNMPBIOSFirmwareFailure(SNMPFailure):
    """SNMP BIOS Firmware Failure

    This exception is used when error occurs when collecting BIOS firmware.
    """
    def __init__(self, message):
        super(SNMPBIOSFirmwareFailure, self).__init__(message)


class SNMPServerModelFailure(SNMPFailure):
    """SNMP Server Model Failure

    This exception is used when error occurs when collecting server model.
    """
    def __init__(self, message):
        super(SNMPServerModelFailure, self).__init__(message)


def get_irmc_firmware_version(snmp_client):
    """Get irmc firmware version of the node.

    :param snmp_client: an SNMP client object.
    :raises: SNMPFailure if SNMP operation failed.
    :returns: a string of bmc name and irmc firmware version.
    """

    try:
        bmc_name = snmp_client.get(BMC_NAME_OID)
        irmc_firm_ver = snmp_client.get(IRMC_FW_VERSION_OID)
        return ('%(bmc)s%(sep)s%(firm_ver)s' %
                {'bmc': bmc_name if bmc_name else '',
                 'firm_ver': irmc_firm_ver if irmc_firm_ver else '',
                 'sep': '-' if bmc_name and irmc_firm_ver else ''})
    except SNMPFailure as e:
        raise SNMPIRMCFirmwareFailure(
            SNMP_FAILURE_MSG % ("GET IRMC FIRMWARE VERSION", e))


def get_bios_firmware_version(snmp_client):
    """Get bios firmware version of the node.

    :param snmp_client: an SNMP client object.
    :raises: SNMPFailure if SNMP operation failed.
    :returns: a string of bios firmware version.
    """

    try:
        bios_firmware_version = snmp_client.get(BIOS_FW_VERSION_OID)
        return six.text_type(bios_firmware_version)
    except SNMPFailure as e:
        raise SNMPBIOSFirmwareFailure(
            SNMP_FAILURE_MSG % ("GET BIOS FIRMWARE VERSION", e))


def get_server_model(snmp_client):
    """Get server model of the node.

    :param snmp_client: an SNMP client object.
    :raises: SNMPFailure if SNMP operation failed.
    :returns: a string of server model.
    """

    try:
        server_model = snmp_client.get(SERVER_MODEL_OID)
        return six.text_type(server_model)
    except SNMPFailure as e:
        raise SNMPServerModelFailure(
            SNMP_FAILURE_MSG % ("GET SERVER MODEL", e))


class SNMPClient(object):
    """SNMP client object.

    Performs low level SNMP get and set operations. Encapsulates all
    interaction with PySNMP to simplify dynamic importing and unit testing.
    """

    def __init__(self, address, port, version, community=None, security=None):
        self.address = address
        self.port = port
        self.version = version
        if self.version == SNMP_V3:
            self.security = security
        else:
            self.community = community
        self.cmd_gen = cmdgen.CommandGenerator()

    def _get_auth(self):
        """Return the authorization data for an SNMP request.

        :returns: A
            :class:`pysnmp.entity.rfc3413.oneliner.cmdgen.CommunityData`
            object.
        """
        if self.version == SNMP_V3:
            # Handling auth/encryption credentials is not (yet) supported.
            # This version supports a security name analogous to community.
            return cmdgen.UsmUserData(self.security)
        else:
            mp_model = 1 if self.version == SNMP_V2C else 0
            return cmdgen.CommunityData(self.community, mpModel=mp_model)

    def _get_transport(self):
        """Return the transport target for an SNMP request.

        :returns: A :class:
            `pysnmp.entity.rfc3413.oneliner.cmdgen.UdpTransportTarget` object.
        :raises: snmp_error.PySnmpError if the transport address is bad.
        """
        # The transport target accepts timeout and retries parameters, which
        # default to 1 (second) and 5 respectively. These are deemed sensible
        # enough to allow for an unreliable network or slow device.
        return cmdgen.UdpTransportTarget((self.address, self.port))

    def get(self, oid):
        """Use PySNMP to perform an SNMP GET operation on a single object.

        :param oid: The OID of the object to get.
        :raises: SNMPFailure if an SNMP request fails.
        :returns: The value of the requested object.
        """
        try:
            results = self.cmd_gen.getCmd(self._get_auth(),
                                          self._get_transport(),
                                          oid)
        except snmp_error.PySnmpError as e:
            raise SNMPFailure(SNMP_FAILURE_MSG % ("GET", e))

        error_indication, error_status, error_index, var_binds = results

        if error_indication:
            # SNMP engine-level error.
            raise SNMPFailure(SNMP_FAILURE_MSG % ("GET", error_indication))

        if error_status:
            # SNMP PDU error.
            raise SNMPFailure(
                "SNMP operation '%(operation)s' failed: %(error)s at"
                " %(index)s" %
                {'operation': "GET", 'error': error_status.prettyPrint(),
                 'index':
                     error_index and var_binds[int(error_index) - 1]
                     or '?'})

        # We only expect a single value back
        name, val = var_binds[0]
        return val

    def get_next(self, oid):
        """Use PySNMP to perform an SNMP GET NEXT operation on a table object.

        :param oid: The OID of the object to get.
        :raises: SNMPFailure if an SNMP request fails.
        :returns: A list of values of the requested table object.
        """
        try:
            results = self.cmd_gen.nextCmd(self._get_auth(),
                                           self._get_transport(),
                                           oid)
        except snmp_error.PySnmpError as e:
            raise SNMPFailure(SNMP_FAILURE_MSG % ("GET_NEXT", e))

        error_indication, error_status, error_index, var_binds = results

        if error_indication:
            # SNMP engine-level error.
            raise SNMPFailure(
                SNMP_FAILURE_MSG % ("GET_NEXT", error_indication))

        if error_status:
            # SNMP PDU error.
            raise SNMPFailure(
                "SNMP operation '%(operation)s' failed: %(error)s at"
                " %(index)s" %
                {'operation': "GET_NEXT", 'error': error_status.prettyPrint(),
                 'index':
                     error_index and var_binds[int(error_index) - 1]
                     or '?'})

        return [val for row in var_binds for name, val in row]

    def set(self, oid, value):
        """Use PySNMP to perform an SNMP SET operation on a single object.

        :param oid: The OID of the object to set.
        :param value: The value of the object to set.
        :raises: SNMPFailure if an SNMP request fails.
        """
        try:
            results = self.cmd_gen.setCmd(self._get_auth(),
                                          self._get_transport(),
                                          (oid, value))
        except snmp_error.PySnmpError as e:
            raise SNMPFailure(SNMP_FAILURE_MSG % ("SET", e))

        error_indication, error_status, error_index, var_binds = results

        if error_indication:
            # SNMP engine-level error.
            raise SNMPFailure(SNMP_FAILURE_MSG % ("SET", error_indication))

        if error_status:
            # SNMP PDU error.
            raise SNMPFailure(
                "SNMP operation '%(operation)s' failed: %(error)s at"
                " %(index)s" %
                {'operation': "SET", 'error': error_status.prettyPrint(),
                 'index':
                     error_index and var_binds[int(error_index) - 1]
                     or '?'})
