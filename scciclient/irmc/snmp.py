# Copyright 2016 FUJITSU LIMITED
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
NOTE THAT CERTAIN DISTROS MAY INSTALL openipmi BY DEFAULT, INSTEAD OF ipmitool,
WHICH PROVIDES DIFFERENT COMMAND-LINE OPTIONS AND *IS NOT SUPPORTED* BY THIS
DRIVER.
"""

import six


BMC_NAME_OID = '1.3.6.1.4.1.231.2.10.2.2.10.3.4.1.3.1.1'
IRMC_FW_VERSION_OID = '1.3.6.1.4.1.231.2.10.2.2.10.3.4.1.4.1.1'
BIOS_FW_VERSION_OID = '1.3.6.1.4.1.231.2.10.2.2.10.4.1.1.11.1'
SERVER_MODEL_OID = '1.3.6.1.4.1.231.2.10.2.2.10.2.3.1.4.1'


def get_irmc_firmware_version(snmp_client):
    """Get irmc firmware version of the node.

    :param snmp_client: an SNMP client object.
    :raises: SNMPFailure if SNMP operation failed.
    :returns: a string of bmc name and irmc firmware version.
    """

    bmc_name = snmp_client.get(BMC_NAME_OID)
    irmc_firm_ver = snmp_client.get(IRMC_FW_VERSION_OID)

    return ('%(bmc)s%(sep)s%(firm_ver)s' %
            {'bmc': bmc_name if bmc_name else '',
             'firm_ver': irmc_firm_ver if irmc_firm_ver else '',
             'sep': '-' if bmc_name and irmc_firm_ver else ''})


def get_bios_firmware_version(snmp_client):
    """Get bios firmware version of the node.

    :param snmp_client: an SNMP client object.
    :raises: SNMPFailure if SNMP operation failed.
    :returns: a string of bios firmware version.
    """

    bios_firmware_version = snmp_client.get(BIOS_FW_VERSION_OID)
    return six.text_type(bios_firmware_version)


def get_server_model(snmp_client):
    """Get server model of the node.

    :param snmp_client: an SNMP client object.
    :raises: SNMPFailure if SNMP operation failed.
    :returns: a string of server model.
    """

    server_model = snmp_client.get(SERVER_MODEL_OID)
    return six.text_type(server_model)
