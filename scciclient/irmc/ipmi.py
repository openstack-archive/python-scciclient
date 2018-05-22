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

import functools
import itertools

from pyghmi import exceptions as ipmi_exception
from pyghmi.ipmi import command as ipmi_command

# F1 1A - Get the number of specific PCI devices on baremetal
GET_PCI = '0x2E 0xF1 0x80 0x28 0x00 0x1A %s 0x00'

# F5 81 - GET TPM STATUS
GET_TPM_STATUS = '0x2E 0xF5 0x80 0x28 0x00 0x81 0xC0'


class IPMIFailure(Exception):
    """IPMI Failure

    This exception is used when IPMI operation failed.
    """
    def __init__(self, message):
        super(IPMIFailure, self).__init__(message)


class InvalidParameterValue(IPMIFailure):
    """Invalid Parameter Value Failure

    This exception is used when invalid parameter values are passed to
    the APIs exposed by this module.
    """
    def __init__(self, message):
        super(InvalidParameterValue, self).__init__(message)


def _parse_raw_bytes(raw_bytes):
    """Convert a string of hexadecimal values to decimal values parameters

    Example: '0x2E 0xF1 0x80 0x28 0x00 0x1A 0x01 0x00' is converted to:
              46, 241, [128, 40, 0, 26, 1, 0]

    :param raw_bytes: string of hexadecimal values
    :returns: 3 decimal values
    """
    bytes_list = [int(x, base=16) for x in raw_bytes.split()]
    return bytes_list[0], bytes_list[1], bytes_list[2:]


def _send_raw_command(ipmicmd, raw_bytes):
    """Use IPMI command object to send raw ipmi command to BMC

    :param ipmicmd: IPMI command object
    :param raw_bytes: string of hexadecimal values. This is commonly used
        for certain vendor specific commands.
    :returns: dict -- The response from IPMI device
    """

    netfn, command, data = _parse_raw_bytes(raw_bytes)
    response = ipmicmd.raw_command(netfn, command, data=data)

    return response


def get_tpm_status(d_info):
    """Get the TPM support status.

    Get the TPM support status of the node.

    :param d_info: the list of ipmitool parameters for accessing a node.
    :returns: TPM support status
    """

    # note:
    # Get TPM support status : ipmi cmd '0xF5', valid flags '0xC0'
    #
    # $ ipmitool raw 0x2E 0xF5 0x80 0x28 0x00 0x81 0xC0
    #
    # Raw response:
    # 80 28 00 C0 C0: True
    # 80 28 00 -- --: False (other values than 'C0 C0')

    ipmicmd = ipmi_command.Command(bmc=d_info['irmc_address'],
                                   userid=d_info['irmc_username'],
                                   password=d_info['irmc_password'])
    try:
        response = _send_raw_command(ipmicmd, GET_TPM_STATUS)
        if response['code'] != 0:
            raise IPMIFailure(
                "IPMI operation '%(operation)s' failed: %(error)s" %
                {'operation': "GET TMP status",
                 'error': response.get('error')})
        out = ' '.join('{:02X}'.format(x) for x in response['data'])
        return out is not None and out[-5:] == 'C0 C0'

    except ipmi_exception.IpmiException as e:
        raise IPMIFailure(
            "IPMI operation '%(operation)s' failed: %(error)s" %
            {'operation': "GET TMP status", 'error': e})


def _pci_seq(ipmicmd):
    """Get output of ipmiraw command and the ordinal numbers.

    :param ipmicmd: IPMI command object.
    :returns: List of tuple contain ordinal number and output of ipmiraw
    command.
    """
    for i in range(1, 0xff + 1):
        try:
            res = _send_raw_command(ipmicmd, GET_PCI % hex(i))
            yield i, res
        except ipmi_exception.IpmiException as e:
            raise IPMIFailure(
                "IPMI operation '%(operation)s' failed: %(error)s" %
                {'operation': "GET PCI device quantity", 'error': e})


def get_pci_device(d_info, pci_device_ids):
    """Get quantity of PCI devices.

    Get quantity of PCI devices of the node.

    :param d_info: the list of ipmitool parameters for accessing a node.
    :param pci_device_ids: the list contains pairs of <vendorID>/<deviceID> for
    PCI devices.
    :returns: the number of PCI devices.
    """

    # note:
    # Get quantity of PCI devices:
    # ipmi cmd '0xF1'
    #
    # $ ipmitool raw 0x2E 0xF1 0x80 0x28 0x00 0x1A 0x01 0x00
    #
    # Raw response:
    # 80 28 00 00 00 05 data1 data2 34 17 76 11 00 04
    # 01

    # data1: 2 octet of VendorID
    # data2: 2 octet of DeviceID

    ipmicmd = ipmi_command.Command(bmc=d_info['irmc_address'],
                                   userid=d_info['irmc_username'],
                                   password=d_info['irmc_password'])

    response = itertools.takewhile(
        lambda y: (y[1]['code'] != 0xC9 and y[1].get('error') is None),
        _pci_seq(ipmicmd))

    def _pci_count(accm, v):
        out = v[1]['data']
        # if system returns value, record id will be increased.
        pci_id = "0x{:02x}{:02x}/0x{:02x}{:02x}".format(
            out[7], out[6], out[9], out[8])
        return accm + 1 if pci_id in pci_device_ids else accm

    device_count = functools.reduce(_pci_count, response, 0)

    return device_count
