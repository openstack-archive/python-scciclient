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

import time

from pyghmi.ipmi import command as ipmi_command

# F1 1A - Get the number of GPU devices on PCI and the number of CPUs with FPGA
GET_GPU_FPGA = '0x2E 0xF1 0x80 0x28 0x00 0x1A %s 0x00'

# F5 81 - GET TPM STATUS
GET_TPM_STATUS = '0x2E 0xF5 0x80 0x28 0x00 0x81 0xC0'


class IPMIFailure(Exception):
    """IPMI Failure

    This exception is used when invalid inputs are passed to
    the APIs exposed by this module.
    """
    def __init__(self, message):
        super(IPMIFailure, self).__init__(message)


class PasswordFileFailedToCreate(Exception):
    """IPMI Failure

    This exception is used when invalid inputs are passed to
    the APIs exposed by this module.
    """
    def __init__(self, message):
        super(PasswordFileFailedToCreate, self).__init__(message)


def parse_raw_bytes(raw_bytes):
    """Convert a string of hexadecimal values to decimal values parameters for
     raw ipmi command.

    Example: '0x2E 0xF1 0x80 0x28 0x00 0x1A 0x01 0x00' is converted to:
              46, 241, [128, 40, 0, 26, 1, 0]

    :param raw_bytes: string of hexadecimal values
    :returns: 3 decimal values
    """
    bytes_list = [int(x, base=16) for x in raw_bytes.split()]
    return bytes_list[0], bytes_list[1], bytes_list[2:]


def send_raw_command(ipmicmd, raw_bytes):
    """Use IPMI command object to send raw ipmi command to BMC

    :param ipmicmd: IPMI command object
    :param raw_bytes: string of hexadecimal values. This is commonly used
        for certain vendor specific commands.
    :returns: dict -- The response from IPMI device
    """
    netfn, command, data = parse_raw_bytes(raw_bytes)
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

    response = send_raw_command(ipmicmd, GET_TPM_STATUS)
    out = ' '.join('{:02x}'.format(x) for x in response['data'])
    if out is not None and out[-5:] == 'C0 C0':
        return True
    else:
        return False


def get_gpu_fpgas(d_info, gpu_ids, fpga_ids):
    """Get quantity of GPU devices on PCI and quantity of CPUs with FPGA.

    Get quantity of GPU devices on PCI and quantity of CPUs with FPGA of the
    node.

    :param d_info: the list of ipmitool parameters for accessing a node.
    :param gpu_ids: the list contains pairs of <vendorID>/<deviceID> for GPU
    :param fpga_ids: the list contains pairs of <vendorID>/<deviceID> for CPUs
    with FPGA.
    :returns: quantity of GPU devices on PCI and quantity of CPUs with FPGA.
    """

    # note:
    # Get quantity of GPU devices on PCI and quantity of CPUs with FPGA:
    # ipmi cmd '0xF1'
    #
    # $ ipmitool raw 0x2E 0xF1 0x80 0x28 0x00 0x1A 0x01 0x00
    #
    # Raw response:
    # 80 28 00 00 00 05 data1 data2 34 17 76 11 00 04
    # 01

    # data1: 2 octet of VendorID
    # data2: 2 octet of DeviceID

    gpu_count = 0
    fpga_count = 0

    ipmicmd = ipmi_command.Command(bmc=d_info['irmc_address'],
                                   userid=d_info['irmc_username'],
                                   password=d_info['irmc_password'])

    if gpu_ids and fpga_ids:
        # check gpu_ids and fpga_ids parameters in /etc/ironic.conf
        gpu_id_list = gpu_ids.split(',')
        fpga_id_list = fpga_ids.split(',')
        record_id = 1
        while True:
            # Sometime the server started but PCI device list building is
            # still in progress so system will response error. We have to wait
            # for some more seconds.
            time.sleep(1)
            response = send_raw_command(
                ipmicmd, GET_GPU_FPGA % "0x{:02x}".format(record_id))

            if response.get('error') is None:
                hex_array = ["{:02x}".format(int(x)) for x in response['data']]
                line = ' '.join(hex_array)
                # if system return value, record id will be increased.
                if len(line) >= 28:
                    pci_id = '0x%s%s/0x%s%s' % (line[21:23], line[18:20],
                                                line[27:29], line[24:26])
                    if pci_id in gpu_id_list:
                        gpu_count += 1
                    if pci_id in fpga_id_list:
                        fpga_count += 1
                record_id += 1
            else:
                # Quit if record id is higher than 1 and system returns error
                if record_id > 1:
                    break

    return gpu_count, fpga_count
