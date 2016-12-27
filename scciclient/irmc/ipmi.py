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

import subprocess

import six


BMC_NAME_OID = '1.3.6.1.4.1.231.2.10.2.2.10.3.4.1.3.1.1'
IRMC_FW_VERSION_OID = '1.3.6.1.4.1.231.2.10.2.2.10.3.4.1.4.1.1'
BIOS_FW_VERSION_OID = '1.3.6.1.4.1.231.2.10.2.2.10.4.1.1.11.1.1'
SERVER_MODEL_OID = '1.3.6.1.4.1.231.2.10.2.2.10.2.3.1.4.1'


def _exec_ipmitool(d_info, command):
    """Execute the ipmitool command.

    This uses the lanplus interface to communicate with the BMC device driver.

    :param d_info: the list of ipmitool parameters for accessing a node.
    :param command: the ipmitool command to be executed.
    """

    ipmi_cmd = ("ipmitool -H %(address)s"
                " -I lanplus -U %(user)s -P %(passwd)s %(cmd)s"
                % {'address': d_info['irmc_address'],
                   'user': d_info['irmc_username'],
                   'passwd': d_info['irmc_password'],
                   'cmd': command})

    out = None
    try:
        out = subprocess.check_output(ipmi_cmd, shell=True)
    except Exception:
        pass
    return out


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

    cmd = "raw 0x2E 0xF5 0x80 0x28 0x00 0x81 0xC0"
    out = _exec_ipmitool(d_info, cmd)

    if out is not None and out[-5:] == 'C0 C0':
        return True
    else:
        return False


def get_gpu_fpgas(d_info, gpu_ids, fpga_ids):
    """Get the number of GPU devices on PCI and number of CPUs with FPGA.

    Get the number of GPU devices on PCI and number of CPUs with FPGA of the
    node.

    :param d_info: the list of ipmitool parameters for accessing a node.
    :param gpu_ids: the list contains pairs of <vendorID>/<deviceID> for GPU
    :param fpga_ids: the list contains pairs of <vendorID>/<deviceID> for CPUs
    with FPGA
    :returns: number of GPU devices on PCI and number of CPUs with FPGA.
    """

    # note:
    # Get number of GPU devices on PCI and number of CPUs with FPGA:
    # ipmi cmd '0xF5'
    #
    # $ ipmitool raw 0x2E 0xF5 0x80 0x28 0x00 0x1A 0x01 0x00
    #
    # Raw response:
    # 80 28 00 00 00 05 data1 data2 34 17 76 11 00 04
    #
    # data1: 2 octet of VendorID
    # data2: 2 octet of DeviceID

    gpu_count = 0
    fpga_count = 0

    if gpu_ids and fpga_ids:
        # check gpu_ids and fpga_ids parameters in /etc/ironic.conf
        gpu_id_list = gpu_ids.split(',')
        fpga_id_list = fpga_ids.split(',')
        pci_dev = 1

        while True:
            cmd = ("raw 0x2E 0xF1 0x80 0x28 0x00 0x1A 0x" +
                   '{:02}'.format(pci_dev) + " 0x00")
            out = _exec_ipmitool(d_info, cmd)
            pci_dev += 1

            if out is None:
                break

            for line in out.splitlines():
                if len(line) > 22:
                    pci_id = ("0x" + line[22:24] + line[19:21] + '/' +
                              "0x" + line[28:30] + line[25:27])

                    if pci_id in gpu_id_list:
                        gpu_count += 1
                    if pci_id in fpga_id_list:
                        fpga_count += 1

    return gpu_count, fpga_count


def get_irmc_firmware_version(snmp_client):
    """Get irmc firmware version of the node.

    :param snmp_client: an SNMP client object.
    :raises: SNMPFailure if SNMP operation failed.
    :returns: a string of bmc name and irmc firmware version.
    """

    bmc_name = snmp_client.get(BMC_NAME_OID)
    irmc_firmware_version = snmp_client.get(IRMC_FW_VERSION_OID)
    return ('%(bmc)s-%(firm_ver)s' %
            {'bmc': bmc_name,
             'firm_ver': irmc_firmware_version})


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
