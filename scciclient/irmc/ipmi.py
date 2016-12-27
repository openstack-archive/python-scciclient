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

import contextlib
import tempfile

from oslo_concurrency import processutils
from oslo_utils import excutils


class IPMIFailure(Exception):
    """IPMI Failure

    This exception is used when invalid inputs are passed to
    the APIs exposed by this module.
    """
    def __init__(self, message):
        super(IPMIFailure, self).__init__(message)


def exec_ipmitool(d_info, command):
    """Execute the ipmitool command.

    :param d_info: the ipmitool parameters for accessing a node.
    :param command: the ipmitool command to be executed.
    :returns: output from executing the command.
    :raises: PasswordFileFailedToCreate from creating or writing to the
             temporary file.
    :raises: processutils.ProcessExecutionError from executing the command.

    """
    args = ['ipmitool',
            '-I', 'lanplus',
            '-H', d_info['irmc_address'],
            '-U', d_info['irmc_username']
            ]

    password = d_info['irmc_password']
    tempdir = d_info['irmc_tempdir']
    with _make_password_file(password or '\0', tempdir) as pw_file:
        args.append('-f')
        args.append(pw_file)
        args.extend(command.split(" "))

        result = None
        try:
            out, err = processutils.execute(*args)
            if not err:
                result = out
        except processutils.ProcessExecutionError:
            pass
        return result


@contextlib.contextmanager
def _make_password_file(password, tempdir):
    """Makes a temporary file that contains the password.

    :param password: the password
    :param tempdir: the absolute location of the temporary file
    :returns: the absolute pathname of the temporary file
    :raises: PasswordFileFailedToCreate from creating or writing to the
             temporary file
    """
    f = None
    try:
        f = tempfile.NamedTemporaryFile(mode='w', dir=tempdir)
        f.write(str(password))
        f.flush()
    except (IOError, OSError) as exc:
        if f is not None:
            f.close()
        raise IPMIFailure("Failed to create the password file. %s" % exc)
    except Exception:
        with excutils.save_and_reraise_exception():
            if f is not None:
                f.close()

    try:
        # NOTE: This yield can not be in the try/except block above
        # because an exception by the caller of this function would then get
        # changed to a PasswordFileFailedToCreate exception which would mislead
        # about the problem and its cause.
        yield f.name
    finally:
        if f is not None:
            f.close()


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
    out = exec_ipmitool(d_info, cmd)

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
    # 01

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
            out = exec_ipmitool(d_info, cmd)

            if out is not None:
                for line in out.splitlines():
                    line = line.strip()
                    if len(line) >= 28:
                        pci_id = '0x%s%s/0x%s%s' % (line[21:23], line[18:20],
                                                    line[27:29], line[24:26])
                        if pci_id in gpu_id_list:
                            gpu_count += 1
                        if pci_id in fpga_id_list:
                            fpga_count += 1
                pci_dev += 1
            else:
                if pci_dev > 1:
                    break

    return gpu_count, fpga_count
