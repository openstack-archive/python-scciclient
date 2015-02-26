# Copyright 2015 FUJITSU LIMITED
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
SCCI functionalities shared between different iRMC modules.
"""

import functools
import xml.etree.ElementTree as ET

import requests


class SCCIError(Exception):
    """SCCI Error

    This exception is gerenral excetion.
    """
    def __init__(self, message, errorcode=None):
        super(SCCIError, self).__init__(message)


class SCCIInvalidInputError(SCCIError):
    """SCCIInvalidInputError

    This exception is used when invalid inputs are passed to
    the APIs exposed by this module.
    """
    def __init__(self, message):
        super(SCCIInvalidInputError, self).__init__(message)


class SCCIClientError(SCCIError):
    """SCCIClientError

    This exception is used when a problem is encountered in
    executing an operation on the iRMC
    """
    def __init__(self, message):
        super(SCCIClientError, self).__init__(message)


"""
List of iRMC S4 supported SCCI commands

SCCI
OpCode  SCCI Command String      Description
0xE002  ConfigSpace              ConfigSpace Write
0x0111  PowerOnCabinet           Power On the Server
0x0112  PowerOffCabinet          Power Off the Server
0x0113  PowerOffOnCabinet        Power Cycle the Server
0x0204  ResetServer              Hard Reset the Server
0x020C  RaiseNMI                 Pulse the NMI (Non Maskable Interrupt)
0x0205  RequestShutdownAndOff    Graceful Shutdown, requires running Agent
0x0206  RequestShutdownAndReset  Graceful Reboot, requires running Agent
0x0209  ShutdownRequestCancelled Cancel a Shutdown Request
0x0203  ResetFirmware  Perform a BMC Reset
0x0251  ConnectRemoteFdImage     Connect or Disconnect a Floppy Disk image on a
                                 Remote Image Mount (NFS or CIFS Share )
0x0252  ConnectRemoteCdImage     Connect or Disconnect a CD/DVD .iso image on a
                                 Remote Image Mount (NFS or CIFS Share )
0x0253  ConnectRemoteHdImage     Connect or Disconnect a Hard Disk image on a
                                 Remote Image Mount (NFS or CIFS Share )
"""

_POWER_CMD = '''
<?xml version="1.0" encoding="UTF-8" standalone="yes" ?>
<CMDSEQ>
  <CMD Context="SCCI" OC="%s" OE="0" OI="0" Type="SET">
  </CMD>
</CMDSEQ>
'''


POWER_ON = _POWER_CMD % "PowerOnCabinet"
POWER_OFF = _POWER_CMD % "PowerOffCabinet"
POWER_CYCLE = _POWER_CMD % "PowerOffOnCabinet"
POWER_RESET = _POWER_CMD % "ResetServer"


_VIRTUAL_MEDIA_CMD = '''
<?xml version="1.0" encoding="UTF-8" standalone="yes" ?>
<CMDSEQ>
  <CMD Context="SCCI" OC="%s" OE="0" OI="0" Type="SET">
    <DATA Type="xsd::integer">%d</DATA>
  </CMD>
</CMDSEQ>
'''


MOUNT_CD = _VIRTUAL_MEDIA_CMD % ("ConnectRemoteCdImage", 1)
UNMOUNT_CD = _VIRTUAL_MEDIA_CMD % ("ConnectRemoteCdImage", 0)
MOUNT_FD = _VIRTUAL_MEDIA_CMD % ("ConnectRemoteFdImage", 1)
UNMOUNT_FD = _VIRTUAL_MEDIA_CMD % ("ConnectRemoteFdImage", 0)


_VIRTUAL_MEDIA_CD_SETTINGS = '''
<?xml version="1.0" encoding="UTF-8" standalone="yes" ?>
<CMDSEQ>
  <!-- "ConfBmcMediaOptionsRemoteMediaEnabled" -->
  <!-- Make sure this one is enabled -->
  <CMD Context="SCCI" OC="ConfigSpace" OE="1A80" OI="0" Type="SET">
    <DATA Type="xsd::integer">1</DATA>
  </CMD>
  <!-- "ConfBmcMediaOptionsCdNumber" -->
  <!-- Number of emulated CDROM/DVD Devices -->
  <CMD Context="SCCI" OC="ConfigSpace" OE="1A68" OI="0" Type="SET">
    <DATA Type="xsd::integer">2</DATA>
  </CMD>
  <!-- "ConfBmcRemoteCdImageServer" -->
  <CMD Context="SCCI" OC="ConfigSpace" OE="1A60" OI="0" Type="SET">
    <DATA Type="xsd::string">%s</DATA>
  </CMD>
  <!-- "ConfBmcRemoteCdImageUserDomain" -->
  <CMD Context="SCCI" OC="ConfigSpace" OE="1A63" OI="0" Type="SET">
    <DATA Type="xsd::string">%s</DATA>
  </CMD>
  <!-- "ConfBmcRemoteCdImageShareType" -->
  <!-- 0 = NFS Share / 1 = CIFS Share -->
  <CMD Context="SCCI" OC="ConfigSpace" OE="1A64" OI="0" Type="SET">
    <DATA Type="xsd::integer">%d</DATA>
  </CMD>
  <!-- "ConfBmcRemoteCdImageShareName" -->
  <CMD Context="SCCI" OC="ConfigSpace" OE="1A65" OI="0" Type="SET">
    <DATA Type="xsd::string">%s</DATA>
  </CMD>
  <!-- "ConfBmcRemoteCdImageImageName" -->
  <CMD Context="SCCI" OC="ConfigSpace" OE="1A66" OI="0" Type="SET">
    <DATA Type="xsd::string">%s</DATA>
  </CMD>
  <!-- "ConfBmcRemoteCdImageUserName" -->
  <CMD Context="SCCI" OC="ConfigSpace" OE="1A61" OI="0" Type="SET">
    <DATA Type="xsd::string">%s</DATA>
  </CMD>
  <!-- "ConfBmcRemoteCdImageUserPassword" -->
  <CMD Context="SCCI" OC="ConfigSpace" OE="1A62" OI="0" Type="SET">
    <DATA Type="xsd::string" Encrypted="0">%s</DATA>
  </CMD>
</CMDSEQ>
'''


_VIRTUAL_MEDIA_FD_SETTINGS = '''
<?xml version="1.0" encoding="UTF-8" standalone="yes" ?>
<CMDSEQ>
  <!-- "ConfBmcMediaOptionsRemoteMediaEnabled" -->
  <!-- Make sure this one is enabled -->
  <CMD Context="SCCI" OC="ConfigSpace" OE="1A80" OI="0" Type="SET">
    <DATA Type="xsd::integer">1</DATA>
  </CMD>
  <!-- "ConfBmcMediaOptionsFdNumber" -->
  <!-- Number of emulated FD Devices -->
  <CMD Context="SCCI" OC="ConfigSpace" OE="1A58" OI="0" Type="SET">
    <DATA Type="xsd::integer">2</DATA>
  </CMD>
  <!-- "ConfBmcRemoteFdImageServer" -->
  <CMD Context="SCCI" OC="ConfigSpace" OE="1A50" OI="0" Type="SET">
    <DATA Type="xsd::string">%s</DATA>
  </CMD>
  <!-- "ConfBmcRemoteFdImageUserDomain" -->
  <CMD Context="SCCI" OC="ConfigSpace" OE="1A53" OI="0" Type="SET">
    <DATA Type="xsd::string">%s</DATA>
  </CMD>
  <!-- "ConfBmcRemoteFdImageShareType" -->
  <!-- 0 = NFS Share / 1 = CIFS Share -->
  <CMD Context="SCCI" OC="ConfigSpace" OE="1A54" OI="0" Type="SET">
    <DATA Type="xsd::integer">%d</DATA>
  </CMD>
  <!-- "ConfBmcRemoteFdImageShareName" -->
  <CMD Context="SCCI" OC="ConfigSpace" OE="1A55" OI="0" Type="SET">
    <DATA Type="xsd::string">%s</DATA>
  </CMD>
  <!-- "ConfBmcRemoteFdImageImageName" -->
  <CMD Context="SCCI" OC="ConfigSpace" OE="1A56" OI="0" Type="SET">
    <DATA Type="xsd::string">%s</DATA>
  </CMD>
  <!-- "ConfBmcRemoteFdImageUserName" -->
  <CMD Context="SCCI" OC="ConfigSpace" OE="1A51" OI="0" Type="SET">
    <DATA Type="xsd::string">%s</DATA>
  </CMD>
  <!-- "ConfBmcRemoteFdImageUserPassword" -->
  <CMD Context="SCCI" OC="ConfigSpace" OE="1A52" OI="0" Type="SET">
    <DATA Type="xsd::string" Encrypted="0">%s</DATA>
  </CMD>
</CMDSEQ>
'''


class SHARETYPE(object):
    """"Virtual Media Share Type."""
    NFS = 0
    CIFS = 1


def scci_cmd(host, userid, password, cmd,
             port=443, auth_method='basic', client_timeout=60):
    """execute SCCI command

    This function calls SCCI server modules
    :param host: hostname or IP of iRMC
    :param userid: userid for iRMC with administrator privileges
    :param password: password for userid
    :param cmd: SCCI command
    :param port: port number of iRMC
    :param auth_method: irmc_username
    :param client_timeout: timeout for SCCI operations
    :returns: requests.Response from SCCI server
    :raises: SCCIInvalidInputError if port and/or auth_method params
             are invalid
    :raises: SCCIClientError if SCCI failed
    """
    auth_obj = None
    try:
        protocol = {80: 'http', 443: 'https'}[port]
        auth_obj = {
            'basic': requests.auth.HTTPBasicAuth(userid, password),
            'digest': requests.auth.HTTPDigestAuth(userid, password)
        }[auth_method.lower()]

    except KeyError:
        raise SCCIInvalidInputError(
            ("Invalid port %(port)d or " +
             "auth_method for method %(auth_method)s") %
            {'port': port, 'auth_method': auth_method})

    try:
        header = {'Content-type': 'application/x-www-form-urlencoded'}
        r = requests.post(protocol + '://' + host + '/config',
                          data=cmd,
                          headers=header,
                          verify=False,
                          timeout=client_timeout,
                          allow_redirects=False,
                          auth=auth_obj)

        if r.status_code not in (200, 201):
            raise SCCIClientError(
                ('HTTP PROTOCOL ERROR, STATUS CODE = %s' %
                 str(r.status_code)))

        result_xml = ET.fromstring(r.text)
        status = result_xml.find("./Value")
        # severity = result_xml.find("./Severity")
        # message = result_xml.find("./Message")
        if not int(status.text) == 0:
            raise SCCIClientError(
                ('SCCI PROTOCOL ERROR, STATUS CODE = %s' %
                 str(status.text)))
        else:
            return r

    except ET.ParseError as parse_error:
        raise SCCIClientError(parse_error)

    except requests.exceptions.RequestException as requests_exception:
        raise SCCIClientError(requests_exception)


def get_client(host, userid, password,
               port=443, auth_method='basic', client_timeout=60):
    """get SCCI command partial function

    This function returs SCCI command partial function
    :param host: hostname or IP of iRMC
    :param userid: userid for iRMC with administrator privileges
    :param password: password for userid
    :param port: port number of iRMC
    :param auth_method: irmc_username
    :param client_timeout: timeout for SCCI operations
    :returns: scci_cmd partial function which takes a SCCI command param
    """

    return functools.partial(scci_cmd, host, userid, password,
                             port=port, auth_method=auth_method,
                             client_timeout=client_timeout)


def get_virtual_cd_set_params_cmd(remote_image_server,
                                  remote_image_user_domain,
                                  remote_image_share_type,
                                  remote_image_share_name,
                                  remote_image_deploy_iso,
                                  remote_image_username,
                                  remote_image_user_password):
    """get Virtual CD Media Set Parameters Command

    This function returs Virtual CD Media Set Parameters Command
    :param remote_image_server: remote image server name or IP
    :param remote_image_user_domain: domain name of remote image server
    :param remote_image_share_type: share type of SHARETYPE
    :param remote_image_share_name: share name
    :param remote_image_deploy_iso: deploy ISO image file name
    :param remote_image_username: username of remote image server
    :param remote_image_user_password: password of the username
    :returns: SCCI command
    """

    cmd = _VIRTUAL_MEDIA_CD_SETTINGS % (
        remote_image_server,
        remote_image_user_domain,
        remote_image_share_type,
        remote_image_share_name,
        remote_image_deploy_iso,
        remote_image_username,
        remote_image_user_password)

    return(cmd)


def get_virtual_fd_set_params_cmd(remote_image_server,
                                  remote_image_user_domain,
                                  remote_image_share_type,
                                  remote_image_share_name,
                                  remote_image_floppy_fat,
                                  remote_image_username,
                                  remote_image_user_password):
    """get Virtual FD Media Set Parameters Command

    This function returs Virtual FD Media Set Parameters Command
    :param remote_image_server: remote image server name or IP
    :param remote_image_user_domain: domain name of remote image server
    :param remote_image_share_type: share type of SHARETYPE
    :param remote_image_share_name: share name
    :param remote_image_deploy_iso: deploy ISO image file name
    :param remote_image_username: username of remote image server
    :param remote_image_user_password: password of the username
    :returns: SCCI command
    """
    cmd = _VIRTUAL_MEDIA_FD_SETTINGS % (
        remote_image_server,
        remote_image_user_domain,
        remote_image_share_type,
        remote_image_share_name,
        remote_image_floppy_fat,
        remote_image_username,
        remote_image_user_password)

    return(cmd)


def get_report(host, userid, password,
               port=443, auth_method='basic', client_timeout=60):
    """get iRMC report

    This function returns iRMC report in XML format
    :param host: hostname or IP of iRMC
    :param userid: userid for iRMC with administrator privileges
    :param password: password for userid
    :param port: port number of iRMC
    :param auth_method: irmc_username
    :param client_timeout: timeout for SCCI operations
    :returns: root element of SCCI report
    :raises: ISCCIInvalidInputError if port and/or auth_method params
             are invalid
    :raises: SCCIClientError if SCCI failed
    """

    auth_obj = None
    try:
        protocol = {80: 'http', 443: 'https'}[port]
        auth_obj = {
            'basic': requests.auth.HTTPBasicAuth(userid, password),
            'digest': requests.auth.HTTPDigestAuth(userid, password)
        }[auth_method.lower()]

    except KeyError:
        raise SCCIInvalidInputError(
            ("Invalid port %(port)d or " +
             "auth_method for method %(auth_method)s") %
            {'port': port, 'auth_method': auth_method})

    try:
        r = requests.get(protocol + '://' + host + '/report.xml',
                         verify=False,
                         timeout=(10, client_timeout),
                         allow_redirects=False,
                         auth=auth_obj)

        if r.status_code not in (200, 201):
            raise SCCIClientError(
                ('HTTP PROTOCOL ERROR, STATUS CODE = %s' %
                 str(r.status_code)))

        root = ET.fromstring(r.text)
        return root

    except ET.ParseError as parse_error:
        raise SCCIClientError(parse_error)

    except requests.exceptions.RequestException as requests_exception:
        raise SCCIClientError(requests_exception)


def get_sensor_data_records(report):
    """get sensor data

    This function returns sensor data in XML
    :param report: SCCI report element
    :returns: sensor element of SCCI report, or None
    """

    sensor = report.find("./System/SensorDataRecords")
    # ET.dump(sensor[0])
    return sensor


def get_irmc_version(report):
    """get iRMC version

    This function return iRMC version number
    :param report: SCCI report element
    :returns: version element of SCCI report, or None
    """

    version = report.find("./System/ManagementControllers/iRMC")
    # ET.dump(version[0])
    return version
