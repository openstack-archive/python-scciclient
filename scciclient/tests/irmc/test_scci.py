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
Test class for iRMC Power Driver
"""

import os
import time
import xml.etree.ElementTree as ET

import mock
from requests_mock.contrib import fixture as rm_fixture
import testtools

from scciclient.irmc import ipmi
from scciclient.irmc import scci
from scciclient.irmc import snmp


class SCCITestCase(testtools.TestCase):
    """Tests for SCCI

    Unit Test Cases for power on/off/reset, and mount cd/fd
    """

    def setUp(self):
        super(SCCITestCase, self).setUp()

        self.requests_mock = self.useFixture(rm_fixture.Fixture())

        with open(os.path.join(
                os.path.dirname(__file__),
                'fixtures/irmc_report_ok.xml'), "r") as report_ok:
            self.report_ok_txt = report_ok.read()
        self.report_ok_xml = ET.fromstring(self.report_ok_txt)

        with open(os.path.join(
                os.path.dirname(__file__),
                'fixtures/irmc_report_ng.xml'), "r") as report_ng:
            self.report_ng_txt = report_ng.read()
        self.report_ng_xml = ET.fromstring(self.report_ng_txt)

        self.irmc_address = '10.124.196.159'
        self.irmc_username = 'admin'
        self.irmc_password = 'admin0'
        self.irmc_port = 80
        self.irmc_auth_method = 'basic'
        self.irmc_client_timeout = 60
        self.irmc_info = {'irmc_address': self.irmc_address,
                          'irmc_username': self.irmc_username,
                          'irmc_password': self.irmc_password,
                          'irmc_snmp_port': 161,
                          'irmc_snmp_version': 'v2c',
                          'irmc_snmp_community': 'public',
                          'irmc_snmp_security': None,
                          'irmc_client_timeout': self.irmc_client_timeout,
                          'irmc_sensor_method': 'ipmitool',
                          'irmc_auth_method': self.irmc_auth_method,
                          'irmc_port': 443,
                          'irmc_tempdir': "/tmp"
                          }

        self.irmc_remote_image_server = '10.33.110.49'
        self.irmc_remote_image_user_domain = 'example.local'
        self.irmc_remote_image_share_type = scci.ShareType.nfs
        self.irmc_remote_image_share_name = 'share'
        self.irmc_remote_image_deploy_iso = 'ubuntu-14.04.1-server-amd64.iso'
        self.irmc_remote_image_username = 'deployer'
        self.irmc_remote_image_user_password = 'password'

    def test_get_share_type_ok(self):
        nfs_result = scci.get_share_type("nfs")
        self.assertEqual(scci.ShareType.nfs, nfs_result)
        cifs_result = scci.get_share_type("cifs")
        self.assertEqual(scci.ShareType.cifs, cifs_result)

        NFS_result = scci.get_share_type("NFS")
        self.assertEqual(scci.ShareType.nfs, NFS_result)
        CIFS_result = scci.get_share_type("CIFS")
        self.assertEqual(scci.ShareType.cifs, CIFS_result)

    def test_get_share_type_ng(self):
        self.assertRaises(KeyError,
                          scci.get_share_type,
                          "abc")

    @mock.patch('scciclient.irmc.scci.requests')
    def test_scci_cmd_protocol_https_ok(self, mock_requests):
        https_port = 443
        mock_requests.post.return_value = mock.Mock(
            return_value='ok',
            status_code=200,
            text="""<?xml version="1.0" encoding="UTF-8"?>
            <Status>
            <Value>0</Value>
            <Severity>Information</Severity>
            <Message>No Error</Message>
            </Status>""")
        returned_mock_requests_post = scci.scci_cmd(
            self.irmc_address,
            self.irmc_username,
            self.irmc_password,
            scci.POWER_ON,
            port=https_port,
            auth_method=self.irmc_auth_method,
            client_timeout=self.irmc_client_timeout)
        mock_requests.post.assert_called_with(
            'https://' + self.irmc_address + '/config',
            data=scci.POWER_ON,
            headers={'Content-type': 'application/x-www-form-urlencoded'},
            verify=False,
            timeout=self.irmc_client_timeout,
            allow_redirects=False,
            auth=mock_requests.auth.HTTPBasicAuth(self.irmc_username,
                                                  self.irmc_password))
        self.assertEqual('ok', returned_mock_requests_post.return_value)

    def test_scci_cmd_protocol_http_and_auth_basic_ok(self):
        self.requests_mock.post("http://" + self.irmc_address + "/config",
                                text="""<?xml version="1.0" encoding="UTF-8"?>
                                        <Status>
                                            <Value>0</Value>
                                            <Severity>Information</Severity>
                                            <Message>No Error</Message>
                                        </Status>""")

        r = scci.scci_cmd(self.irmc_address,
                          self.irmc_username,
                          self.irmc_password,
                          scci.POWER_ON,
                          port=self.irmc_port,
                          auth_method=self.irmc_auth_method,
                          client_timeout=self.irmc_client_timeout)
        self.assertEqual(r.status_code, 200)

    def test_scci_cmd_protocol_http_and_auth_digest_ok(self):
        self.requests_mock.post("http://" + self.irmc_address + "/config",
                                text="""<?xml version="1.0" encoding="UTF-8"?>
                                     <Status>
                                         <Value>0</Value>
                                         <Severity>Information</Severity>
                                         <Message>No Error</Message>
                                     </Status>""")

        auth_digest = 'digest'
        r = scci.scci_cmd(self.irmc_address,
                          self.irmc_username,
                          self.irmc_password,
                          scci.POWER_ON,
                          port=self.irmc_port,
                          auth_method=auth_digest,
                          client_timeout=self.irmc_client_timeout)
        self.assertEqual(r.status_code, 200)

    def test_scci_cmd_authentication_failure(self):
        self.requests_mock.post("http://" + self.irmc_address + "/config",
                                text="401 Unauthorized",
                                status_code=401)

        e = self.assertRaises(scci.SCCIClientError,
                              scci.scci_cmd,
                              self.irmc_address,
                              self.irmc_username,
                              self.irmc_password,
                              scci.POWER_ON,
                              port=self.irmc_port,
                              auth_method=self.irmc_auth_method,
                              client_timeout=self.irmc_client_timeout)

        self.assertEqual(
            'HTTP PROTOCOL ERROR, STATUS CODE = 401',
            str(e))

    def test_scci_cmd_protocol_ng(self):
        ssh_port = 22
        e = self.assertRaises(scci.SCCIInvalidInputError,
                              scci.scci_cmd,
                              self.irmc_address,
                              self.irmc_username,
                              self.irmc_password,
                              scci.POWER_ON,
                              port=ssh_port,
                              auth_method=self.irmc_auth_method,
                              client_timeout=self.irmc_client_timeout)
        self.assertEqual((("Invalid port %(port)d or "
                           "auth_method for method %(auth_method)s") %
                          {'port': ssh_port,
                           'auth_method': self.irmc_auth_method}), str(e))

    def test_scci_cmd_auth_method_ng(self):
        unknown_auth_method = 'unknown'
        e = self.assertRaises(scci.SCCIInvalidInputError,
                              scci.scci_cmd,
                              self.irmc_address,
                              self.irmc_username,
                              self.irmc_password,
                              scci.POWER_ON,
                              port=self.irmc_port,
                              auth_method=unknown_auth_method,
                              client_timeout=self.irmc_client_timeout)
        self.assertEqual(("Invalid port %(port)d or "
                          "auth_method for method %(auth_method)s") %
                         {'port': self.irmc_port,
                          'auth_method': unknown_auth_method}, str(e))

    def test_power_on_scci_xml_parse_failed(self):
        self.requests_mock.post(
            "http://" + self.irmc_address + "/config",
            text="""<?xml version="1.0" encoding="UTF-8"?>
            <Status>
            <Value>31</Value>
            <Severity>Error</Severity>
            <Message>Error 31 (Import of settings in WinSCU XML format failed)
            occurred</Message>
            <Error Context="SCCI" OC="0" OE="0" OI="0">
            XML parser creation failed (Error parsing:
            attribute value should start with a quote
            SEQ>  <CMD Context="SCCI" OC=PowerOnCabinet OE="0" OI="0"
            -----------------------------^------------------------------).
            </Error>
            </Status>""")

        client = scci.get_client(self.irmc_address,
                                 self.irmc_username,
                                 self.irmc_password,
                                 port=self.irmc_port,
                                 auth_method=self.irmc_auth_method,
                                 client_timeout=self.irmc_client_timeout)

        e = self.assertRaises(scci.SCCIClientError,
                              client,
                              scci.POWER_ON)
        self.assertEqual(
            'not well-formed (invalid token): line 10, column 41',
            str(e))

    def test_power_on_http_failed(self):
        self.requests_mock.post("http://" + self.irmc_address + "/config",
                                text="anything",
                                status_code=302)

        client = scci.get_client(self.irmc_address,
                                 self.irmc_username,
                                 self.irmc_password,
                                 port=self.irmc_port,
                                 auth_method=self.irmc_auth_method,
                                 client_timeout=self.irmc_client_timeout)

        e = self.assertRaises(scci.SCCIClientError,
                              client,
                              scci.POWER_ON)
        self.assertEqual(
            'HTTP PROTOCOL ERROR, STATUS CODE = 302',
            str(e))

    def test_power_on_ok(self):
        self.requests_mock.post("http://" + self.irmc_address + "/config",
                                text="""<?xml version="1.0" encoding="UTF-8"?>
                                <Status>
                                    <Value>0</Value>
                                    <Severity>Information</Severity>
                                    <Message>No Error</Message>
                                </Status>""")

        client = scci.get_client(self.irmc_address,
                                 self.irmc_username,
                                 self.irmc_password,
                                 port=self.irmc_port,
                                 auth_method=self.irmc_auth_method,
                                 client_timeout=self.irmc_client_timeout)
        r = client(scci.POWER_ON)
        self.assertEqual(r.status_code, 200)

    def test_power_off_ok(self):
        self.requests_mock.post("http://" + self.irmc_address + "/config",
                                text="""<?xml version="1.0" encoding="UTF-8"?>
                                <Status>
                                    <Value>0</Value>
                                    <Severity>Information</Severity>
                                    <Message>No Error</Message>
                                </Status>""")

        client = scci.get_client(self.irmc_address,
                                 self.irmc_username,
                                 self.irmc_password,
                                 port=self.irmc_port,
                                 auth_method=self.irmc_auth_method,
                                 client_timeout=self.irmc_client_timeout)
        r = client(scci.POWER_OFF)
        self.assertEqual(r.status_code, 200)

    def test_power_cycle_ok(self):
        self.requests_mock.post("http://" + self.irmc_address + "/config",
                                text="""<?xml version="1.0" encoding="UTF-8"?>
                                <Status>
                                    <Value>0</Value>
                                    <Severity>Information</Severity>
                                    <Message>No Error</Message>
                                </Status>""")

        client = scci.get_client(self.irmc_address,
                                 self.irmc_username,
                                 self.irmc_password,
                                 port=self.irmc_port,
                                 auth_method=self.irmc_auth_method,
                                 client_timeout=self.irmc_client_timeout)
        r = client(scci.POWER_CYCLE)
        self.assertEqual(r.status_code, 200)

    def test_power_reset_ok(self):
        self.requests_mock.post("http://" + self.irmc_address + "/config",
                                text="""<?xml version="1.0" encoding="UTF-8"?>
                                <Status>
                                    <Value>0</Value>
                                    <Severity>Information</Severity>
                                    <Message>No Error</Message>
                                </Status>""")

        client = scci.get_client(self.irmc_address,
                                 self.irmc_username,
                                 self.irmc_password,
                                 port=self.irmc_port,
                                 auth_method=self.irmc_auth_method,
                                 client_timeout=self.irmc_client_timeout)
        r = client(scci.POWER_RESET)
        self.assertEqual(r.status_code, 200)

    def test_power_raise_nmi_ok(self):
        self.requests_mock.post("http://" + self.irmc_address + "/config",
                                text="""<?xml version="1.0" encoding="UTF-8"?>
                                <Status>
                                    <Value>0</Value>
                                    <Severity>Information</Severity>
                                    <Message>No Error</Message>
                                </Status>""")

        client = scci.get_client(self.irmc_address,
                                 self.irmc_username,
                                 self.irmc_password,
                                 port=self.irmc_port,
                                 auth_method=self.irmc_auth_method,
                                 client_timeout=self.irmc_client_timeout)
        r = client(scci.POWER_RAISE_NMI)
        self.assertEqual(r.status_code, 200)

    def test_power_soft_off_ok(self):
        self.requests_mock.post("http://" + self.irmc_address + "/config",
                                text="""<?xml version="1.0" encoding="UTF-8"?>
                                <Status>
                                    <Value>0</Value>
                                    <Severity>Information</Severity>
                                    <Message>No Error</Message>
                                </Status>""")

        client = scci.get_client(self.irmc_address,
                                 self.irmc_username,
                                 self.irmc_password,
                                 port=self.irmc_port,
                                 auth_method=self.irmc_auth_method,
                                 client_timeout=self.irmc_client_timeout)
        r = client(scci.POWER_SOFT_OFF)
        self.assertEqual(r.status_code, 200)

    def test_power_soft_off_ng(self):
        self.requests_mock.post(
            "http://" + self.irmc_address + "/config",
            text="""<?xml version="1.0" encoding="UTF-8"?>
            <Status>
            <Value>31</Value>
            <Severity>Error</Severity>
            <Message>Error 31 (Import of settings in WinSCU"""
            """ XML format failed) occurred</Message>
            <Error Context="SCCI" OC="ShutdownRequestCancelled"
             OE="0" OI="0">ServerView Agent not connected</Error>
            </Status>""")

        client = scci.get_client(self.irmc_address,
                                 self.irmc_username,
                                 self.irmc_password,
                                 port=self.irmc_port,
                                 auth_method=self.irmc_auth_method,
                                 client_timeout=self.irmc_client_timeout)
        e = self.assertRaises(scci.SCCIClientError,
                              client,
                              scci.POWER_SOFT_OFF)
        self.assertEqual(
            'SCCI PROTOCOL ERROR, STATUS CODE = 31,'
            ' ERROR = ServerView Agent not connected, MESSAGE = Error 31'
            ' (Import of settings in WinSCU XML format failed) occurred',
            str(e))

    def test_power_soft_cycle_ok(self):
        self.requests_mock.post("http://" + self.irmc_address + "/config",
                                text="""<?xml version="1.0" encoding="UTF-8"?>
                                <Status>
                                    <Value>0</Value>
                                    <Severity>Information</Severity>
                                    <Message>No Error</Message>
                                </Status>""")

        client = scci.get_client(self.irmc_address,
                                 self.irmc_username,
                                 self.irmc_password,
                                 port=self.irmc_port,
                                 auth_method=self.irmc_auth_method,
                                 client_timeout=self.irmc_client_timeout)
        r = client(scci.POWER_SOFT_CYCLE)
        self.assertEqual(r.status_code, 200)

    def test_power_soft_cycle_ng(self):
        self.requests_mock.post(
            "http://" + self.irmc_address + "/config",
            text="""<?xml version="1.0" encoding="UTF-8"?>
            <Status>
            <Value>31</Value>
            <Severity>Error</Severity>
            <Message>Error 31 (Import of settings in WinSCU"""
            """ XML format failed) occurred</Message>
            <Error Context="SCCI" OC="ShutdownRequestCancelled"
             OE="0" OI="0">ServerView Agent not connected</Error>
            </Status>""")

        client = scci.get_client(self.irmc_address,
                                 self.irmc_username,
                                 self.irmc_password,
                                 port=self.irmc_port,
                                 auth_method=self.irmc_auth_method,
                                 client_timeout=self.irmc_client_timeout)
        e = self.assertRaises(scci.SCCIClientError,
                              client,
                              scci.POWER_SOFT_CYCLE)
        self.assertEqual(
            'SCCI PROTOCOL ERROR, STATUS CODE = 31,'
            ' ERROR = ServerView Agent not connected, MESSAGE = Error 31'
            ' (Import of settings in WinSCU XML format failed) occurred',
            str(e))

    def test_power_cancel_shutdown_ok(self):
        self.requests_mock.post("http://" + self.irmc_address + "/config",
                                text="""<?xml version="1.0" encoding="UTF-8"?>
                                <Status>
                                    <Value>0</Value>
                                    <Severity>Information</Severity>
                                    <Message>No Error</Message>
                                </Status>""")

        client = scci.get_client(self.irmc_address,
                                 self.irmc_username,
                                 self.irmc_password,
                                 port=self.irmc_port,
                                 auth_method=self.irmc_auth_method,
                                 client_timeout=self.irmc_client_timeout)
        r = client(scci.POWER_CANCEL_SHUTDOWN)
        self.assertEqual(r.status_code, 200)

    def test_power_cancel_shutdown_ng(self):
        self.requests_mock.post(
            "http://" + self.irmc_address + "/config",
            text="""<?xml version="1.0" encoding="UTF-8"?>
            <Status>
            <Value>31</Value>
            <Severity>Error</Severity>
            <Message>Error 31 (Import of settings in WinSCU"""
            """ XML format failed) occurred</Message>
            <Error Context="SCCI" OC="ShutdownRequestCancelled"
             OE="0" OI="0">ServerView Agent not connected</Error>
            </Status>""")

        client = scci.get_client(self.irmc_address,
                                 self.irmc_username,
                                 self.irmc_password,
                                 port=self.irmc_port,
                                 auth_method=self.irmc_auth_method,
                                 client_timeout=self.irmc_client_timeout)
        e = self.assertRaises(scci.SCCIClientError,
                              client,
                              scci.POWER_CANCEL_SHUTDOWN)
        self.assertEqual(
            'SCCI PROTOCOL ERROR, STATUS CODE = 31,'
            ' ERROR = ServerView Agent not connected, MESSAGE = Error 31'
            ' (Import of settings in WinSCU XML format failed) occurred',
            str(e))

    def test_get_sensor_data_records_ok(self):
        sensor = scci.get_sensor_data_records(self.report_ok_xml)
        self.assertEqual(len(sensor), 10)

    def test_get_sensor_data_records_ng(self):
        sensor = scci.get_sensor_data_records(self.report_ng_xml)
        self.assertEqual(sensor, None)

    def test_get_irmc_version_ok(self):
        version = scci.get_irmc_version(self.report_ok_xml)
        self.assertEqual(version.attrib['Name'], "iRMC S4")

    def test_get_irmc_version_ng(self):
        version = scci.get_irmc_version(self.report_ng_xml)
        self.assertEqual(version, None)

    def test_get_report_ok(self):
        self.requests_mock.get(
            "http://" + self.irmc_address + "/report.xml",
            text=self.report_ok_txt,
            headers={'Content-Type': "application/x-www-form-urlencoded"})

        root = scci.get_report(self.irmc_address,
                               self.irmc_username,
                               self.irmc_password,
                               port=self.irmc_port,
                               auth_method=self.irmc_auth_method,
                               client_timeout=self.irmc_client_timeout)

        self.assertEqual(root.tag, 'Root')

        sensor = scci.get_sensor_data_records(root)
        self.assertEqual(sensor.tag, 'SensorDataRecords')

    def test_get_report_http_failed(self):
        self.requests_mock.get(
            "http://" + self.irmc_address + "/report.xml",
            text=self.report_ok_txt,
            headers={'Content-Type': "application/x-www-form-urlencoded"},
            status_code=302)

        e = self.assertRaises(scci.SCCIClientError,
                              scci.get_report,
                              self.irmc_address,
                              self.irmc_username,
                              self.irmc_password,
                              port=self.irmc_port,
                              auth_method=self.irmc_auth_method,
                              client_timeout=self.irmc_client_timeout)
        self.assertEqual(
            'HTTP PROTOCOL ERROR, STATUS CODE = 302',
            str(e))

    @mock.patch.object(time, 'sleep')
    def test_virtual_media_cd_setting_ok(self, sleep_mock):
        self.requests_mock.post("http://" + self.irmc_address + "/config",
                                text="""<?xml version="1.0" encoding="UTF-8"?>
                                <Status>
                                    <Value>0</Value>
                                    <Severity>Information</Severity>
                                    <Message>No Error</Message>
                                </Status>""")

        cmd = scci.get_virtual_cd_set_params_cmd(
            self.irmc_remote_image_server,
            self.irmc_remote_image_user_domain,
            self.irmc_remote_image_share_type,
            self.irmc_remote_image_share_name,
            self.irmc_remote_image_deploy_iso,
            self.irmc_remote_image_username,
            self.irmc_remote_image_user_password)
        client = scci.get_client(self.irmc_address,
                                 self.irmc_username,
                                 self.irmc_password,
                                 port=self.irmc_port,
                                 auth_method=self.irmc_auth_method,
                                 client_timeout=self.irmc_client_timeout)

        r = client(cmd, async=False)
        self.assertEqual(r.status_code, 200)
        sleep_mock.assert_called_once_with(5)

    @mock.patch.object(time, 'sleep')
    def test_virtual_media_fd_setting_ok(self, sleep_mock):
        self.requests_mock.post("http://" + self.irmc_address + "/config",
                                text="""<?xml version="1.0" encoding="UTF-8"?>
                                <Status>
                                    <Value>0</Value>
                                    <Severity>Information</Severity>
                                    <Message>No Error</Message>
                                </Status>""")

        cmd = scci.get_virtual_fd_set_params_cmd(
            self.irmc_remote_image_server,
            self.irmc_remote_image_user_domain,
            self.irmc_remote_image_share_type,
            self.irmc_remote_image_share_name,
            'floppy1.flp',
            self.irmc_remote_image_username,
            self.irmc_remote_image_user_password)
        client = scci.get_client(self.irmc_address,
                                 self.irmc_username,
                                 self.irmc_password,
                                 port=self.irmc_port,
                                 auth_method=self.irmc_auth_method,
                                 client_timeout=self.irmc_client_timeout)
        r = client(cmd, async=False)
        self.assertEqual(r.status_code, 200)
        sleep_mock.assert_called_once_with(5)

    @mock.patch.object(time, 'sleep')
    def test_mount_cd_ok(self, sleep_mock):
        self.requests_mock.post("http://" + self.irmc_address + "/config",
                                text="""<?xml version="1.0" encoding="UTF-8"?>
                                <Status>
                                    <Value>0</Value>
                                    <Severity>Information</Severity>
                                    <Message>No Error</Message>
                                </Status>""")

        client = scci.get_client(self.irmc_address,
                                 self.irmc_username,
                                 self.irmc_password,
                                 port=self.irmc_port,
                                 auth_method=self.irmc_auth_method,
                                 client_timeout=self.irmc_client_timeout)
        r = client(scci.MOUNT_CD)
        self.assertEqual(r.status_code, 200)
        self.assertFalse(sleep_mock.called)

    @mock.patch.object(time, 'sleep')
    def test_mount_fd_ok(self, sleep_mock):
        self.requests_mock.post("http://" + self.irmc_address + "/config",
                                text="""<?xml version="1.0" encoding="UTF-8"?>
                                <Status>
                                    <Value>0</Value>
                                    <Severity>Information</Severity>
                                    <Message>No Error</Message>
                                </Status>""")

        client = scci.get_client(self.irmc_address,
                                 self.irmc_username,
                                 self.irmc_password,
                                 port=self.irmc_port,
                                 auth_method=self.irmc_auth_method,
                                 client_timeout=self.irmc_client_timeout)
        r = client(scci.MOUNT_FD)
        self.assertEqual(r.status_code, 200)
        self.assertFalse(sleep_mock.called)

    def test_unmount_cd_ok(self):
        self.requests_mock.post("http://" + self.irmc_address + "/config",
                                text="""<?xml version="1.0" encoding="UTF-8"?>
                                <Status>
                                <Value>0</Value>
                                <Severity>Information</Severity>
                                <Message>No Error</Message>
                                </Status>""")

        client = scci.get_client(self.irmc_address,
                                 self.irmc_username,
                                 self.irmc_password,
                                 port=self.irmc_port,
                                 auth_method=self.irmc_auth_method,
                                 client_timeout=self.irmc_client_timeout)
        r = client(scci.UNMOUNT_CD)
        self.assertEqual(r.status_code, 200)

    def test_unmount_fd_ok(self):
        self.requests_mock.post("http://" + self.irmc_address + "/config",
                                text="""<?xml version="1.0" encoding="UTF-8"?>
                                <Status>
                                    <Value>0</Value>
                                    <Severity>Information</Severity>
                                    <Message>No Error</Message>
                                </Status>""")

        client = scci.get_client(self.irmc_address,
                                 self.irmc_username,
                                 self.irmc_password,
                                 port=self.irmc_port,
                                 auth_method=self.irmc_auth_method,
                                 client_timeout=self.irmc_client_timeout)
        r = client(scci.MOUNT_FD)
        self.assertEqual(r.status_code, 200)

    def test_get_essential_properties(self):
        ESSENTIAL_PROPERTIES_KEYS = {
            'memory_mb', 'local_gb', 'cpus', 'cpu_arch'}
        expected = {'memory_mb': 8192,
                    'local_gb': 185,
                    'cpus': 16,
                    'cpu_arch': 'x86_64'}

        result = scci.get_essential_properties(
            self.report_ok_xml, ESSENTIAL_PROPERTIES_KEYS)

        self.assertEqual(expected, result)

    def test_get_essential_properties_empty_cpu_socket(self):
        ESSENTIAL_PROPERTIES_KEYS = {
            'memory_mb', 'local_gb', 'cpus', 'cpu_arch'}
        expected = {'memory_mb': 8192,
                    'local_gb': 185,
                    'cpus': 16,
                    'cpu_arch': 'x86_64'}

        result = scci.get_essential_properties(
            self.report_ng_xml, ESSENTIAL_PROPERTIES_KEYS)

        self.assertEqual(expected, result)

    @mock.patch.object(ipmi, 'get_gpu')
    @mock.patch.object(snmp, 'get_server_model')
    @mock.patch.object(snmp, 'get_irmc_firmware_version')
    @mock.patch.object(snmp, 'get_bios_firmware_version')
    @mock.patch.object(ipmi, 'get_tpm_status')
    def test_get_capabilities_properties(self,
                                         tpm_mock,
                                         bios_mock,
                                         irmc_mock,
                                         server_mock,
                                         gpu_mock):
        capabilities_properties = {'trusted_boot', 'irmc_firmware_version',
                                   'rom_firmware_version', 'server_model',
                                   'pci_gpu_devices'}
        gpu_ids = ['0x1000/0x0079', '0x2100/0x0080']
        kwargs = {}
        kwargs['sleep_flag'] = True

        tpm_mock.return_value = False
        bios_mock.return_value = 'V4.6.5.4 R1.15.0 for D3099-B1x'
        irmc_mock.return_value = 'iRMC S4-7.82F'
        server_mock.return_value = 'TX2540M1F5'
        gpu_mock.return_value = 1

        expected = {'irmc_firmware_version': 'iRMC S4-7.82F',
                    'pci_gpu_devices': 1,
                    'rom_firmware_version': 'V4.6.5.4 R1.15.0 for D3099-B1x',
                    'server_model': 'TX2540M1F5',
                    'trusted_boot': False}

        result = scci.get_capabilities_properties(
            self.irmc_info,
            capabilities_properties,
            gpu_ids,
            **kwargs)

        self.assertEqual(expected, result)
        tpm_mock.assert_called_once_with(self.irmc_info)
        bios_mock.assert_called_once_with(mock.ANY)
        irmc_mock.assert_called_once_with(mock.ANY)
        server_mock.assert_called_once_with(mock.ANY)
        gpu_mock.assert_called_once_with(self.irmc_info,
                                         gpu_ids)

    @mock.patch.object(ipmi, 'get_gpu')
    @mock.patch.object(snmp, 'get_server_model')
    @mock.patch.object(snmp, 'get_irmc_firmware_version')
    @mock.patch.object(snmp, 'get_bios_firmware_version')
    @mock.patch.object(ipmi, 'get_tpm_status')
    def test_get_capabilities_properties_blank(self,
                                               tpm_mock,
                                               bios_mock,
                                               irmc_mock,
                                               server_mock,
                                               gpu_mock):

        capabilities_properties = {}
        gpu_ids = ['0x1000/0x0079', '0x2100/0x0080']
        kwargs = {}
        kwargs['sleep_flag'] = True

        tpm_mock.return_value = False
        bios_mock.return_value = 'V4.6.5.4 R1.15.0 for D3099-B1x'
        irmc_mock.return_value = 'iRMC S4-7.82F'
        server_mock.return_value = 'TX2540M1F5'
        gpu_mock.return_value = 1

        expected = {}

        result = scci.get_capabilities_properties(
            self.irmc_info,
            capabilities_properties,
            gpu_ids,
            **kwargs)

        self.assertEqual(expected, result)

    @mock.patch.object(ipmi, '_send_raw_command')
    @mock.patch.object(snmp.SNMPClient, 'get')
    def test_get_capabilities_properties_scci_client_error(self,
                                                           snmp_mock,
                                                           ipmiraw_mock):
        capabilities_properties = {'trusted_boot', 'irmc_firmware_version',
                                   'rom_firmware_version', 'server_model',
                                   'pci_gpu_devices'}
        gpu_ids = ['0x1000/0x0079', '0x2100/0x0080']
        kwargs = {}
        kwargs['sleep_flag'] = True

        ipmiraw_mock.return_value = None
        snmp_mock.side_effect = snmp.SNMPFailure("error")

        e = self.assertRaises(scci.SCCIClientError,
                              scci.get_capabilities_properties,
                              self.irmc_info,
                              capabilities_properties,
                              gpu_ids,
                              **kwargs)
        self.assertEqual('Capabilities inspection failed: SNMP operation \''
                         'GET BIOS FIRMWARE VERSION\' failed: error', str(e))

    @mock.patch.object(ipmi, 'get_gpu')
    @mock.patch.object(snmp.SNMPClient, 'get')
    def test_get_capabilities_properties_scci_client_error_ipmi(self,
                                                                snmp_mock,
                                                                ipmi_mock):
        capabilities_properties = {'trusted_boot', 'irmc_firmware_version',
                                   'rom_firmware_version', 'server_model',
                                   'pci_gpu_devices'}
        gpu_ids = ['0x1000/0x0079', '0x2100/0x0080']
        kwargs = {}
        kwargs['sleep_flag'] = True

        ipmi_mock.side_effect = ipmi.IPMIFailure("IPMI error")
        snmp_mock.return_value = None

        e = self.assertRaises(scci.SCCIClientError,
                              scci.get_capabilities_properties,
                              self.irmc_info,
                              capabilities_properties,
                              gpu_ids,
                              **kwargs)
        self.assertEqual('Capabilities inspection failed: IPMI error', str(e))
