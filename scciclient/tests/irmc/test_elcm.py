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
Test class for iRMC eLCM functionality.
"""

import mock
from oslo_utils import encodeutils
import requests
from requests_mock.contrib import fixture as rm_fixture
import testtools

from scciclient.irmc import elcm
from scciclient.irmc import scci


class ELCMTestCase(testtools.TestCase):
    """Tests for eLCM"""

    RESPONSE_TEMPLATE = ('Date: Mon, 07 Dec 2015 17:10:55 GMT\n'
                         'Server: iRMC S4 Webserver\n'
                         'Content-Length: 123\n'
                         'Content-Type: application/json; charset=UTF-8\n'
                         '\r\n'
                         '{\n'
                         '%(json_text)s\n'
                         '}')

    def setUp(self):
        super(ELCMTestCase, self).setUp()

        self.requests_mock = self.useFixture(rm_fixture.Fixture())

        self.irmc_info = {
            'irmc_address': '10.124.196.159',
            'irmc_username': 'admin',
            'irmc_password': 'admin0',
            'irmc_port': 80,
            'irmc_auth_method': 'basic',
            'irmc_client_timeout': 60,
        }

        self.raid_info = {
            'Server': {
                'HWConfigurationIrmc': {
                    'Adapters': {
                        'RAIDAdapter': [
                            {
                                'Arrays': None,
                                'LogicalDrives': None
                            }
                        ]
                    },
                    '@Version': '1.00'
                },
                '@Version': '1.01'
            }
        }

    def _create_server_url(self, path, port=None):
        scheme = 'unknown'

        if port is None:
            port = self.irmc_info['irmc_port']
        if port == 80:
            scheme = 'http'
        elif port == 443:
            scheme = 'https'

        return ('%(scheme)s://%(addr)s%(path)s' %
                {'scheme': scheme,
                 'addr': self.irmc_info['irmc_address'],
                 'path': path})

    def _create_server_response(self, content):
        response = requests.Response()
        response._content = encodeutils.safe_encode(content)
        response.encoding = 'utf-8'
        return response

    def test__parse_elcm_response_body_as_json_empty(self):
        response = self._create_server_response('')
        self.assertRaises(elcm.ELCMInvalidResponse,
                          elcm._parse_elcm_response_body_as_json,
                          response=response)

    def test__parse_elcm_response_body_as_json_invalid(self):
        content = 'abc123'
        response = self._create_server_response(content)
        self.assertRaises(elcm.ELCMInvalidResponse,
                          elcm._parse_elcm_response_body_as_json,
                          response=response)

    def test__parse_elcm_response_body_as_json_missing_empty_line(self):
        content = ('key1:val1\nkey2:val2\n'
                   '{"1":1,"2":[123, "abc"],"3":3}')
        response = self._create_server_response(content)
        self.assertRaises(elcm.ELCMInvalidResponse,
                          elcm._parse_elcm_response_body_as_json,
                          response=response)

    def test__parse_elcm_response_body_as_json_ok(self):
        content = ('key1:val1\nkey2:val2\n'
                   '\r\n'
                   '{"1":1,"2":[123, "abc"],"3":3}')
        response = self._create_server_response(content)
        result = elcm._parse_elcm_response_body_as_json(response)

        expected = {
            "1": 1,
            "2": [123, "abc"],
            "3": 3
        }
        self.assertEqual(expected, result)

    def test_elcm_request_protocol_http_ok(self):
        irmc_info = dict(self.irmc_info)
        irmc_info['irmc_port'] = 80

        self.requests_mock.register_uri(
            'GET',
            self._create_server_url(elcm.URL_PATH_PROFILE_MGMT,
                                    port=80),
            text=self.RESPONSE_TEMPLATE % {'json_text': 'abc123'})

        response = elcm.elcm_request(
            irmc_info,
            method='GET',
            path=elcm.URL_PATH_PROFILE_MGMT)

        self.assertEqual(200, response.status_code)

        expected = self.RESPONSE_TEMPLATE % {'json_text': 'abc123'}
        self.assertEqual(expected, response.text)

    def test_elcm_request_protocol_https_ok(self):
        irmc_info = dict(self.irmc_info)
        irmc_info['irmc_port'] = 443

        self.requests_mock.register_uri(
            'GET',
            self._create_server_url(elcm.URL_PATH_PROFILE_MGMT,
                                    port=443),
            text=self.RESPONSE_TEMPLATE % {'json_text': 'abc123'})

        response = elcm.elcm_request(
            irmc_info,
            method='GET',
            path=elcm.URL_PATH_PROFILE_MGMT)

        self.assertEqual(200, response.status_code)

        expected = self.RESPONSE_TEMPLATE % {'json_text': 'abc123'}
        self.assertEqual(expected, response.text)

    def test_elcm_request_unsupported_port(self):
        irmc_info = dict(self.irmc_info)
        irmc_info['irmc_port'] = 22

        e = self.assertRaises(scci.SCCIInvalidInputError,
                              elcm.elcm_request,
                              irmc_info,
                              method='GET',
                              path=elcm.URL_PATH_PROFILE_MGMT)

        auth_method = self.irmc_info['irmc_auth_method']
        self.assertEqual((("Invalid port %(port)d or "
                           "auth_method for method %(auth_method)s") %
                          {'port': 22,
                           'auth_method': auth_method}), str(e))

    def test_elcm_request_auth_method_basic(self):
        irmc_info = dict(self.irmc_info)
        irmc_info['irmc_auth_method'] = 'basic'

        self.requests_mock.register_uri(
            'GET',
            self._create_server_url(elcm.URL_PATH_PROFILE_MGMT),
            status_code=200,
            text='ok')

        response = elcm.elcm_request(
            irmc_info,
            method='GET',
            path=elcm.URL_PATH_PROFILE_MGMT)

        self.assertEqual(200, response.status_code)
        self.assertEqual('ok', response.text)

    def test_elcm_request_auth_method_digest(self):
        irmc_info = dict(self.irmc_info)
        irmc_info['irmc_auth_method'] = 'digest'

        self.requests_mock.register_uri(
            'GET',
            self._create_server_url(elcm.URL_PATH_PROFILE_MGMT),
            status_code=200,
            text='ok')

        response = elcm.elcm_request(
            irmc_info,
            method='GET',
            path=elcm.URL_PATH_PROFILE_MGMT)

        self.assertEqual(200, response.status_code)
        self.assertEqual('ok', response.text)

    def test_elcm_request_unsupported_auth_method(self):
        irmc_info = dict(self.irmc_info)
        irmc_info['irmc_auth_method'] = 'unknown'

        e = self.assertRaises(scci.SCCIInvalidInputError,
                              elcm.elcm_request,
                              irmc_info,
                              method='GET',
                              path=elcm.URL_PATH_PROFILE_MGMT)

        port = self.irmc_info['irmc_port']
        self.assertEqual((("Invalid port %(port)d or "
                           "auth_method for method %(auth_method)s") %
                          {'port': port,
                           'auth_method': 'unknown'}), str(e))

    def test_elcm_request_auth_failed(self):
        self.requests_mock.register_uri(
            'GET',
            self._create_server_url(elcm.URL_PATH_PROFILE_MGMT),
            status_code=401,
            text='401 Unauthorized')

        e = self.assertRaises(scci.SCCIClientError,
                              elcm.elcm_request,
                              self.irmc_info,
                              method='GET',
                              path=elcm.URL_PATH_PROFILE_MGMT)

        self.assertEqual('UNAUTHORIZED', str(e))

    def test_elcm_profile_get_versions_failed(self):
        self.requests_mock.register_uri(
            'GET',
            self._create_server_url(elcm.URL_PATH_PROFILE_MGMT) + 'version',
            status_code=503)

        self.assertRaises(scci.SCCIClientError,
                          elcm.elcm_profile_get_versions,
                          self.irmc_info)

    def test_elcm_profile_get_versions_ok(self):
        self.requests_mock.register_uri(
            'GET',
            self._create_server_url(elcm.URL_PATH_PROFILE_MGMT) + 'version',
            text=(self.RESPONSE_TEMPLATE % {
                'json_text':
                    '"Server":{'
                    '  "@Version": "1.01",'
                    '  "AdapterConfigIrmc": {'
                    '    "@Version": "1.00"'
                    '   },'
                    '  "SystemConfig": {'
                    '    "BiosConfig": {'
                    '      "@Version": "1.02"'
                    '    }'
                    '  }'
                    '}'}))

        result = elcm.elcm_profile_get_versions(self.irmc_info)

        expected = {
            "Server": {
                "@Version": "1.01",
                "AdapterConfigIrmc": {
                    "@Version": "1.00"
                },
                "SystemConfig": {
                    "BiosConfig": {
                        "@Version": "1.02"
                    }
                }
            }
        }
        self.assertEqual(expected, result)

    def test_elcm_profile_get_not_found(self):
        profile_name = elcm.PROFILE_BIOS_CONFIG
        self.requests_mock.register_uri(
            'GET',
            self._create_server_url((elcm.URL_PATH_PROFILE_MGMT +
                                     profile_name)),
            status_code=404)

        self.assertRaises(elcm.ELCMProfileNotFound,
                          elcm.elcm_profile_get,
                          self.irmc_info,
                          profile_name=profile_name)

    def test_elcm_profile_list_failed(self):
        self.requests_mock.register_uri(
            'GET',
            self._create_server_url(elcm.URL_PATH_PROFILE_MGMT),
            status_code=503)

        self.assertRaises(scci.SCCIClientError,
                          elcm.elcm_profile_list,
                          self.irmc_info)

    def test_elcm_profile_list_ok(self):
        self.requests_mock.register_uri(
            'GET',
            self._create_server_url(elcm.URL_PATH_PROFILE_MGMT),
            text=(self.RESPONSE_TEMPLATE % {
                'json_text':
                    '"Links":{'
                    '  "profileStore":['
                    '    {"@odata.id": "id1"},'
                    '    {"@odata.id": "id2"}'
                    '    ]'
                    '}'}))

        result = elcm.elcm_profile_list(self.irmc_info)

        expected = {
            "Links": {
                "profileStore": [
                    {"@odata.id": "id1"},
                    {"@odata.id": "id2"}
                ]
            }
        }
        self.assertEqual(expected, result)

    def test_elcm_profile_get_failed(self):
        profile_name = elcm.PROFILE_BIOS_CONFIG
        self.requests_mock.register_uri(
            'GET',
            self._create_server_url((elcm.URL_PATH_PROFILE_MGMT +
                                     profile_name)),
            status_code=500)

        self.assertRaises(scci.SCCIClientError,
                          elcm.elcm_profile_get,
                          self.irmc_info,
                          profile_name=profile_name)

    def test_elcm_profile_get_ok(self):
        profile_name = elcm.PROFILE_BIOS_CONFIG
        self.requests_mock.register_uri(
            'GET',
            self._create_server_url((elcm.URL_PATH_PROFILE_MGMT +
                                     profile_name)),
            text=(self.RESPONSE_TEMPLATE % {
                'json_text':
                    '"Server":{'
                    '  "SystemConfig":{'
                    '    "BiosConfig":{'
                    '       "key":"val"'
                    '    }'
                    '  }'
                    '}'}))

        result = elcm.elcm_profile_get(
            self.irmc_info,
            profile_name=profile_name)

        expected = {
            "Server": {
                "SystemConfig": {
                    "BiosConfig": {
                        "key": "val"
                    }
                }
            }
        }
        self.assertEqual(expected, result)

    def test_elcm_profile_create_failed(self):
        param_path = elcm.PARAM_PATH_BIOS_CONFIG
        self.requests_mock.register_uri(
            'POST',
            self._create_server_url(elcm.URL_PATH_PROFILE_MGMT + 'get'),
            status_code=200)  # Success code is 202

        self.assertRaises(scci.SCCIClientError,
                          elcm.elcm_profile_create,
                          self.irmc_info,
                          param_path=param_path)

    def test_elcm_profile_create_ok(self):
        param_path = elcm.PARAM_PATH_BIOS_CONFIG
        self.requests_mock.register_uri(
            'POST',
            self._create_server_url(elcm.URL_PATH_PROFILE_MGMT + 'get'),
            status_code=202,  # Success code is 202
            text=(self.RESPONSE_TEMPLATE % {
                'json_text':
                    '"Session":{'
                    '  "Id": 123,'
                    '  "Status": "activated"'
                    '}'}))

        result = elcm.elcm_profile_create(self.irmc_info,
                                          param_path=param_path)

        expected = {
            "Session": {
                "Id": 123,
                "Status": "activated",
            }
        }
        self.assertEqual(expected, result)

    def test_elcm_profile_set_failed(self):
        input_data = {
            "Server": {
                "SystemConfig": {
                    "BiosConfig": {
                        "key": "val"
                    }
                }
            }
        }
        self.requests_mock.register_uri(
            'POST',
            self._create_server_url(elcm.URL_PATH_PROFILE_MGMT + 'set'),
            status_code=200)  # Success code is 202

        self.assertRaises(scci.SCCIClientError,
                          elcm.elcm_profile_set,
                          self.irmc_info,
                          input_data=input_data)

    def test_elcm_profile_set_ok(self):
        input_data = {
            "Server": {
                "SystemConfig": {
                    "BiosConfig": {
                        "key": "val"
                    }
                }
            }
        }
        self.requests_mock.register_uri(
            'POST',
            self._create_server_url(elcm.URL_PATH_PROFILE_MGMT + 'set'),
            status_code=202,  # Success code is 202
            text=(self.RESPONSE_TEMPLATE % {
                'json_text':
                    '"Session":{'
                    '  "Id": 123,'
                    '  "Status": "activated"'
                    '}'}))

        result = elcm.elcm_profile_set(self.irmc_info,
                                       input_data=input_data)

        expected = {
            "Session": {
                "Id": 123,
                "Status": "activated",
            }
        }
        self.assertEqual(expected, result)

    def test_elcm_profile_set_with_raid_config_failed(self):
        input_data = {
            "Server": {
                "HWConfigurationIrmc": {
                    "Adapters": {
                        "RAIDAdapter": [
                            {
                                "key": "val"
                            }
                        ]
                    }
                }
            }
        }
        self.requests_mock.register_uri(
            'POST',
            self._create_server_url(elcm.URL_PATH_PROFILE_MGMT + 'set'),
            status_code=400)  # Success code is 202

        self.assertRaises(scci.SCCIClientError,
                          elcm.elcm_profile_set,
                          self.irmc_info,
                          input_data=input_data)

    def test_elcm_profile_set_with_raid_config_ok(self):
        input_data = {
            "Server": {
                "HWConfigurationIrmc": {
                    "Adapters": {
                        "RAIDAdapter": [
                            {
                                "key": "val"
                            }
                        ]
                    }
                }
            }
        }
        self.requests_mock.register_uri(
            'POST',
            self._create_server_url(elcm.URL_PATH_PROFILE_MGMT + 'set'),
            status_code=202,  # Success code is 202
            text=(self.RESPONSE_TEMPLATE % {
                'json_text':
                    '"Session":{'
                    '  "Id": 123,'
                    '  "Status": "activated"'
                    '}'}))

        result = elcm.elcm_profile_set(self.irmc_info,
                                       input_data=input_data)

        expected = {
            "Session": {
                "Id": 123,
                "Status": "activated",
            }
        }
        self.assertEqual(expected, result)

    def test_elcm_profile_delete_not_found(self):
        profile_name = elcm.PROFILE_BIOS_CONFIG
        self.requests_mock.register_uri(
            'DELETE',
            self._create_server_url((elcm.URL_PATH_PROFILE_MGMT +
                                     profile_name)),
            status_code=404)

        self.assertRaises(elcm.ELCMProfileNotFound,
                          elcm.elcm_profile_delete,
                          self.irmc_info,
                          profile_name=profile_name)

    def test_elcm_profile_delete_failed(self):
        profile_name = elcm.PROFILE_BIOS_CONFIG
        self.requests_mock.register_uri(
            'DELETE',
            self._create_server_url((elcm.URL_PATH_PROFILE_MGMT +
                                     profile_name)),
            status_code=500)

        self.assertRaises(scci.SCCIClientError,
                          elcm.elcm_profile_delete,
                          self.irmc_info,
                          profile_name=profile_name)

    def test_elcm_profile_delete_ok(self):
        profile_name = elcm.PROFILE_BIOS_CONFIG
        self.requests_mock.register_uri(
            'DELETE',
            self._create_server_url((elcm.URL_PATH_PROFILE_MGMT +
                                     profile_name)),
            text='ok')

        result = elcm.elcm_profile_delete(self.irmc_info,
                                          profile_name=profile_name)

        self.assertIsNone(result)

    def test_elcm_session_list_failed(self):
        self.requests_mock.register_uri(
            'GET',
            self._create_server_url('/sessionInformation/'),
            status_code=500)

        self.assertRaises(scci.SCCIClientError,
                          elcm.elcm_session_list,
                          self.irmc_info)

    def test_elcm_session_list_empty(self):
        self.requests_mock.register_uri(
            'GET',
            self._create_server_url('/sessionInformation/'),
            text=(self.RESPONSE_TEMPLATE % {
                'json_text':
                    '"SessionList":{'
                    '  "Contains":['
                    '  ]'
                    '}'}))

        result = elcm.elcm_session_list(self.irmc_info)

        expected = {
            "SessionList": {
                "Contains": [
                ]
            }
        }
        self.assertEqual(expected, result)

    def test_elcm_session_list_ok(self):
        self.requests_mock.register_uri(
            'GET',
            self._create_server_url('/sessionInformation/'),
            text=(self.RESPONSE_TEMPLATE % {
                'json_text':
                    '"SessionList":{'
                    '  "Contains":['
                    '    { "Id": 1, "Name": "name1" },'
                    '    { "Id": 2, "Name": "name2" },'
                    '    { "Id": 3, "Name": "name3" }'
                    '  ]'
                    '}'}))

        result = elcm.elcm_session_list(self.irmc_info)

        expected = {
            "SessionList": {
                "Contains": [
                    {"Id": 1, "Name": "name1"},
                    {"Id": 2, "Name": "name2"},
                    {"Id": 3, "Name": "name3"}
                ]
            }
        }
        self.assertEqual(expected, result)

    def test_elcm_session_get_status_not_found(self):
        session_id = 123
        self.requests_mock.register_uri(
            'GET',
            self._create_server_url(('/sessionInformation/%s/status' %
                                     session_id)),
            status_code=404)

        self.assertRaises(elcm.ELCMSessionNotFound,
                          elcm.elcm_session_get_status,
                          self.irmc_info,
                          session_id=session_id)

    def test_elcm_session_get_status_failed(self):
        session_id = 123
        self.requests_mock.register_uri(
            'GET',
            self._create_server_url(('/sessionInformation/%s/status' %
                                     session_id)),
            status_code=500)

        self.assertRaises(scci.SCCIClientError,
                          elcm.elcm_session_get_status,
                          self.irmc_info,
                          session_id=session_id)

    def test_elcm_session_get_status_ok(self):
        session_id = 123
        self.requests_mock.register_uri(
            'GET',
            self._create_server_url(('/sessionInformation/%s/status' %
                                     session_id)),
            text=(self.RESPONSE_TEMPLATE % {
                'json_text':
                    '"Session":{'
                    '  "Id": 123,'
                    '  "Status": "abc123"'
                    '}'}))

        result = elcm.elcm_session_get_status(self.irmc_info,
                                              session_id=session_id)

        expected = {
            "Session": {
                "Id": 123,
                "Status": "abc123",
            }
        }
        self.assertEqual(expected, result)

    def test_elcm_session_get_log_not_found(self):
        session_id = 123
        self.requests_mock.register_uri(
            'GET',
            self._create_server_url(('/sessionInformation/%s/log' %
                                     session_id)),
            status_code=404)

        self.assertRaises(elcm.ELCMSessionNotFound,
                          elcm.elcm_session_get_log,
                          self.irmc_info,
                          session_id=session_id)

    def test_elcm_session_get_log_failed(self):
        session_id = 123
        self.requests_mock.register_uri(
            'GET',
            self._create_server_url(('/sessionInformation/%s/log' %
                                     session_id)),
            status_code=500)

        self.assertRaises(scci.SCCIClientError,
                          elcm.elcm_session_get_log,
                          self.irmc_info,
                          session_id=session_id)

    def test_elcm_session_get_log_ok(self):
        session_id = 123
        self.requests_mock.register_uri(
            'GET',
            self._create_server_url(('/sessionInformation/%s/log' %
                                     session_id)),
            text=(self.RESPONSE_TEMPLATE % {
                'json_text':
                    '"Session":{'
                    '  "Id": 123,'
                    '  "A_Param": "abc123"'
                    '}'}))

        result = elcm.elcm_session_get_log(self.irmc_info,
                                           session_id=session_id)

        expected = {
            "Session": {
                "Id": 123,
                "A_Param": "abc123",
            }
        }
        self.assertEqual(expected, result)

    def test_elcm_session_terminate_not_found(self):
        session_id = 123
        self.requests_mock.register_uri(
            'DELETE',
            self._create_server_url(('/sessionInformation/%s/terminate' %
                                     session_id)),
            status_code=404)

        self.assertRaises(elcm.ELCMSessionNotFound,
                          elcm.elcm_session_terminate,
                          self.irmc_info,
                          session_id=session_id)

    def test_elcm_session_terminate_failed(self):
        session_id = 123
        self.requests_mock.register_uri(
            'DELETE',
            self._create_server_url(('/sessionInformation/%s/terminate' %
                                     session_id)),
            status_code=500)

        self.assertRaises(scci.SCCIClientError,
                          elcm.elcm_session_terminate,
                          self.irmc_info,
                          session_id=session_id)

    def test_elcm_session_terminate_ok(self):
        session_id = 123
        self.requests_mock.register_uri(
            'DELETE',
            self._create_server_url(('/sessionInformation/%s/terminate' %
                                     session_id)),
            text='ok')

        result = elcm.elcm_session_terminate(self.irmc_info,
                                             session_id=session_id)

        self.assertIsNone(result)

    def test_elcm_session_delete_not_found(self):
        session_id = 123
        self.requests_mock.register_uri(
            'DELETE',
            self._create_server_url(('/sessionInformation/%s/remove' %
                                     session_id)),
            status_code=404)

        self.assertRaises(elcm.ELCMSessionNotFound,
                          elcm.elcm_session_delete,
                          self.irmc_info,
                          session_id=session_id)

    def test_elcm_session_delete_failed(self):
        session_id = 123
        self.requests_mock.register_uri(
            'DELETE',
            self._create_server_url(('/sessionInformation/%s/remove' %
                                     session_id)),
            status_code=500)

        self.assertRaises(scci.SCCIClientError,
                          elcm.elcm_session_delete,
                          self.irmc_info,
                          session_id=session_id)

    def test_elcm_session_delete_ok(self):
        session_id = 123
        self.requests_mock.register_uri(
            'DELETE',
            self._create_server_url(('/sessionInformation/%s/remove' %
                                     session_id)),
            text='ok')

        result = elcm.elcm_session_delete(self.irmc_info,
                                          session_id=session_id)

        self.assertIsNone(result)

    @mock.patch.object(elcm, 'elcm_profile_delete')
    @mock.patch.object(elcm, 'elcm_profile_get')
    @mock.patch.object(elcm, 'elcm_session_delete')
    @mock.patch.object(elcm, 'elcm_session_get_status')
    @mock.patch.object(elcm.time, 'sleep')
    def test__process_session_data_get_ok(self, mock_sleep,
                                          mock_session_get,
                                          mock_session_delete,
                                          mock_profile_get,
                                          mock_profile_delete):
        session_id = 123
        expected_bios_cfg = {
            'Server': {
                'SystemConfig': {
                    'BiosConfig': {
                        'key1': 'val1'
                    }
                }
            }
        }
        mock_session_get.side_effect = [
            {'Session': {'Id': session_id,
                         'Status': 'activated'}},
            {'Session': {'Id': session_id,
                         'Status': 'running'}},
            {'Session': {'Id': session_id,
                         'Status': 'terminated regularly'}}]
        mock_profile_get.return_value = expected_bios_cfg

        result = elcm._process_session_data(irmc_info=self.irmc_info,
                                            operation='BACKUP_BIOS',
                                            session_id=session_id)
        self.assertEqual(expected_bios_cfg, result['bios_config'])

        mock_session_get.assert_has_calls([
            mock.call(irmc_info=self.irmc_info, session_id=session_id),
            mock.call(irmc_info=self.irmc_info, session_id=session_id),
            mock.call(irmc_info=self.irmc_info, session_id=session_id)])
        mock_profile_get.assert_called_once_with(
            irmc_info=self.irmc_info,
            profile_name=elcm.PROFILE_BIOS_CONFIG)

        self.assertEqual(2, mock_sleep.call_count)
        self.assertEqual(1, mock_session_delete.call_count)
        self.assertEqual(1, mock_profile_delete.call_count)

    @mock.patch.object(elcm, 'elcm_profile_delete')
    @mock.patch.object(elcm, 'elcm_profile_get')
    @mock.patch.object(elcm, 'elcm_session_delete')
    @mock.patch.object(elcm, 'elcm_session_get_status')
    @mock.patch.object(elcm.time, 'sleep')
    def test__process_session_data_set_ok(self, mock_sleep,
                                          mock_session_get,
                                          mock_session_delete,
                                          mock_profile_get,
                                          mock_profile_delete):
        session_id = 123
        mock_session_get.side_effect = [
            {'Session': {'Id': session_id,
                         'Status': 'activated'}},
            {'Session': {'Id': session_id,
                         'Status': 'running'}},
            {'Session': {'Id': session_id,
                         'Status': 'terminated regularly'}}]

        elcm._process_session_data(irmc_info=self.irmc_info,
                                   operation='RESTORE_BIOS',
                                   session_id=session_id)

        mock_session_get.assert_has_calls([
            mock.call(irmc_info=self.irmc_info, session_id=session_id),
            mock.call(irmc_info=self.irmc_info, session_id=session_id),
            mock.call(irmc_info=self.irmc_info, session_id=session_id)])
        mock_profile_get.assert_not_called()
        self.assertEqual(2, mock_sleep.call_count)
        self.assertEqual(1, mock_session_delete.call_count)
        self.assertEqual(1, mock_profile_delete.call_count)

    @mock.patch.object(elcm, 'elcm_profile_delete')
    @mock.patch.object(elcm, 'elcm_profile_get')
    @mock.patch.object(elcm, 'elcm_session_delete')
    @mock.patch.object(elcm, 'elcm_session_get_status')
    @mock.patch.object(elcm.time, 'sleep')
    def test__process_session_data_timeout(self, mock_sleep,
                                           mock_session_get,
                                           mock_session_delete,
                                           mock_profile_get,
                                           mock_profile_delete):
        session_id = 123
        mock_session_get.return_value = {'Session': {'Id': session_id,
                                                     'Status': 'running'}}

        self.assertRaises(elcm.ELCMSessionTimeout,
                          elcm._process_session_data,
                          irmc_info=self.irmc_info,
                          operation='BACKUP_BIOS',
                          session_id=session_id,
                          session_timeout=0.5)

        self.assertEqual(True, mock_sleep.called)
        self.assertEqual(True, mock_session_get.called)
        mock_profile_get.assert_not_called()
        mock_session_delete.assert_not_called()
        mock_profile_delete.assert_not_called()

    @mock.patch.object(elcm, 'elcm_profile_delete')
    @mock.patch.object(elcm, 'elcm_session_delete')
    @mock.patch.object(elcm, 'elcm_session_get_log')
    @mock.patch.object(elcm, 'elcm_session_get_status')
    def test__process_session_data_error(self,
                                         mock_session_get,
                                         mock_session_get_log,
                                         mock_session_delete,
                                         mock_profile_delete):
        session_id = 123
        mock_session_get.return_value = {'Session': {'Id': session_id,
                                                     'Status': 'error'}}

        self.assertRaises(scci.SCCIClientError,
                          elcm._process_session_data,
                          irmc_info=self.irmc_info,
                          operation='RESTORE_BIOS',
                          session_id=session_id,
                          session_timeout=0.5)

        self.assertEqual(True, mock_session_get.called)
        self.assertEqual(True, mock_session_get_log.called)
        mock_session_delete.assert_not_called()
        mock_profile_delete.assert_not_called()

    @mock.patch.object(elcm, 'elcm_profile_delete')
    @mock.patch.object(elcm, 'elcm_profile_create')
    @mock.patch.object(elcm, 'elcm_profile_get')
    @mock.patch.object(elcm, 'elcm_session_delete')
    @mock.patch.object(elcm, 'elcm_session_get_status')
    @mock.patch.object(elcm.time, 'sleep')
    def test_backup_bios_config_ok(self, mock_sleep, mock_session_get,
                                   mock_session_delete, mock_profile_get,
                                   mock_profile_create, mock_profile_delete):
        session_id = 123
        expected_bios_cfg = {
            'Server': {
                'SystemConfig': {
                    'BiosConfig': {
                        'key1': 'val1'
                    }
                }
            }
        }
        mock_session_get.side_effect = [
            {'Session': {'Id': session_id,
                         'Status': 'activated'}},
            {'Session': {'Id': session_id,
                         'Status': 'running'}},
            {'Session': {'Id': session_id,
                         'Status': 'terminated regularly'}}]
        mock_profile_get.return_value = expected_bios_cfg
        mock_profile_create.return_value = {'Session': {'Id': session_id,
                                                        'Status': 'activated'}}

        result = elcm.backup_bios_config(irmc_info=self.irmc_info)
        self.assertEqual(expected_bios_cfg, result['bios_config'])

        self.assertEqual(2, mock_sleep.call_count)
        self.assertEqual(True, mock_session_get.called)
        self.assertEqual(1, mock_session_delete.call_count)
        self.assertEqual(2, mock_profile_get.call_count)
        self.assertEqual(1, mock_profile_create.call_count)
        self.assertEqual(2, mock_profile_delete.call_count)

    @mock.patch.object(elcm, 'elcm_profile_delete')
    @mock.patch.object(elcm, 'elcm_profile_get')
    @mock.patch.object(elcm, 'elcm_profile_set')
    @mock.patch.object(elcm, 'elcm_session_delete')
    @mock.patch.object(elcm, 'elcm_session_get_status')
    @mock.patch.object(elcm.time, 'sleep')
    def _test_restore_bios_config_ok(self, mock_sleep, mock_session_get,
                                     mock_session_delete, mock_profile_set,
                                     mock_profile_get, mock_profile_delete,
                                     bios_cfg):
        session_id = 123
        mock_session_get.side_effect = [
            {'Session': {'Id': session_id,
                         'Status': 'activated'}},
            {'Session': {'Id': session_id,
                         'Status': 'running'}},
            {'Session': {'Id': session_id,
                         'Status': 'terminated regularly'}}]
        mock_profile_set.return_value = {'Session': {'Id': session_id,
                                                     'Status': 'activated'}}

        elcm.restore_bios_config(irmc_info=self.irmc_info,
                                 bios_config=bios_cfg)

        self.assertEqual(2, mock_sleep.call_count)
        self.assertEqual(True, mock_session_get.called)
        self.assertEqual(1, mock_session_delete.call_count)
        self.assertEqual(1, mock_profile_get.call_count)
        self.assertEqual(1, mock_profile_set.call_count)
        self.assertEqual(2, mock_profile_delete.call_count)

    def test_restore_bios_config_ok_with_dict(self):
        bios_cfg = {
            'Server': {
                'SystemConfig': {
                    'BiosConfig': {
                        'key1': 'val1'
                    }
                }
            }
        }
        self._test_restore_bios_config_ok(bios_cfg=bios_cfg)

    def test_restore_bios_config_ok_with_str(self):
        bios_cfg = ('{"Server":'
                    '  {"SystemConfig":'
                    '    {"BiosConfig":'
                    '      {'
                    '        "key1": "val1"'
                    '      }'
                    '    }'
                    '  }'
                    '}')
        self._test_restore_bios_config_ok(bios_cfg=bios_cfg)

    def _test_restore_bios_config_invalid_input(self, bios_cfg):
        self.assertRaises(scci.SCCIInvalidInputError,
                          elcm.restore_bios_config,
                          irmc_info=self.irmc_info,
                          bios_config=bios_cfg)

    def test_restore_bios_config_invalid_input_dict(self):
        bios_cfg = {
            'Server': {
                'SystemConfig': {
                }
            }
        }
        self._test_restore_bios_config_invalid_input(bios_cfg=bios_cfg)

    def test_restore_bios_config_invalid_input_str(self):
        bios_cfg = '{"key": "val"}'
        self._test_restore_bios_config_invalid_input(bios_cfg=bios_cfg)

    @mock.patch.object(elcm, 'backup_bios_config')
    def test_get_secure_boot_mode_true(self, backup_bios_config_mock):
        backup_bios_config_mock.return_value = {
            'bios_config': {
                'Server': {
                    'SystemConfig': {
                        'BiosConfig': {
                            'SecurityConfig': {
                                'SecureBootControlEnabled': True
                            }
                        }
                    }
                }
            }
        }
        result = elcm.get_secure_boot_mode(irmc_info=self.irmc_info)
        self.assertEqual(True, result)
        backup_bios_config_mock.assert_called_once_with(
            irmc_info=self.irmc_info)

    @mock.patch.object(elcm, 'backup_bios_config')
    def test_get_secure_boot_mode_false(self, backup_bios_config_mock):
        backup_bios_config_mock.return_value = {
            'bios_config': {
                'Server': {
                    'SystemConfig': {
                        'BiosConfig': {
                            'SecurityConfig': {
                                'SecureBootControlEnabled': False
                            }
                        }
                    }
                }
            }
        }
        result = elcm.get_secure_boot_mode(irmc_info=self.irmc_info)
        self.assertEqual(False, result)
        backup_bios_config_mock.assert_called_once_with(
            irmc_info=self.irmc_info)

    @mock.patch.object(elcm, 'backup_bios_config')
    def test_get_secure_boot_mode_fail(self, backup_bios_config_mock):
        backup_bios_config_mock.return_value = {
            'bios_config': {
                'Server': {
                    'SystemConfig': {
                        'BiosConfig': {
                            'SecurityConfig': {
                                'FlashWriteEnabled': False
                            }
                        }
                    }
                }
            }
        }

        self.assertRaises(elcm.SecureBootConfigNotFound,
                          elcm.get_secure_boot_mode,
                          irmc_info=self.irmc_info)
        backup_bios_config_mock.assert_called_once_with(
            irmc_info=self.irmc_info)

    @mock.patch.object(elcm, 'restore_bios_config')
    def test_set_secure_boot_mode_true(self, restore_bios_config_mock):
        elcm.set_secure_boot_mode(irmc_info=self.irmc_info, enable=True)
        bios_config_data = {
            'Server': {
                '@Version': '1.01',
                'SystemConfig': {
                    'BiosConfig': {
                        '@Version': '1.01',
                        'SecurityConfig': {
                            'SecureBootControlEnabled': True
                        }
                    }
                }
            }
        }
        restore_bios_config_mock.assert_called_once_with(
            irmc_info=self.irmc_info, bios_config=bios_config_data)

    @mock.patch.object(elcm, 'restore_bios_config')
    def test_set_secure_boot_mode_false(self, restore_bios_config_mock):
        elcm.set_secure_boot_mode(irmc_info=self.irmc_info, enable=False)
        bios_config_data = {
            'Server': {
                '@Version': '1.01',
                'SystemConfig': {
                    'BiosConfig': {
                        '@Version': '1.01',
                        'SecurityConfig': {
                            'SecureBootControlEnabled': False
                        }
                    }
                }
            }
        }
        restore_bios_config_mock.assert_called_once_with(
            irmc_info=self.irmc_info, bios_config=bios_config_data)

    @mock.patch.object(elcm, 'get_raid_adapter')
    @mock.patch.object(elcm, 'elcm_profile_set')
    @mock.patch.object(elcm, '_process_session_data')
    def test_create_raid_config_without_arrays_info_and_physical_disks(
            self, session_mock, elcm_profile_set_mock, raid_info_mock):

        elcm_profile_set_mock.return_value = {
            "Session": {
                "Id": 1,
                "A_Param": "abc123"
            }
        }
        session_id = 1
        session_timeout = 1800
        operation = 'CONFIG_RAID'

        raid_info_mock.return_value = self.raid_info
        expected_input = {
            'Server': {
                'HWConfigurationIrmc': {
                    '@Processing': 'execute',
                    'Adapters': {
                        'RAIDAdapter': [
                            {
                                'Arrays': {
                                    'Array': []
                                },
                                'LogicalDrives': {
                                    'LogicalDrive': [
                                        {
                                            '@Number': 0,
                                            '@Action': 'Create',
                                            'RaidLevel': '1',
                                            'InitMode': 'slow',
                                            'Size': {
                                                '@Unit': 'GB',
                                                '#text': 100
                                            },
                                        }
                                    ]
                                }
                            }
                        ]
                    },
                    '@Version': '1.00'
                },
                '@Version': '1.01'
            }
        }
        target_raid_config = {
            'logical_disks':
                [
                    {
                        'size_gb': 100,
                        'raid_level': '1',
                    }
                ]
        }

        elcm.create_raid_configuration(
            self.irmc_info, target_raid_config=target_raid_config)

        session_mock.assert_called_once_with(self.irmc_info, operation,
                                             session_id, session_timeout)
        # Check raid_input data
        raid_info_mock.assert_called_once_with(self.irmc_info)
        elcm_profile_set_mock.assert_called_once_with(
            self.irmc_info, expected_input)

    @mock.patch.object(elcm, 'get_raid_adapter')
    @mock.patch.object(elcm, 'elcm_profile_set')
    @mock.patch.object(elcm, '_process_session_data')
    def test_create_raid_config_with_arrays_info_and_without_physical_disks(
            self, session_mock, elcm_profile_set_mock, raid_info_mock):

        raid_info_mock.return_value = self.raid_info
        expected_input = {
            'Server': {
                'HWConfigurationIrmc': {
                    '@Processing': 'execute',
                    'Adapters': {
                        'RAIDAdapter': [
                            {
                                'Arrays': {
                                    'Array': []
                                },
                                'LogicalDrives': {
                                    'LogicalDrive': [
                                        {
                                            '@Number': 0,
                                            '@Action': 'Create',
                                            'RaidLevel': '0',
                                            'InitMode': 'slow',
                                            'Size': {
                                                '@Unit': 'GB',
                                                '#text': 100
                                            },
                                        },
                                        {
                                            '@Number': 1,
                                            '@Action': 'Create',
                                            'RaidLevel': '1',
                                            'InitMode': 'slow',
                                            'Size': {
                                                '@Unit': 'GB',
                                                '#text': 100
                                            },
                                        }
                                    ]
                                }
                            }
                        ]
                    },
                    '@Version': '1.00'
                },
                '@Version': '1.01'
            }
        }
        target_raid_config = {
            'logical_disks':
                [
                    {
                        'size_gb': 100,
                        'raid_level': '0',
                    },
                    {
                        'size_gb': 100,
                        'raid_level': '1',
                    }
                ]
        }

        elcm_profile_set_mock.return_value = {
            "Session": {
                "Id": 1,
                "A_Param": "abc123"
            }
        }
        session_id = 1
        session_timeout = 1800
        operation = 'CONFIG_RAID'

        elcm.create_raid_configuration(
            self.irmc_info, target_raid_config=target_raid_config)

        session_mock.assert_called_once_with(self.irmc_info, operation,
                                             session_id, session_timeout)
        # Check raid_input data
        elcm_profile_set_mock.assert_called_once_with(
            self.irmc_info, expected_input)
        raid_info_mock.assert_called_once_with(self.irmc_info)

    @mock.patch.object(elcm, 'get_raid_adapter')
    @mock.patch.object(elcm, 'elcm_profile_set')
    @mock.patch.object(elcm, '_process_session_data')
    def test_create_raid_config_with_physical_disks_and_without_array_info(
            self, session_mock, elcm_profile_set_mock, raid_info_mock):

        raid_info_mock.return_value = self.raid_info
        expected_input = {
            'Server': {
                'HWConfigurationIrmc': {
                    '@Processing': 'execute',
                    'Adapters': {
                        'RAIDAdapter': [
                            {
                                'Arrays': {
                                    'Array': [
                                        {
                                            '@Number': 0,
                                            '@ConfigurationType': 'Setting',
                                            'PhysicalDiskRefs': {
                                                'PhysicalDiskRef': [
                                                    {
                                                        '@Number': '0'
                                                    },
                                                    {
                                                        '@Number': '1'
                                                    }
                                                ]
                                            }
                                        }
                                    ]
                                },
                                'LogicalDrives': {
                                    'LogicalDrive': [
                                        {
                                            '@Number': 0,
                                            '@Action': 'Create',
                                            'RaidLevel': '1',
                                            'InitMode': 'slow',
                                            'Size': {
                                                '@Unit': 'GB',
                                                '#text': 100
                                            },
                                            'ArrayRefs': {
                                                'ArrayRef': [
                                                    {
                                                        '@Number': 0
                                                    }
                                                ]
                                            }
                                        }
                                    ]
                                }
                            }
                        ]
                    },
                    '@Version': '1.00'
                },
                '@Version': '1.01'
            }
        }
        target_raid_config = {
            "logical_disks":
                [
                    {
                        'size_gb': 100,
                        "raid_level": "1",
                        "physical_disks": [
                            "0",
                            "1"
                        ],
                    },
                ]
        }

        elcm_profile_set_mock.return_value = {
            "Session": {
                "Id": 1,
                "A_Param": "abc123"
            }
        }
        session_id = 1
        session_timeout = 1800
        operation = 'CONFIG_RAID'

        elcm.create_raid_configuration(
            self.irmc_info, target_raid_config=target_raid_config)

        session_mock.assert_called_once_with(self.irmc_info, operation,
                                             session_id, session_timeout)
        # Check raid_input data
        elcm_profile_set_mock.assert_called_once_with(
            self.irmc_info, expected_input)
        raid_info_mock.assert_called_once_with(self.irmc_info)

    @mock.patch.object(elcm, 'get_raid_adapter')
    @mock.patch.object(elcm, 'elcm_profile_set')
    @mock.patch.object(elcm, '_process_session_data')
    def test_create_raid_config_along_with_physical_disks_and_array_info(
            self, session_mock, elcm_profile_set_mock, raid_info_mock):

        raid_info_mock.return_value = self.raid_info
        expected_input = {
            'Server': {
                'HWConfigurationIrmc': {
                    '@Processing': 'execute',
                    'Adapters': {
                        'RAIDAdapter': [
                            {
                                'Arrays': {
                                    'Array': [
                                        {
                                            '@Number': 0,
                                            '@ConfigurationType': 'Setting',
                                            'PhysicalDiskRefs': {
                                                'PhysicalDiskRef': [
                                                    {
                                                        '@Number': '0'
                                                    },
                                                    {
                                                        '@Number': '1'
                                                    }
                                                ]
                                            }
                                        },
                                        {
                                            '@Number': 1,
                                            '@ConfigurationType': 'Setting',
                                            'PhysicalDiskRefs': {
                                                'PhysicalDiskRef': [
                                                    {
                                                        '@Number': '4'
                                                    },
                                                    {
                                                        '@Number': '5'
                                                    }
                                                ]
                                            }
                                        },
                                    ]
                                },
                                'LogicalDrives': {
                                    'LogicalDrive': [
                                        {
                                            '@Number': 0,
                                            '@Action': 'Create',
                                            'RaidLevel': '0',
                                            'InitMode': 'slow',
                                            'Size': {
                                                '@Unit': 'GB',
                                                '#text': 100
                                            },
                                            'ArrayRefs': {
                                                'ArrayRef': [
                                                    {
                                                        '@Number': 0
                                                    }
                                                ]
                                            }
                                        },
                                        {
                                            '@Number': 1,
                                            '@Action': 'Create',
                                            'RaidLevel': '1',
                                            'InitMode': 'slow',
                                            'Size': {
                                                '@Unit': 'GB',
                                                '#text': 100
                                            },
                                            'ArrayRefs': {
                                                'ArrayRef': [
                                                    {
                                                        '@Number': 1
                                                    }
                                                ]
                                            }
                                        }
                                    ]
                                }
                            }
                        ]
                    },
                    '@Version': '1.00'
                },
                '@Version': '1.01'
            }
        }
        target_raid_config = {
            'logical_disks':
                [
                    {
                        'size_gb': 100,
                        'raid_level': '0',
                        'physical_disks': [
                            '0',
                            '1'
                        ]
                    },
                    {
                        'size_gb': 100,
                        'raid_level': '1',
                        'physical_disks': [
                            '4',
                            '5'
                        ]
                    },
                ]
        }

        elcm_profile_set_mock.return_value = {
            "Session": {
                "Id": 1,
                "A_Param": "abc123"
            }
        }
        session_id = 1
        session_timeout = 1800
        operation = 'CONFIG_RAID'

        elcm.create_raid_configuration(
            self.irmc_info, target_raid_config=target_raid_config)

        session_mock.assert_called_once_with(self.irmc_info, operation,
                                             session_id, session_timeout)
        # Check raid_input data
        elcm_profile_set_mock.assert_called_once_with(
            self.irmc_info, expected_input)
        raid_info_mock.assert_called_once_with(self.irmc_info)

    @mock.patch.object(elcm, 'delete_raid_configuration')
    @mock.patch.object(elcm, 'get_raid_adapter')
    @mock.patch.object(elcm, 'elcm_profile_set')
    @mock.patch.object(elcm, '_process_session_data')
    def test_create_raid_config_with_exist_raid_config(
            self, session_mock, elcm_profile_set_mock, raid_info_mock,
            delete_raid_mock):

        raid_info_mock.return_value = {
            'Server': {
                'HWConfigurationIrmc': {
                    'Adapters': {
                        'RAIDAdapter': [
                            {
                                'Arrays': None,
                                'LogicalDrives': {
                                    'LogicalDrive': [
                                        {
                                            '@Number': 0,
                                            '@Action': None,
                                            'RaidLevel': '1'
                                        },
                                    ]
                                }
                            }
                        ]
                    },
                    '@Version': '1.00'
                },
                '@Version': '1.01'
            }
        }

        elcm_profile_set_mock.return_value = {
            "Session": {
                "Id": 1,
                "A_Param": "abc123"
            }
        }
        session_id = 1
        session_timeout = 1800
        operation = 'CONFIG_RAID'

        expected_raid_call = {
            'Server': {
                'HWConfigurationIrmc': {
                    '@Processing': 'execute',
                    'Adapters': {
                        'RAIDAdapter': [
                            {
                                'Arrays': {
                                    'Array': []
                                },
                                'LogicalDrives': {
                                    'LogicalDrive': [
                                        {
                                            '@Number': 0,
                                            '@Action': 'Create',
                                            'RaidLevel': '1',
                                            'InitMode': 'slow',
                                            'Size': {
                                                '@Unit': 'GB',
                                                '#text': 100
                                            }
                                        },
                                    ]
                                }
                            }
                        ]
                    },
                    '@Version': '1.00'
                },
                '@Version': '1.01'
            }
        }

        target_raid_config = {
            'logical_disks':
                [
                    {
                        'size_gb': 100,
                        'raid_level': '1'
                    },
                ]
        }

        elcm.create_raid_configuration(self.irmc_info, target_raid_config)

        elcm_profile_set_mock.assert_called_once_with(self.irmc_info,
                                                      expected_raid_call)
        delete_raid_mock.assert_called_once_with(self.irmc_info)
        session_mock.assert_has_calls([mock.call(self.irmc_info, operation,
                                      session_id, session_timeout)])
        raid_info_mock.assert_has_calls([mock.call(self.irmc_info)])

    def test_create_raid_config_without_logical_disk(self):

        target_raid_config = {
            'logical_disks': []
        }

        self.assertRaises(elcm.ELCMValueError,
                          elcm.create_raid_configuration,
                          irmc_info=self.irmc_info,
                          target_raid_config=target_raid_config)

    @mock.patch.object(elcm, 'get_raid_adapter')
    @mock.patch.object(elcm, 'elcm_profile_set')
    @mock.patch.object(elcm, '_process_session_data')
    def test_create_raid_config_with_raid_level_is_max(
            self, session_mock, elcm_profile_set_mock, raid_info_mock):

        raid_info_mock.return_value = self.raid_info
        expected_input = {
            'Server': {
                'HWConfigurationIrmc': {
                    '@Processing': 'execute',
                    'Adapters': {
                        'RAIDAdapter': [
                            {
                                'Arrays': {
                                    'Array': []
                                },
                                'LogicalDrives': {
                                    'LogicalDrive': [
                                        {
                                            '@Number': 0,
                                            '@Action': 'Create',
                                            'RaidLevel': '0',
                                            'InitMode': 'slow'
                                        }
                                    ]
                                }
                            }
                        ]
                    },
                    '@Version': '1.00'
                },
                '@Version': '1.01'
            }
        }

        elcm_profile_set_mock.return_value = {
            "Session": {
                "Id": 1,
                "A_Param": "abc123"
            }
        }
        session_id = 1
        session_timeout = 1800
        operation = 'CONFIG_RAID'

        target_raid_config = {
            'logical_disks':
                [
                    {
                        'size_gb': 'MAX',
                        'raid_level': '0'
                    },
                ]
        }

        elcm.create_raid_configuration(self.irmc_info, target_raid_config)
        elcm_profile_set_mock.assert_called_once_with(self.irmc_info,
                                                      expected_input)
        session_mock.assert_called_once_with(self.irmc_info, operation,
                                             session_id, session_timeout)

    @mock.patch.object(elcm, 'get_raid_adapter')
    @mock.patch.object(elcm, 'elcm_profile_set')
    @mock.patch.object(elcm, '_process_session_data')
    def test_create_raid_config_hybrid_in_target_raid_config(
            self, session_mock, elcm_profile_set_mock, raid_info_mock):

        raid_info_mock.return_value = self.raid_info
        expected_input = {
            'Server': {
                'HWConfigurationIrmc': {
                    '@Processing': 'execute',
                    'Adapters': {
                        'RAIDAdapter': [
                            {
                                'Arrays': {
                                    'Array': [
                                        {
                                            '@Number': 1,
                                            '@ConfigurationType': 'Setting',
                                            'PhysicalDiskRefs': {
                                                'PhysicalDiskRef': [
                                                    {
                                                        '@Number': '0'
                                                    },
                                                    {
                                                        '@Number': '1'
                                                    }
                                                ]
                                            }
                                        },
                                    ]
                                },
                                'LogicalDrives': {
                                    'LogicalDrive': [
                                        {
                                            '@Number': 0,
                                            '@Action': 'Create',
                                            'RaidLevel': '0',
                                            'InitMode': 'slow',
                                            'Size': {
                                                '@Unit': 'GB',
                                                '#text': 100
                                            },

                                        },
                                        {
                                            '@Number': 1,
                                            '@Action': 'Create',
                                            'RaidLevel': '1',
                                            'InitMode': 'slow',
                                            'Size': {
                                                '@Unit': 'GB',
                                                '#text': 100
                                            },
                                            'ArrayRefs': {
                                                'ArrayRef': [
                                                    {
                                                        '@Number': 1
                                                    }
                                                ]
                                            }
                                        }
                                    ]
                                }
                            }
                        ]
                    },
                    '@Version': '1.00'
                },
                '@Version': '1.01'
            }
        }
        target_raid_config = {
            'logical_disks':
                [
                    {
                        'size_gb': 100,
                        'raid_level': '0',
                    },
                    {
                        'size_gb': 100,
                        'raid_level': '1',
                        'physical_disks': [
                            '0',
                            '1'
                        ]
                    },
                ]
        }

        elcm_profile_set_mock.return_value = {
            "Session": {
                "Id": 1,
                "A_Param": "abc123"
            }
        }
        session_id = 1
        session_timeout = 1800
        operation = 'CONFIG_RAID'

        elcm.create_raid_configuration(
            self.irmc_info, target_raid_config=target_raid_config)

        session_mock.assert_called_once_with(self.irmc_info, operation,
                                             session_id, session_timeout)
        # Check raid_input data
        elcm_profile_set_mock.assert_called_once_with(
            self.irmc_info, expected_input)
        raid_info_mock.assert_called_once_with(self.irmc_info)

    @mock.patch.object(elcm, 'get_raid_adapter')
    @mock.patch.object(elcm, 'elcm_profile_set')
    @mock.patch.object(elcm, '_process_session_data')
    def test_create_raid_10_in_target_raid_config(
            self, session_mock, elcm_profile_set_mock, raid_info_mock):

        raid_info_mock.return_value = self.raid_info
        expected_input = {
            'Server': {
                'HWConfigurationIrmc': {
                    '@Processing': 'execute',
                    'Adapters': {
                        'RAIDAdapter': [
                            {
                                'Arrays': {
                                    'Array': []
                                },
                                'LogicalDrives': {
                                    'LogicalDrive': [
                                        {
                                            '@Number': 0,
                                            '@Action': 'Create',
                                            'RaidLevel': '10',
                                            'InitMode': 'slow',
                                            'Size': {
                                                '@Unit': 'GB',
                                                '#text': 100
                                            }
                                        }
                                    ]
                                }
                            }
                        ]
                    },
                    '@Version': '1.00'
                },
                '@Version': '1.01'
            }
        }

        target_raid_config = {
            'logical_disks':
                [
                    {
                        'size_gb': 100,
                        'raid_level': '10',
                    }
                ]
        }

        elcm_profile_set_mock.return_value = {
            "Session": {
                "Id": 1,
                "A_Param": "abc123"
            }
        }
        session_id = 1
        session_timeout = 1800
        operation = 'CONFIG_RAID'

        elcm.create_raid_configuration(self.irmc_info,
                                       target_raid_config=target_raid_config)

        session_mock.assert_called_once_with(self.irmc_info, operation,
                                             session_id, session_timeout)
        # Check raid_input data
        elcm_profile_set_mock.assert_called_once_with(
            self.irmc_info, expected_input)
        raid_info_mock.assert_called_once_with(self.irmc_info)

    @mock.patch.object(elcm, 'get_raid_adapter')
    @mock.patch.object(elcm, 'elcm_profile_set')
    @mock.patch.object(elcm, '_process_session_data')
    def test_create_raid_50_in_target_raid_config(
            self, session_mock, elcm_profile_set_mock, raid_info_mock):

        raid_info_mock.return_value = self.raid_info
        expected_input = {
            'Server': {
                'HWConfigurationIrmc': {
                    '@Processing': 'execute',
                    'Adapters': {
                        'RAIDAdapter': [
                            {
                                'Arrays': {
                                    'Array': []
                                },
                                'LogicalDrives': {
                                    'LogicalDrive': [
                                        {
                                            '@Number': 0,
                                            '@Action': 'Create',
                                            'RaidLevel': '50',
                                            'InitMode': 'slow',
                                            'Size': {
                                                '@Unit': 'GB',
                                                '#text': 100
                                            }
                                        }
                                    ]
                                }
                            }
                        ]
                    },
                    '@Version': '1.00'
                },
                '@Version': '1.01'
            }
        }
        target_raid_config = {
            'logical_disks':
                [
                    {
                        'size_gb': 100,
                        'raid_level': '50',
                    }
                ]
        }

        elcm_profile_set_mock.return_value = {
            "Session": {
                "Id": 1,
                "A_Param": "abc123"
            }
        }
        session_id = 1
        session_timeout = 1800
        operation = 'CONFIG_RAID'

        elcm.create_raid_configuration(self.irmc_info,
                                       target_raid_config=target_raid_config)

        session_mock.assert_called_once_with(self.irmc_info, operation,
                                             session_id, session_timeout)
        # Check raid_input data
        elcm_profile_set_mock.assert_called_once_with(
            self.irmc_info, expected_input)

        raid_info_mock.assert_called_once_with(self.irmc_info)

    @mock.patch.object(elcm, 'elcm_profile_get')
    @mock.patch.object(elcm, '_create_raid_adapter_profile')
    def test_get_raid_config_with_logical_drives(
            self, create_raid_adapter_mock, elcm_profile_get_mock):

        profile_name = 'RAIDAdapter'
        elcm_profile_get_mock.return_value = {
            'Server': {
                'HWConfigurationIrmc': {
                    'Adapters': {
                        'RAIDAdapter': [
                            {
                                '@AdapterId': 'RAIDAdapter0',
                                '@ConfigurationType': 'Addressing',
                                'Arrays': {
                                    'Array': [
                                        {
                                            '@Number': 0,
                                            '@ConfigurationType': 'Addressing',
                                            'PhysicalDiskRefs': {
                                                'PhysicalDiskRef': [
                                                    {
                                                        '@Number': '1'
                                                    }
                                                ]
                                            }
                                        }
                                    ]
                                },
                                'LogicalDrives': {
                                    'LogicalDrive': [
                                        {
                                            '@Number': 0,
                                            '@Action': 'None',
                                            'RaidLevel': '0',
                                            'InitMode': 'slow',
                                            'Size': {
                                                '@Unit': 'GB',
                                                '#text': 100
                                            },
                                            'ArrayRefs': {
                                                'ArrayRef': [
                                                    {
                                                        '@Number': 0
                                                    }
                                                ]
                                            }
                                        }
                                    ]
                                },
                                'PhysicalDisks': {
                                    'PhysicalDisk': [
                                        {
                                            '@Number': '0',
                                            '@Action': 'None',
                                            'Slot': 0,
                                            'PDStatus': 'Operational'
                                        }
                                    ]
                                }
                            }
                        ]
                    },
                    '@Version': '1.00'
                },
                '@Version': '1.01'
            }
        }

        elcm.get_raid_adapter(irmc_info=self.irmc_info)
        elcm_profile_get_mock.assert_called_once_with(
            self.irmc_info, profile_name)
        create_raid_adapter_mock.assert_called_once_with(self.irmc_info)

    @mock.patch.object(elcm, 'get_raid_adapter')
    @mock.patch.object(elcm, 'elcm_profile_set')
    @mock.patch.object(elcm, 'elcm_profile_delete')
    @mock.patch.object(elcm, '_process_session_data')
    def test_delete_raid_adapter(
        self, session_mock, elcm_profile_delete_mock, elcm_profile_set_mock,
            raid_info_mock):
        raid_info_mock.return_value = {
            'Server': {
                'HWConfigurationIrmc': {
                    'Adapters': {
                        'RAIDAdapter': [
                            {
                                '@AdapterId': 'RAIDAdapter0',
                                '@ConfigurationType': 'Addressing',
                                'Arrays': {
                                    'Array': [
                                        {
                                            '@Number': 0,
                                            '@ConfigurationType': 'Addressing',
                                            'PhysicalDiskRefs': {
                                                'PhysicalDiskRef': [
                                                    {
                                                        '@Number': '1'
                                                    },
                                                    {
                                                        '@Number': '4'
                                                    }
                                                ]
                                            }
                                        }
                                    ]
                                },
                                'LogicalDrives': {
                                    'LogicalDrive': [
                                        {
                                            '@Number': 0,
                                            '@Action': 'None',
                                            'RaidLevel': '0',
                                            'ArrayRefs': {
                                                'ArrayRef': [
                                                    {
                                                        '@Number': 0
                                                    }
                                                ]
                                            }
                                        }
                                    ]
                                },
                                'PhysicalDisks': {
                                    'PhysicalDisk': [
                                        {
                                            '@Number': '1',
                                            '@Action': 'None',
                                            'Slot': 1,
                                        },
                                        {
                                            '@Number': '4',
                                            '@Action': 'None',
                                            'Slot': 4,
                                        }
                                    ]
                                }
                            }
                        ]
                    },
                    '@Version': '1.00'
                },
                '@Version': '1.01'
            }
        }

        expected_input = {
            'Server': {
                'HWConfigurationIrmc': {
                    '@Processing': 'execute',
                    'Adapters': {
                        'RAIDAdapter': [
                            {
                                '@AdapterId': 'RAIDAdapter0',
                                '@ConfigurationType': 'Addressing',
                                'Arrays': {
                                    'Array': [
                                        {
                                            '@Number': 0,
                                            '@ConfigurationType': 'Addressing',
                                            'PhysicalDiskRefs': {
                                                'PhysicalDiskRef': [
                                                    {
                                                        '@Number': '1'
                                                    },
                                                    {
                                                        '@Number': '4'
                                                    }
                                                ]
                                            }
                                        }
                                    ]
                                },
                                'LogicalDrives': {
                                    'LogicalDrive': [
                                        {
                                            '@Number': 0,
                                            '@Action': 'Delete',
                                            'RaidLevel': '0',
                                            'ArrayRefs': {
                                                'ArrayRef': [
                                                    {
                                                        '@Number': 0
                                                    }
                                                ]
                                            }
                                        }
                                    ]
                                },
                                'PhysicalDisks': {
                                    'PhysicalDisk': [
                                        {
                                            '@Number': '1',
                                            '@Action': 'None',
                                            'Slot': 1,
                                        },
                                        {
                                            '@Number': '4',
                                            '@Action': 'None',
                                            'Slot': 4,
                                        }
                                    ]
                                }
                            }
                        ]
                    },
                    '@Version': '1.00'
                },
                '@Version': '1.01'
            }
        }
        profile_name = 'RAIDAdapter'

        elcm_profile_set_mock.return_value = {
            "Session": {
                "Id": 1,
                "A_Param": "abc123"
            }
        }
        session_id = 1
        session_timeout = 1800
        operation = 'CONFIG_RAID'

        elcm.delete_raid_configuration(irmc_info=self.irmc_info)
        session_mock.assert_called_once_with(self.irmc_info, operation,
                                             session_id, session_timeout)
        # Check raid_adapter data
        elcm_profile_set_mock.assert_called_once_with(
            self.irmc_info, expected_input)
        raid_info_mock.assert_called_once_with(self.irmc_info)
        elcm_profile_delete_mock.assert_called_once_with(self.irmc_info,
                                                         profile_name)

    @mock.patch.object(elcm, 'get_raid_adapter')
    @mock.patch.object(elcm, '_get_existing_logical_drives')
    @mock.patch.object(elcm, 'elcm_profile_set')
    @mock.patch.object(elcm, '_process_session_data')
    def test_delete_raid_adapter_without_existing_logical_drive(
            self, process_session_data_mock, elcm_profile_set_mock,
            existing_logical_drives_mock, raid_info_mock):
        raid_info_mock.return_value = {
            'Server': {
                'HWConfigurationIrmc': {
                    'Adapters': {
                        'RAIDAdapter': [
                            {
                                'key': 'value'
                            }
                        ]
                    }
                }
            }
        }

        existing_logical_drives_mock.return_value = None
        elcm.delete_raid_configuration(self.irmc_info)

        process_session_data_mock.assert_not_called()
        elcm_profile_set_mock.assert_not_called()

    @mock.patch.object(elcm, 'elcm_profile_delete')
    @mock.patch.object(elcm, 'elcm_profile_create')
    @mock.patch.object(elcm, 'elcm_session_get_status')
    @mock.patch.object(elcm, 'elcm_session_delete')
    @mock.patch.object(elcm, 'elcm_profile_get')
    def test_success_session_monitoring(self, elcm_profile_get_mock,
                                        elcm_session_delete_mock,
                                        elcm_session_mock,
                                        elcm_profile_create_mock,
                                        elcm_profile_delete_mock):
        profile_name = 'RAIDAdapter'
        param_path = 'Server/HWConfigurationIrmc/Adapters/RAIDAdapter'
        session_id = 1

        elcm_profile_create_mock.return_value = {
            "Session": {
                "Id": 1,
                "A_Param": "abc123"
            }
        }

        elcm_session_mock.return_value = {
            "Session": {
                "Id": 1,
                "Tag": "",
                "WorkSequence": "obtainProfileParameters",
                "Start": "2018\/03\/19 12:28:03",
                "Duration": 249,
                "Status": "terminated regularly"
            }
        }
        elcm._create_raid_adapter_profile(irmc_info=self.irmc_info)

        elcm_profile_get_mock.assert_called_once_with(self.irmc_info,
                                                      profile_name)
        elcm_session_delete_mock.assert_called_once_with(
            irmc_info=self.irmc_info, session_id=session_id, terminate=True)
        elcm_session_mock.assert_called_once_with(irmc_info=self.irmc_info,
                                                  session_id=session_id)
        elcm_profile_create_mock.assert_called_once_with(self.irmc_info,
                                                         param_path)
        elcm_profile_delete_mock.assert_called_once_with(self.irmc_info,
                                                         profile_name)

    @mock.patch.object(elcm, 'elcm_profile_delete')
    @mock.patch.object(elcm, 'elcm_profile_create')
    @mock.patch.object(elcm, 'elcm_session_get_status')
    @mock.patch.object(elcm, 'elcm_session_get_log')
    def test_fail_session_monitoring(self, elcm_session_get_log_mock,
                                     elcm_session_mock,
                                     elcm_profile_create_mock,
                                     elcm_profile_delete_mock):
        profile_name = 'RAIDAdapter'
        param_path = 'Server/HWConfigurationIrmc/Adapters/RAIDAdapter'

        session_id = 1

        elcm_profile_create_mock.return_value = {
            "Session": {
                "Id": 1,
                "A_Param": "abc123"
            }
        }

        elcm_session_mock.return_value = {
            "Session": {
                "Id": 1,
                "Tag": "",
                "WorkSequence": "obtainProfileParameters",
                "Start": "",
                "Duration": 0,
                "Status": "terminated - conflict with another running eLCM "
                          "activity"
            }
        }

        elcm_session_get_log_mock.return_value = {
            'SessionLog': {
                'Id': 1,
                'Tag': '',
                'WorkSequence': 'obtainProfileParameters',
                'Entries': {
                    'Entry': [
                        {
                            '@date': '2018\/03\/12 15:10:00',
                            '#text': 'createRaidDatabase: '
                                     'RAID Controller check start'
                        },
                        {
                            '@date': '2018\/03\/19 09:40:03',
                            '#text': 'LCMScheduler: Executing of '
                                     'obtainProfileParameters prohibited as '
                                     'obtainProfileParameters currently '
                                     'running'
                        }
                    ]
                }
            }
        }

        self.assertRaises(scci.SCCIClientError,
                          elcm._create_raid_adapter_profile, self.irmc_info)

        elcm_session_get_log_mock.assert_called_once_with(
            irmc_info=self.irmc_info, session_id=session_id)
        elcm_session_mock.assert_called_once_with(irmc_info=self.irmc_info,
                                                  session_id=session_id)
        elcm_profile_create_mock.assert_called_once_with(self.irmc_info,
                                                         param_path)
        elcm_profile_delete_mock.assert_called_once_with(self.irmc_info,
                                                         profile_name)

    @mock.patch.object(elcm, 'elcm_profile_delete')
    @mock.patch.object(elcm, 'elcm_profile_create')
    @mock.patch.object(elcm, '_process_session_data')
    def test_pass_raised_elcm_profile_not_found(
            self, _process_session_data_mock,
            elcm_profile_create_mock, elcm_profile_delete_mock):
        elcm_profile_delete_mock.side_effect = \
            elcm.ELCMProfileNotFound('not found')
        session_id = 1
        elcm_profile_create_mock.return_value = {
            'Session': {'Id': session_id,
                        'Status': 'running'}}
        session_timeout = 1800

        elcm._create_raid_adapter_profile(self.irmc_info)

        _process_session_data_mock.assert_called_once_with(
            self.irmc_info, 'CONFIG_RAID', session_id,
            session_timeout)
        elcm_profile_create_mock.assert_called_once_with(
            self.irmc_info, elcm.PARAM_PATH_RAID_CONFIG)
        elcm_profile_delete_mock.assert_called_once_with(
            self.irmc_info, elcm.PROFILE_RAID_CONFIG)

    @mock.patch.object(elcm, 'restore_bios_config')
    @mock.patch.object(elcm, 'elcm_profile_get_versions')
    def test_set_bios_configuration_without_versions(self,
                                                     get_versions_mock,
                                                     restore_bios_config_mock):
        settings = [{
            "name": "single_root_io_virtualization_support_enabled",
            "value": "True"
        }, {
            "name": "hyper_threading_enabled",
            "value": "True"
        }]

        get_versions_mock.return_value = {
            "Server": {
                "AdapterConfigIrmc": {
                    "@Version": "1.00"
                },
                "SystemConfig": {
                    "BiosConfig": {
                    }
                }
            }
        }

        bios_config_data = {
            'Server': {
                'SystemConfig': {
                    'BiosConfig': {
                        'PciConfig': {
                            'SingleRootIOVirtualizationSupportEnabled': True
                        },
                        'CpuConfig': {
                            'HyperThreadingEnabled': True,
                        }
                    }
                }
            }
        }
        elcm.set_bios_configuration(self.irmc_info, settings)
        restore_bios_config_mock.assert_called_once_with(self.irmc_info,
                                                         bios_config_data)

    @mock.patch.object(elcm, 'restore_bios_config')
    @mock.patch.object(elcm, 'elcm_profile_get_versions')
    def test_set_bios_configuration_with_versions(self,
                                                  get_versions_mock,
                                                  restore_bios_config_mock):
        settings = [{
            "name": "single_root_io_virtualization_support_enabled",
            "value": "True"
        }, {
            "name": "hyper_threading_enabled",
            "value": "True"
        }]

        get_versions_mock.return_value = {
            "Server": {
                "@Version": "1.01",
                "AdapterConfigIrmc": {
                    "@Version": "1.00"
                },
                "SystemConfig": {
                    "BiosConfig": {
                        "@Version": "1.02"
                    }
                }
            }
        }

        bios_config = {
            'Server': {
                'SystemConfig': {
                    'BiosConfig': {
                        'PciConfig': {
                            'SingleRootIOVirtualizationSupportEnabled': True
                        },
                        'CpuConfig': {
                            'HyperThreadingEnabled': True,
                        },
                        "@Version": "1.02"
                    }
                },
                "@Version": "1.01"
            }
        }
        elcm.set_bios_configuration(self.irmc_info, settings)
        restore_bios_config_mock.assert_called_once_with(self.irmc_info,
                                                         bios_config)

    @mock.patch.object(elcm, 'elcm_profile_get_versions')
    def test_set_bios_configuration_not_found(self,
                                              get_versions_mock):
        settings = [{
            "name": "single_root_io_virtualization_support_enabled",
            "value": "True"
        }, {
            "name": "setting1",
            "value": "True"
        }]

        get_versions_mock.return_value = {
            "Server": {
                "@Version": "1.01",
                "AdapterConfigIrmc": {
                    "@Version": "1.00"
                },
                "SystemConfig": {
                    "BiosConfig": {
                        "@Version": "1.02"
                    }
                }
            }
        }

        self.assertRaises(elcm.BiosConfigNotFound, elcm.set_bios_configuration,
                          self.irmc_info, settings)

    @mock.patch.object(elcm, 'restore_bios_config')
    @mock.patch.object(elcm, 'elcm_profile_get_versions')
    def test_set_bios_configuration_with_boolean_input(
            self, get_versions_mock, restore_bios_config_mock):
        settings = [{
            "name": "single_root_io_virtualization_support_enabled",
            "value": True
        }, {
            "name": "hyper_threading_enabled",
            "value": False
        }]

        get_versions_mock.return_value = {
            "Server": {
                "@Version": "1.01",
                "AdapterConfigIrmc": {
                    "@Version": "1.00"
                },
                "SystemConfig": {
                    "BiosConfig": {
                        "@Version": "1.02"
                    }
                }
            }
        }

        bios_config = {
            'Server': {
                'SystemConfig': {
                    'BiosConfig': {
                        'PciConfig': {
                            'SingleRootIOVirtualizationSupportEnabled': True
                        },
                        'CpuConfig': {
                            'HyperThreadingEnabled': False,
                        },
                        "@Version": "1.02"
                    }
                },
                "@Version": "1.01"
            }
        }
        elcm.set_bios_configuration(self.irmc_info, settings)
        restore_bios_config_mock.assert_called_once_with(self.irmc_info,
                                                         bios_config)

    @mock.patch.object(elcm, 'backup_bios_config')
    def test_get_bios_settings(self, backup_bios_config_mock):
        backup_bios_config_mock.return_value = {
            'bios_config': {
                "Server": {
                    "SystemConfig": {
                        "BiosConfig": {
                            "PciConfig": {
                                "SingleRootIOVirtualizationSupportEnabled":
                                    True,
                            },
                            "CpuConfig": {
                                "HyperThreadingEnabled": True,
                            }
                        }
                    }
                }
            }
        }
        result = elcm.get_bios_settings(self.irmc_info)
        expect_settings = [{
            "name": "single_root_io_virtualization_support_enabled",
            "value": "True"
        }, {
            "name": "hyper_threading_enabled",
            "value": "True"
        }]
        self.assertItemsEqual(expect_settings, result)
        backup_bios_config_mock.assert_called_once_with(
            self.irmc_info)
