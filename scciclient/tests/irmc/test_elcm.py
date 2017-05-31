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
    def test__process_session_bios_config_get_ok(self, mock_sleep,
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

        result = elcm._process_session_bios_config(irmc_info=self.irmc_info,
                                                   operation='BACKUP',
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
    def test__process_session_bios_config_set_ok(self, mock_sleep,
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

        elcm._process_session_bios_config(irmc_info=self.irmc_info,
                                          operation='RESTORE',
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
    def test__process_session_bios_config_timeout(self, mock_sleep,
                                                  mock_session_get,
                                                  mock_session_delete,
                                                  mock_profile_get,
                                                  mock_profile_delete):
        session_id = 123
        mock_session_get.return_value = {'Session': {'Id': session_id,
                                                     'Status': 'running'}}

        self.assertRaises(elcm.ELCMSessionTimeout,
                          elcm._process_session_bios_config,
                          irmc_info=self.irmc_info,
                          operation='BACKUP',
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
    def test__process_session_bios_config_error(self,
                                                mock_session_get,
                                                mock_session_get_log,
                                                mock_session_delete,
                                                mock_profile_delete):
        session_id = 123
        mock_session_get.return_value = {'Session': {'Id': session_id,
                                                     'Status': 'error'}}

        self.assertRaises(scci.SCCIClientError,
                          elcm._process_session_bios_config,
                          irmc_info=self.irmc_info,
                          operation='RESTORE',
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
                'SystemConfig': {
                    'BiosConfig': {
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
                'SystemConfig': {
                    'BiosConfig': {
                        'SecurityConfig': {
                            'SecureBootControlEnabled': False
                        }
                    }
                }
            }
        }
        restore_bios_config_mock.assert_called_once_with(
            irmc_info=self.irmc_info, bios_config=bios_config_data)
