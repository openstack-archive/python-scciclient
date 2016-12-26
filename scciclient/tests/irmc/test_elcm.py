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

from oslo_utils import encodeutils
import requests
from requests_mock.contrib import fixture as rm_fixture
import testtools

from scciclient.irmc import elcm
from scciclient.irmc import scci


class ELCMTestCase(testtools.TestCase):
    """Tests for eLCM"""

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

    def test__parse_elcm_response_body_as_json_mix_content(self):
        content = ('key1:val1\nkey2:val2\n'
                   '{"1":1,"2":[123, "abc"],"3":3}')
        response = self._create_server_response(content)
        self.assertRaises(elcm.ELCMInvalidResponse,
                          elcm._parse_elcm_response_body_as_json,
                          response=response)

    def test__parse_elcm_response_body_as_json_ok(self):
        content = '{"1":1,"2":[123, "abc"],"3":3}'
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
            text='{abc123}')

        response = elcm.elcm_request(
            irmc_info,
            method='GET',
            path=elcm.URL_PATH_PROFILE_MGMT)

        self.assertEqual(200, response.status_code)

        expected = '{abc123}'
        self.assertEqual(expected, response.text)

    def test_elcm_request_protocol_https_ok(self):
        irmc_info = dict(self.irmc_info)
        irmc_info['irmc_port'] = 443

        self.requests_mock.register_uri(
            'GET',
            self._create_server_url(elcm.URL_PATH_PROFILE_MGMT,
                                    port=443),
            text='{abc123}')

        response = elcm.elcm_request(
            irmc_info,
            method='GET',
            path=elcm.URL_PATH_PROFILE_MGMT)

        self.assertEqual(200, response.status_code)

        expected = '{abc123}'
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
            self._create_server_url((elcm.URL_PATH_PROFILE_MGMT + '/' +
                                     profile_name)),
            status_code=404)

        self.assertRaises(elcm.ELCMProfileNotFound,
                          elcm.elcm_profile_get,
                          self.irmc_info,
                          profile_name=profile_name)

    def test_elcm_profile_get_failed(self):
        profile_name = elcm.PROFILE_BIOS_CONFIG
        self.requests_mock.register_uri(
            'GET',
            self._create_server_url((elcm.URL_PATH_PROFILE_MGMT + '/' +
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
            self._create_server_url((elcm.URL_PATH_PROFILE_MGMT + '/' +
                                     profile_name)),
            text=('{"Server":{'
                  '   "SystemConfig":{'
                  '     "BiosConfig":{'
                  '        "key":"val"'
                  '}}}}'))

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
            self._create_server_url(elcm.URL_PATH_PROFILE_MGMT + '/get'),
            status_code=200)  # Success code is 202

        self.assertRaises(scci.SCCIClientError,
                          elcm.elcm_profile_create,
                          self.irmc_info,
                          param_path=param_path)

    def test_elcm_profile_create_ok(self):
        param_path = elcm.PARAM_PATH_BIOS_CONFIG
        self.requests_mock.register_uri(
            'POST',
            self._create_server_url(elcm.URL_PATH_PROFILE_MGMT + '/get'),
            status_code=202,  # Success code is 202
            text=('{"Session":{'
                  '   "Id": 123,'
                  '   "Status": "activated"'
                  '}}'))

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
            self._create_server_url(elcm.URL_PATH_PROFILE_MGMT + '/set'),
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
            self._create_server_url(elcm.URL_PATH_PROFILE_MGMT + '/set'),
            status_code=202,  # Success code is 202
            text=('{"Session":{'
                  '   "Id": 123,'
                  '   "Status": "activated"'
                  '}}'))

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
            self._create_server_url((elcm.URL_PATH_PROFILE_MGMT + '/' +
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
            self._create_server_url((elcm.URL_PATH_PROFILE_MGMT + '/' +
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
            self._create_server_url((elcm.URL_PATH_PROFILE_MGMT + '/' +
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
            text=('{"SessionList":{'
                  '  "Contains":['
                  '  ]'
                  '}}'))

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
            text=('{"SessionList":{'
                  '   "Contains":['
                  '     { "Id": 1, "Name": "name1" },'
                  '     { "Id": 2, "Name": "name2" },'
                  '     { "Id": 3, "Name": "name3" }'
                  '   ]'
                  '}}'))

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
            text=('{"Session":{'
                  '   "Id": 123,'
                  '   "Status": "abc123"'
                  '}}'))

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
            text=('{"Session":{'
                  '   "Id": 123,'
                  '   "A_Param": "abc123"'
                  '}}'))

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
