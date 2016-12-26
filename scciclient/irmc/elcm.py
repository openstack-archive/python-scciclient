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
eLCM functionality.
"""

from oslo_serialization import jsonutils
import requests
import six

from scciclient.irmc import scci


"""
List of profile names
"""
PROFILE_BIOS_CONFIG = 'BiosConfig'
PROFILE_IRMC_CONFIG = 'IrmcConfig'


"""
List of URL paths for profiles
"""
URL_PATH_PROFILE_MGMT = '/rest/v1/Oem/eLCM/ProfileManagement'
URL_PATH_PROFILE_BIOS_CONFIG = (URL_PATH_PROFILE_MGMT + '/' +
                                PROFILE_BIOS_CONFIG)
URL_PATH_PROFILE_IRMC_CONFIG = (URL_PATH_PROFILE_MGMT + '/' +
                                PROFILE_IRMC_CONFIG)


"""
List of request params for profiles
"""
PARAM_PATH_BIOS_CONFIG = 'Server/SystemConfig/BiosConfig'
PARAM_PATH_IRMC_CONFIG = 'Server/SystemConfig/IrmcConfig'


"""
Minimum timeout values for some eLCM functions
"""
MIN_TIMEOUT_PROFILE_CREATE = 3 * 60  # 3 mins
MIN_TIMEOUT_PROFILE_SET = 3 * 60  # 3 mins


class ELCMInvalidResponse(scci.SCCIError):
    """ELCMInvalidResponse"""
    def __init__(self, message):
        super(ELCMInvalidResponse, self).__init__(message)


class ELCMProfileNotFound(scci.SCCIError):
    """ELCMProfileNotFound"""
    def __init__(self, message):
        super(ELCMProfileNotFound, self).__init__(message)


class ELCMSessionNotFound(scci.SCCIError):
    """ELCMSessionNotFound"""
    def __init__(self, message):
        super(ELCMSessionNotFound, self).__init__(message)


def _parse_elcm_response_body_as_json(response):
    """parse eLCM response body as json data

    :param response: eLCM response
    :return: json object if success
    :raise ELCMInvalidResponse: if the response does not contain valid
        json data.
    """
    body = response.text

    # NOTE: requests on python2 fails to parse some response body as json
    # even the response data is correct. It fails to split off the headers
    # part and the content part of the response. That leads to the whole data
    # is considered the content, and the json parser will fail.
    # cURL and requests on python 3 work correctly.

    # Workaround for python2, get the json part of the response
    if six.PY2:
        body_parts = body.split('\r\n')
        if len(body_parts) > 0:
            body = body_parts[-1]

    try:
        return jsonutils.loads(body)
    except (ValueError, TypeError):
        raise ELCMInvalidResponse('eLCM response does not contain valid json '
                                  'data. Response is "%s".' % body)


def elcm_request(irmc_info, method, path, **kwargs):
    """send an eLCM request to the server

    :param irmc_info: dict of iRMC params to access the server node
        {
          'irmc_address': host,
          'irmc_username': user_id,
          'irmc_password': password,
          'irmc_port': 80 or 443, default is 443,
          'irmc_auth_method': 'basic' or 'digest', default is 'basic',
          'irmc_client_timeout': timeout, default is 60,
          ...
        }
    :param method: request method such as 'GET', 'POST'
    :param path: url path for eLCM request
    :returns: requests.Response from SCCI server
    :raises SCCIInvalidInputError: if port and/or auth_method params
             are invalid
    :raises SCCIClientError: if SCCI failed
    """
    host = irmc_info['irmc_address']
    port = irmc_info.get('irmc_port', 443)
    auth_method = irmc_info.get('irmc_auth_method', 'basic')
    userid = irmc_info['irmc_username']
    password = irmc_info['irmc_password']
    client_timeout = irmc_info.get('irmc_client_timeout', 60)

    # Request headers, params, and data
    headers = kwargs.get('headers', {'Accept': 'application/json'})
    params = kwargs.get('params')
    data = kwargs.get('data')

    auth_obj = None
    try:
        protocol = {80: 'http', 443: 'https'}[port]
        auth_obj = {
            'basic': requests.auth.HTTPBasicAuth(userid, password),
            'digest': requests.auth.HTTPDigestAuth(userid, password)
        }[auth_method.lower()]

    except KeyError:
        raise scci.SCCIInvalidInputError(
            ("Invalid port %(port)d or " +
             "auth_method for method %(auth_method)s") %
            {'port': port, 'auth_method': auth_method})

    try:
        r = requests.request(method,
                             protocol + '://' + host + path,
                             headers=headers,
                             params=params,
                             data=data,
                             verify=False,
                             timeout=client_timeout,
                             allow_redirects=False,
                             auth=auth_obj)
    except requests.exceptions.RequestException as requests_exception:
        raise scci.SCCIClientError(requests_exception)

    # Process status_code 401
    if r.status_code == 401:
        raise scci.SCCIClientError('UNAUTHORIZED')

    return r


def elcm_profile_get(irmc_info, profile_name):
    """send an eLCM request to get profile data

    :param irmc_info: node info
    :param profile_name: name of profile
    :returns: dict object of profile data if succeed
    :raises: ELCMProfileNotFound if profile does not exist
    :raises: SCCIClientError if SCCI failed
    """
    # Send GET request to the server
    resp = elcm_request(irmc_info,
                        method='GET',
                        path=URL_PATH_PROFILE_MGMT + '/' + profile_name)

    if resp.status_code == 200:
        return _parse_elcm_response_body_as_json(resp)
    elif resp.status_code == 404:
        raise ELCMProfileNotFound('Profile "%s" not found '
                                  'in the profile store.' % profile_name)
    else:
        raise scci.SCCIClientError(('Failed to get profile "%(profile)s" with '
                                    'error code %(error)s' %
                                    {'profile': profile_name,
                                     'error': resp.status_code}))


def elcm_profile_create(irmc_info, param_path):
    """send an eLCM request to create profile

    To create a profile, a new session is spawned with status 'running'.
    When profile is created completely, the session ends.

    :param irmc_info: node info
    :param param_path: path of profile
    :returns: dict object of session info if succeed
        {
          'Session':
          {
            'Id': id
            'Status': 'activated'
            ...
          }
        }
    :raises: SCCIClientError if SCCI failed
    """
    # Send POST request to the server
    # NOTE: This task may take time, if the passed timeout value is
    # less than the minimum required value, correct it.
    _irmc_info = dict(irmc_info)
    try:
        timeout = _irmc_info['irmc_client_timeout']
        if timeout is not None and 0 < timeout < MIN_TIMEOUT_PROFILE_CREATE:
            _irmc_info['irmc_client_timeout'] = MIN_TIMEOUT_PROFILE_CREATE
    except KeyError:
        # No key irmc_client_timeout in the dict, use the default value
        _irmc_info['irmc_client_timeout'] = MIN_TIMEOUT_PROFILE_CREATE

    resp = elcm_request(_irmc_info,
                        method='POST',
                        path=URL_PATH_PROFILE_MGMT + '/get',
                        params={'PARAM_PATH': param_path})

    if resp.status_code == 202:
        return _parse_elcm_response_body_as_json(resp)
    else:
        raise scci.SCCIClientError(('Failed to create profile for path '
                                    '"%(param_path)s" with error code '
                                    '%(error)s' %
                                    {'param_path': param_path,
                                     'error': resp.status_code}))


def elcm_profile_set(irmc_info, input_data):
    """send an eLCM request to set param values

    To apply param values, a new session is spawned with status 'running'.
    When values are applied or error, the session ends.

    :param irmc_info: node info
    :param input_data: param values to apply, eg.
        {
          'Server':
          {
            'SystemConfig':
            {
              'BiosConfig':
              {
                '@Processing': 'execute',
                -- config data --
              }
            }
          }
        }
    :returns: dict object of session info if succeed
        {
          'Session':
          {
            'Id': id
            'Status': 'activated'
            ...
          }
        }
    :raises: SCCIClientError if SCCI failed
    """
    # Prepare the data to apply
    if isinstance(input_data, dict):
        data = jsonutils.dumps(input_data)
    else:
        data = input_data

    # Send POST request to the server
    # NOTE: This task may take time, if the passed timeout value is
    # less than the minimum required value, correct it.
    _irmc_info = dict(irmc_info)
    try:
        timeout = _irmc_info['irmc_client_timeout']
        if timeout is not None and 0 < timeout < MIN_TIMEOUT_PROFILE_SET:
            _irmc_info['irmc_client_timeout'] = MIN_TIMEOUT_PROFILE_SET
    except KeyError:
        # No key irmc_client_timeout in the dict, use the default value
        _irmc_info['irmc_client_timeout'] = MIN_TIMEOUT_PROFILE_SET

    resp = elcm_request(_irmc_info,
                        method='POST',
                        path=URL_PATH_PROFILE_MGMT + '/set',
                        headers={'Content-type':
                                 'application/x-www-form-urlencoded'},
                        data=data)

    if resp.status_code == 202:
        return _parse_elcm_response_body_as_json(resp)
    else:
        raise scci.SCCIClientError(('Failed to apply param values with '
                                    'error code %(error)s' %
                                    {'error': resp.status_code}))


def elcm_profile_delete(irmc_info, profile_name):
    """send an eLCM request to delete a profile

    :param irmc_info: node info
    :param profile_name: name of profile
    :raises: ELCMProfileNotFound if the profile does not exist
    :raises: SCCIClientError if SCCI failed
    """
    # Send DELETE request to the server
    resp = elcm_request(irmc_info,
                        method='DELETE',
                        path=URL_PATH_PROFILE_MGMT + '/' + profile_name)

    if resp.status_code == 200:
        # Profile deleted
        return
    elif resp.status_code == 404:
        # Profile not found
        raise ELCMProfileNotFound('Profile "%s" not found '
                                  'in the profile store.' % profile_name)
    else:
        raise scci.SCCIClientError(('Failed to delete profile "%(profile)s" '
                                    'with error code %(error)s' %
                                    {'profile': profile_name,
                                     'error': resp.status_code}))


def elcm_session_list(irmc_info):
    """send an eLCM request to list all sessions

    :param irmc_info: node info
    :returns: dict object of sessions if succeed
        {
          'SessionList':
          {
            'Contains':
            [
              { 'Id': id1, 'Name': name1 },
              { 'Id': id2, 'Name': name2 },
              { 'Id': idN, 'Name': nameN },
            ]
          }
        }
    :raises: SCCIClientError if SCCI failed
    """
    # Send GET request to the server
    resp = elcm_request(irmc_info,
                        method='GET',
                        path='/sessionInformation/')

    if resp.status_code == 200:
        return _parse_elcm_response_body_as_json(resp)
    else:
        raise scci.SCCIClientError(('Failed to list sessions with '
                                    'error code %s' % resp.status_code))


def elcm_session_get_status(irmc_info, session_id):
    """send an eLCM request to get session status

    :param irmc_info: node info
    :param session_id: session id
    :returns: dict object of session info if succeed
        {
          'Session':
          {
            'Id': id
            'Status': status
            ...
          }
        }
    :raises: ELCMSessionNotFound if the session does not exist
    :raises: SCCIClientError if SCCI failed
    """
    # Send GET request to the server
    resp = elcm_request(irmc_info,
                        method='GET',
                        path='/sessionInformation/%s/status' % session_id)

    if resp.status_code == 200:
        return _parse_elcm_response_body_as_json(resp)
    elif resp.status_code == 404:
        raise ELCMSessionNotFound('Session "%s" does not exist' % session_id)
    else:
        raise scci.SCCIClientError(('Failed to get status of session '
                                    '"%(session)s" with error code %(error)s' %
                                    {'session': session_id,
                                     'error': resp.status_code}))


def elcm_session_get_log(irmc_info, session_id):
    """send an eLCM request to get session log

    :param irmc_info: node info
    :param session_id: session id
    :returns: dict object of session log if succeed
        {
          'Session':
          {
            'Id': id
            ...
          }
        }
    :raises: ELCMSessionNotFound if the session does not exist
    :raises: SCCIClientError if SCCI failed
    """
    # Send GET request to the server
    resp = elcm_request(irmc_info,
                        method='GET',
                        path='/sessionInformation/%s/log' % session_id)

    if resp.status_code == 200:
        return _parse_elcm_response_body_as_json(resp)
    elif resp.status_code == 404:
        raise ELCMSessionNotFound('Session "%s" does not exist' % session_id)
    else:
        raise scci.SCCIClientError(('Failed to get log of session '
                                    '"%(session)s" with error code %(error)s' %
                                    {'session': session_id,
                                     'error': resp.status_code}))


def elcm_session_terminate(irmc_info, session_id):
    """send an eLCM request to terminate a session

    :param irmc_info: node info
    :param session_id: session id
    :raises: ELCMSessionNotFound if the session does not exist
    :raises: SCCIClientError if SCCI failed
    """
    # Send DELETE request to the server
    resp = elcm_request(irmc_info,
                        method='DELETE',
                        path='/sessionInformation/%s/terminate' % session_id)

    if resp.status_code == 200:
        return
    elif resp.status_code == 404:
        raise ELCMSessionNotFound('Session "%s" does not exist' % session_id)
    else:
        raise scci.SCCIClientError(('Failed to terminate session '
                                    '"%(session)s" with error code %(error)s' %
                                    {'session': session_id,
                                     'error': resp.status_code}))


def elcm_session_delete(irmc_info, session_id, terminate=False):
    """send an eLCM request to remove a session from the session list

    :param irmc_info: node info
    :param session_id: session id
    :param terminate: a running session must be terminated before removing
    :raises: ELCMSessionNotFound if the session does not exist
    :raises: SCCIClientError if SCCI failed
    """
    # Terminate the session first if needs to
    if terminate:
        try:
            elcm_session_terminate(irmc_info=irmc_info,
                                   session_id=session_id)
        except Exception:
            # Ignore this error
            pass

    # Send DELETE request to the server
    resp = elcm_request(irmc_info,
                        method='DELETE',
                        path='/sessionInformation/%s/remove' % session_id)

    if resp.status_code == 200:
        return
    elif resp.status_code == 404:
        raise ELCMSessionNotFound('Session "%s" does not exist' % session_id)
    else:
        raise scci.SCCIClientError(('Failed to remove session '
                                    '"%(session)s" with error code %(error)s' %
                                    {'session': session_id,
                                     'error': resp.status_code}))
