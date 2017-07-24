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

import time

from oslo_serialization import jsonutils
import requests

from scciclient.irmc import scci


"""
List of profile names
"""
PROFILE_BIOS_CONFIG = 'BiosConfig'


"""
List of URL paths for profiles
"""
URL_PATH_PROFILE_MGMT = '/rest/v1/Oem/eLCM/ProfileManagement/'


"""
List of request params for profiles
"""
PARAM_PATH_SYSTEM_CONFIG = 'Server/SystemConfig/'
PARAM_PATH_BIOS_CONFIG = PARAM_PATH_SYSTEM_CONFIG + PROFILE_BIOS_CONFIG


"""
Timeout values
"""
PROFILE_CREATE_TIMEOUT = 300  # 300 secs
PROFILE_SET_TIMEOUT = 300  # 300 secs
BIOS_CONFIG_SESSION_TIMEOUT = 30 * 60  # 30 mins


class ELCMInvalidResponse(scci.SCCIError):
    def __init__(self, message):
        super(ELCMInvalidResponse, self).__init__(message)


class ELCMProfileNotFound(scci.SCCIError):
    def __init__(self, message):
        super(ELCMProfileNotFound, self).__init__(message)


class ELCMSessionNotFound(scci.SCCIError):
    def __init__(self, message):
        super(ELCMSessionNotFound, self).__init__(message)


class ELCMSessionTimeout(scci.SCCIError):
    def __init__(self, message):
        super(ELCMSessionTimeout, self).__init__(message)


class SecureBootConfigNotFound(scci.SCCIError):
    def __init__(self, message):
        super(SecureBootConfigNotFound, self).__init__(message)


def _parse_elcm_response_body_as_json(response):
    """parse eLCM response body as json data

    eLCM response should be in form of:
    _
    Key1: value1  <-- optional -->
    Key2: value2  <-- optional -->
    KeyN: valueN  <-- optional -->

    - CRLF -

    JSON string
    -

    :param response: eLCM response
    :return: json object if success
    :raise ELCMInvalidResponse: if the response does not contain valid
        json data.
    """
    try:
        body = response.text
        body_parts = body.split('\r\n')
        if len(body_parts) > 0:
            return jsonutils.loads(body_parts[-1])
        else:
            return None
    except (TypeError, ValueError):
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


def elcm_profile_list(irmc_info):
    """send an eLCM request to list all profiles

    :param irmc_info: node info
    :returns: dict object of profiles if succeed
        {
          'Links':
          {
            'profileStore':
            [
              { '@odata.id': id1 },
              { '@odata.id': id2 },
              { '@odata.id': idN },
            ]
          }
        }
    :raises: SCCIClientError if SCCI failed
    """
    # Send GET request to the server
    resp = elcm_request(irmc_info,
                        method='GET',
                        path=URL_PATH_PROFILE_MGMT)

    if resp.status_code == 200:
        return _parse_elcm_response_body_as_json(resp)
    else:
        raise scci.SCCIClientError(('Failed to list profiles with '
                                    'error code %s' % resp.status_code))


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
                        path=URL_PATH_PROFILE_MGMT + profile_name)

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
    # NOTE: This task may take time, so set a timeout
    _irmc_info = dict(irmc_info)
    _irmc_info['irmc_client_timeout'] = PROFILE_CREATE_TIMEOUT

    resp = elcm_request(_irmc_info,
                        method='POST',
                        path=URL_PATH_PROFILE_MGMT + 'get',
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
    # NOTE: This task may take time, so set a timeout
    _irmc_info = dict(irmc_info)
    _irmc_info['irmc_client_timeout'] = PROFILE_SET_TIMEOUT

    resp = elcm_request(_irmc_info,
                        method='POST',
                        path=URL_PATH_PROFILE_MGMT + 'set',
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
                        path=URL_PATH_PROFILE_MGMT + profile_name)

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
        # Get session status to check
        session = elcm_session_get_status(irmc_info, session_id)
        status = session['Session']['Status']

        # Terminate session if it is activated or running
        if status == 'running' or status == 'activated':
            elcm_session_terminate(irmc_info, session_id)

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


def _process_session_bios_config(irmc_info, operation, session_id,
                                 session_timeout=BIOS_CONFIG_SESSION_TIMEOUT):
    """process session for Bios config backup/restore operation

    :param irmc_info: node info
    :param operation: one of 'BACKUP' and 'RESTORE'
    :param session_id: session id
    :param session_timeout: session timeout
    :return: a dict with following values:
        {
            'bios_config': <data in case of BACKUP operation>,
            'warning': <warning message if there is>
        }
    """
    session_expiration = time.time() + session_timeout

    while time.time() < session_expiration:
        # Get session status to check
        session = elcm_session_get_status(irmc_info=irmc_info,
                                          session_id=session_id)

        status = session['Session']['Status']
        if status == 'running' or status == 'activated':
            # Sleep a bit
            time.sleep(5)
        elif status == 'terminated regularly':
            result = {}

            if operation == 'BACKUP':
                # Bios profile is created, get the data now
                result['bios_config'] = elcm_profile_get(
                    irmc_info=irmc_info,
                    profile_name=PROFILE_BIOS_CONFIG)
            elif operation == 'RESTORE':
                # Bios config applied successfully
                pass

            # Cleanup operation by deleting related session and profile.
            # In case of error, report it as warning instead of error.
            try:
                elcm_session_delete(irmc_info=irmc_info,
                                    session_id=session_id,
                                    terminate=True)
                elcm_profile_delete(irmc_info=irmc_info,
                                    profile_name=PROFILE_BIOS_CONFIG)
            except scci.SCCIError as e:
                result['warning'] = e

            return result
        else:
            # Error occurred, get session log to see what happened
            session_log = elcm_session_get_log(irmc_info=irmc_info,
                                               session_id=session_id)

            raise scci.SCCIClientError(
                ('Failed to %(operation)s bios config. '
                 'Session log is "%(session_log)s".' %
                 {'operation': operation,
                  'session_log': jsonutils.dumps(session_log)}))

    else:
        raise ELCMSessionTimeout(
            ('Failed to %(operation)s bios config. '
             'Session %(session_id)s log is timeout.' %
             {'operation': operation,
              'session_id': session_id}))


def backup_bios_config(irmc_info):
    """backup current bios configuration

    This function sends a BACKUP request to the server. Then when the bios
    config data are ready for retrieving, it will return the data to the
    caller. Note that this operation may take time.

    :param irmc_info: node info
    :return: a dict with following values:
        {
            'bios_config': <bios config data>,
            'warning': <warning message if there is>
        }
    """
    # 1. Make sure there is no BiosConfig profile in the store
    try:
        # Get the profile first, if not found, then an exception
        # will be raised.
        elcm_profile_get(irmc_info=irmc_info,
                         profile_name=PROFILE_BIOS_CONFIG)
        # Profile found, delete it
        elcm_profile_delete(irmc_info=irmc_info,
                            profile_name=PROFILE_BIOS_CONFIG)
    except ELCMProfileNotFound:
        # Ignore this error as it's not an error in this case
        pass

    # 2. Send request to create a new profile for BiosConfig
    session = elcm_profile_create(irmc_info=irmc_info,
                                  param_path=PARAM_PATH_BIOS_CONFIG)

    # 3. Profile creation is in progress, we monitor the session
    session_timeout = irmc_info.get('irmc_bios_session_timeout',
                                    BIOS_CONFIG_SESSION_TIMEOUT)
    return _process_session_bios_config(
        irmc_info=irmc_info,
        operation='BACKUP',
        session_id=session['Session']['Id'],
        session_timeout=session_timeout)


def restore_bios_config(irmc_info, bios_config):
    """restore bios configuration

    This function sends a RESTORE request to the server. Then when the bios
    is ready for restoring, it will apply the provided settings and return.
    Note that this operation may take time.

    :param irmc_info: node info
    :param bios_config: bios config
    """
    def _process_bios_config():
        try:
            if isinstance(bios_config, dict):
                input_data = bios_config
            else:
                input_data = jsonutils.loads(bios_config)

            # The input data must contain flag "@Processing":"execute" in the
            # equivalent section.
            bios_cfg = input_data['Server']['SystemConfig']['BiosConfig']
            bios_cfg['@Processing'] = 'execute'

            return input_data
        except (TypeError, ValueError, KeyError):
            raise scci.SCCIInvalidInputError(
                ('Invalid input bios config "%s".' % bios_config))

    # 1. Parse the bios config and create the input data
    input_data = _process_bios_config()

    # 2. Make sure there is no BiosConfig profile in the store
    try:
        # Get the profile first, if not found, then an exception
        # will be raised.
        elcm_profile_get(irmc_info=irmc_info,
                         profile_name=PROFILE_BIOS_CONFIG)
        # Profile found, delete it
        elcm_profile_delete(irmc_info=irmc_info,
                            profile_name=PROFILE_BIOS_CONFIG)
    except ELCMProfileNotFound:
        # Ignore this error as it's not an error in this case
        pass

    # 3. Send a request to apply the param values
    session = elcm_profile_set(irmc_info=irmc_info,
                               input_data=input_data)

    # 4. Param values applying is in progress, we monitor the session
    session_timeout = irmc_info.get('irmc_bios_session_timeout',
                                    BIOS_CONFIG_SESSION_TIMEOUT)
    _process_session_bios_config(irmc_info=irmc_info,
                                 operation='RESTORE',
                                 session_id=session['Session']['Id'],
                                 session_timeout=session_timeout)


def get_secure_boot_mode(irmc_info):
    """Get the status if secure boot is enabled or not.

    :param irmc_info: node info.
    :raises: SecureBootConfigNotFound, if there is no configuration for secure
             boot mode in the bios.
    :return: True if secure boot mode is enabled on the node, False otherwise.
    """

    result = backup_bios_config(irmc_info=irmc_info)

    try:
        bioscfg = result['bios_config']['Server']['SystemConfig']['BiosConfig']
        return bioscfg['SecurityConfig']['SecureBootControlEnabled']

    except KeyError:
        msg = ("Failed to get secure boot mode from server %s. Upgrading iRMC "
               "firmware may resolve this issue." % irmc_info['irmc_address'])
        raise SecureBootConfigNotFound(msg)


def set_secure_boot_mode(irmc_info, enable):
    """Enable/Disable secure boot on the server.

    :param irmc_info: node info
    :param enable: True, if secure boot needs to be
                   enabled for next boot, else False.
    """

    bios_config_data = {
        'Server': {
            'SystemConfig': {
                'BiosConfig': {
                    'SecurityConfig': {
                        'SecureBootControlEnabled': enable
                    }
                }
            }
        }
    }
    restore_bios_config(irmc_info=irmc_info, bios_config=bios_config_data)
