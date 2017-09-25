# Copyright 2017 Fujitsu Ltd.
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


class SCCIError(Exception):
    """SCCI Error

    This exception is general exception.
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


class ELCMInvalidResponse(SCCIError):
    def __init__(self, message):
        super(ELCMInvalidResponse, self).__init__(message)


class ELCMProfileNotFound(SCCIError):
    def __init__(self, message):
        super(ELCMProfileNotFound, self).__init__(message)


class ELCMSessionNotFound(SCCIError):
    def __init__(self, message):
        super(ELCMSessionNotFound, self).__init__(message)


class ELCMSessionTimeout(SCCIError):
    def __init__(self, message):
        super(ELCMSessionTimeout, self).__init__(message)


class SecureBootConfigNotFound(SCCIError):
    def __init__(self, message):
        super(SecureBootConfigNotFound, self).__init__(message)
