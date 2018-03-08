# Copyright 2017 Brocade Communications Systems, Inc.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ipaddress import ip_address
from st2common.runners.base_action import Action
from ne_base import capture_exceptions


class DeleteDeviceCredentials(Action):

    """
       Implements the logic to delete the device
       credentials from st2 data store.
    """

    def __init__(self, config=None, action_service=None):
        super(
            DeleteDeviceCredentials,
            self).__init__(
            config=config,
            action_service=action_service)

    @capture_exceptions
    def run(self, mgmt_ip):
        try:
            ip_address(mgmt_ip)
        except Exception as err:
            self.logger.error("Invalid IP address: %s", mgmt_ip)
            raise AttributeError(err.message)
        lookup_key = self._get_lookup_key(mgmt_ip, 'user')
        user_kv = self.action_service.get_value(name=lookup_key, local=False)
        if not user_kv:
            self.logger.error("Device not registered. Verify the device ip.")
            exit(-1)
        self._delete_device(mgmt_ip)

    def _get_lookup_key(self, host, key):
        return 'switch.%s.%s' % (host, key)

    def _delete_device(self, host):

        keylist = ['user', 'passwd', 'enablepass', 'ostype', 'snmpver', 'snmpport',
                   'snmpv2c', 'v3user', 'v3auth', 'v3priv', 'authpass', 'privpass',
                   'restproto']

        for item in keylist:
            lookup_name = self._get_lookup_key(host, item)
            self.action_service.delete_value(name=lookup_name, local=False)
