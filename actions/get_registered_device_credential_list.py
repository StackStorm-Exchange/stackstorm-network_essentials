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

from st2actions.runners.pythonrunner import Action


class GetRegisteredDeviceList(Action):

    """
       Implements the logic to list the devices
       that is stored in st2 store.
       Return value is dict of {<switchip>: <snmpver>}
       For example:
            {'10.24.12.106': 'v3', '10.24.85.102': 'None'}
    """

    def __init__(self, config=None, action_service=None):
        super(
            GetRegisteredDeviceList,
            self).__init__(
            config=config,
            action_service=action_service)
        self.host = None
        self.device = {}

    def run(self, mgmt_ip=None):
        self._get_device(mgmt_ip)
        return (self.device)

    def _get_prefix(self, host):
        if host:
            return 'switch.%s.' % (host)
        else:
            return 'switch.'

    def _get_device(self, host):

        devprefix = self._get_prefix(host)
        listval = self.action_service.list_values(local=False, prefix=devprefix)

        for item in listval:
            if 'snmpver' in item.name:
                key = item.name
                switchip = key[7:].rsplit('.', 1)[0]
                value = item.value
                self.device[switchip] = value
                if host:
                    return
