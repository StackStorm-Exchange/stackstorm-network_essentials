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
        self.host = None

    def run(self, mgmt_ip):
        self._delete_device(mgmt_ip)

    def _get_prefix(self, host):
        return 'switch.%s' % (host)

    def _delete_device(self, host):

        devprefix = self._get_prefix(host)
        listval = self.action_service.list_values(local=False, prefix=devprefix)

        for item in listval:
            self.action_service.delete_value(name=item.name, local=False)
