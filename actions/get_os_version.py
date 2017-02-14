# Copyright 2016 Brocade Communications Systems, Inc.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ne_base import NosDeviceAction


class GetOsVersion(NosDeviceAction):
    """
       Implements the logic to get OS version of a devise.
       This action achieves the below functionality
           1.Get OS + Firmware version
    """

    def run(self, mgmt_ip, username, password):
        """Run helper methods to implement the desired state."""
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)

        version = {}
        try:
            with self.pmgr(conn=self.conn, auth=self.auth) as device:
                self.logger.info('successfully connected to %s to '
                                 'get OS Version', self.host)
                version["result"] = self._get_os(device)
                self.logger.info('Closing connection to %s after '
                                 'finding OS -- all done!',
                                 mgmt_ip)
        except Exception, e:
            raise ValueError(e)

        return version

    def _get_os(self, device):

        check_os = device.asset.get_os_full_version()
        return check_os
