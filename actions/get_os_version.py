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

import sys

from ne_base import NosDeviceAction
from ne_base import log_exceptions


class GetOsVersion(NosDeviceAction):
    """
       Implements the logic to get OS version of a devise.
       This action achieves the below functionality
           1.Get OS + Firmware version
    """

    def run(self, mgmt_ip, username, password):
        """Run helper methods to implement the desired state."""
        try:
            self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        except Exception as e:
            self.logger.error(e.message)
            sys.exit(-1)

        version = self.switch_operation(mgmt_ip)

        return version

    @log_exceptions
    def switch_operation(self, mgmt_ip):
        version = {}

        with self.pmgr(conn=self.conn, auth_snmp=self.auth_snmp) as device:
            self.logger.info('successfully connected to %s to '
                             'get OS Version', self.host)
            version["result"] = self._get_os(device)
            self.logger.info('Closing connection to %s after '
                             'finding OS -- all done!',
                             mgmt_ip)
        return version

    def _get_os(self, device):
        if device.connection_type == 'SNMPCLI':
            check_os = device.firmware_version
        else:
            check_os = device.asset.get_os_full_version()
        return check_os
