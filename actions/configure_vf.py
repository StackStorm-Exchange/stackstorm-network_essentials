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
from ne_base import log_exceptions
import sys


class VirtualFabric(NosDeviceAction):
    """
       Implements the logic to enable/disable virtual fabric on VDX Devices
    """

    def run(self, mgmt_ip, username, password, virtual_fabric_enable):
        """Run helper methods to implement the desired state.
        """

        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = self.switch_operation(virtual_fabric_enable)

        return changes

    @log_exceptions
    def switch_operation(self, virtual_fabric_enable):

        changes = {}
        with self.pmgr(conn=self.conn, auth=self.auth) as device:
            if device.os_type != 'nos':
                self.logger.error('VF feature is supported only on VDX platform')
                sys.exit(-1)

            self.logger.info(
                'successfully connected to %s to Configure VCS Virtual Fabric '
                ' on the device', self.host)

            changes['pre_check'] = self._pre_check(device, virtual_fabric_enable)
            if changes['pre_check']:
                changes['virtual_fabric_enable'] = self._config_virtual_fabric_enable(device,
                                                                       virtual_fabric_enable)

            self.logger.info('Closing connection to %s after Configuring VCS Virtual Fabric '
                             'on the device -- all done!',
                             self.host)
        return changes

    def _pre_check(self, device, virtual_fabric_enable):
        """ Check if virtual fabric is pre-configured or not """

        out = device.interface.vfab_enable(get=True)
        if out and virtual_fabric_enable:
            self.logger.info('VCS VF is already enabled on the device')
            return False
        if not out and not virtual_fabric_enable:
            self.logger.info('VCS VF is already disabled on the device')
            return False

        return True

    def _config_virtual_fabric_enable(self, device, virtual_fabric_enable):
        """ Configure Virtual Fabric """

        try:
            tmp = 'Enabling' if virtual_fabric_enable else 'Disabling'
            self.logger.info('%s VCS Virtual Fabric on the device', tmp)
            device.interface.vfab_enable(vfab_enable=virtual_fabric_enable)
        except (ValueError, KeyError):
            self.logger.exception("Configuring VCS Virtual Fabric Failed")
            raise ValueError("Configuring VCS Virtual Fabric Failed")

        return True
