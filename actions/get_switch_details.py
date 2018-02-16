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


class GetSwitchDetails(NosDeviceAction):
    """
       Implements the logic to get switch details from VCS Fabric
       This action acheives the below functionality
    """

    def run(self, mgmt_ip, username, password):
        """Run helper methods to implement the desired state.
        """
        try:
            self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        except Exception as e:
            self.logger.error(e.message)
            sys.exit(-1)

        changes = {}

        self.switch_operation(changes, mgmt_ip)

        return changes

    @log_exceptions
    def switch_operation(self, changes, mgmt_ip):
        with self.pmgr(conn=self.conn, auth_snmp=self.auth_snmp) as device:
            self.logger.info(
                'successfully connected to %s to get switch details',
                self.host)
            changes['switch_details'] = self._get_switch_details(device,
                                                                 mgmt_ip)
            self.logger.info('closing connection to %s after '
                             'getting switch details -'
                             'all done!', self.host)

    def _get_switch_details(self, device, host):
        """get the switch details.
        """
        sw_info = {}
        rb_list = []
        sw_list = []
        if device.os_type == 'nos':
            sw_info['os_type'] = 'nos'
            vcs_info = device.vcs.vcs_nodes
            for vcs in vcs_info:
                rb_list.append(vcs['node-rbridge-id'])
                if vcs['node-is-principal'] == "true":
                    sw_info['principal_ip'] = vcs['node-switch-ip']
                    continue

                sw_list.append(vcs['node-switch-ip'])
        elif device.os_type == 'slxos':
            sw_info['os_type'] = 'slxos'
        else:
            self.logger.error('Operation is not supported on MLX devices')
            raise ValueError('Operation is not supported on MLX  device')

        sw_info['rbridge_id'] = rb_list
        sw_info['switch_ip'] = sw_list

        return sw_info
