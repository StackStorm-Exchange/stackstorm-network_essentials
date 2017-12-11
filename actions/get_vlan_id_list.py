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


class GetNetworkID(NosDeviceAction):
    """
       Implements the logic to return list of network id on
       VDX/SLXOS Switches .
    """

    def run(self, mgmt_ip, username, password, vlan_id_list):
        """Run helper methods to implement the desired state.
        """

        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = self.switch_operation(vlan_id_list)
        return changes

    @log_exceptions
    def switch_operation(self, vlan_id_list):
        changes = {}
        with self.pmgr(conn=self.conn, auth_snmp=self.auth_snmp) as device:
            self.logger.info(
                'Successfully connected to %s to Fetch Vlan ID List',
                self.host)

            changes['vlan_id'] = str(
                self._network_id(device, vlan_id_list))

            self.logger.info('Closing connection to %s after'
                             ' fetching Vlans IDs  -- all done!',
                             self.host)
        return changes

    def _network_id(self, device, vlan_id_list):

        try:
            vlan_str = ''
            network_ids = self.get_vlan_list(vlan_id_list, device)
            for tmp in network_ids:
                vlan_str = vlan_str + ',' + str(tmp)
            num = vlan_str.lstrip(',')
        except (ValueError, KeyError) as e:
            self.logger.error('Failed to expand the vlan id range due to %s',
                e.message)
            raise ValueError('Failed to expand the vlan id range')
        return num
