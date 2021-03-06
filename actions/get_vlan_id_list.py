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


class GetNetworkID(NosDeviceAction):
    """
       Implements the logic to return list of network id on
       VDX/SLXOS Switches .
    """

    def run(self, mgmt_ip, username, password, vlan_id_list, ve_id_list):
        """Run helper methods to implement the desired state.
        """

        try:
            self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        except Exception as e:
            self.logger.error(e.message)
            sys.exit(-1)
        changes = self.switch_operation(vlan_id_list, ve_id_list)
        return changes

    @log_exceptions
    def switch_operation(self, vlan_id_list, ve_id_list):
        changes = {}
        with self.pmgr(conn=self.conn, auth_snmp=self.auth_snmp) as device:
            self.logger.info(
                'Successfully connected to %s to Fetch Vlan ID List',
                self.host)

            if vlan_id_list is None and ve_id_list is None:
                self.logger.error('Missing mandatory args `vlan_id_list`'
                                  ' or `ve_id_list`')
                raise ValueError('Missing mandatory args `vlan_id_list`'
                                 ' or `ve_id_list`')

            if vlan_id_list is not None:
                changes['vlan_id'] = str(
                    self._network_id(device, vlan_id_list))

            if ve_id_list is not None:
                changes['ve_id'] = str(
                    self._ve_id(device, ve_id_list))

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

    def _ve_id(self, device, ve_id_list):

        try:
            ve_str = ''
            network_ids = self.get_ve_list(ve_id_list, device)
            for tmp in network_ids:
                ve_str = ve_str + ',' + str(tmp)
            ve_num = ve_str.lstrip(',')
        except (ValueError, KeyError) as e:
            self.logger.error('Failed to expand the ve id range due to %s',
                e.message)
            raise ValueError('Failed to expand the ve id range')
        return ve_num
