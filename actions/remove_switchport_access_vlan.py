
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
import sys


class RemoveSwitchPort(NosDeviceAction):
    """
       Implements the logic to remove  a access vlan from an interface on VDX
       Switches or remove a untagged port from a vlan.
    """

    def run(self, mgmt_ip, username, password, intf_type, intf_name, vlan_id):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        with self.pmgr(conn=self.conn, auth_snmp=self.auth_snmp) as device:
            self.logger.info('successfully connected to %s to create switchport on Interface',
                             self.host)

            try:
                get_vlan = device.interface.acc_vlan(get=True, int_type=intf_type, name=intf_name)
                if(get_vlan != vlan_id):
                    self.logger.error('Vlan %s is not configured on port %s',
                       vlan_id, intf_name)
                    sys.exit(-1)

                device.interface.acc_vlan(delete=True, int_type=intf_type,
                    name=intf_name, vlan=vlan_id)

            except Exception as error:
                self.logger.error('Remove access vlan is failed due to %s',
                    str(error.message))
                sys.exit(-1)
        return True
