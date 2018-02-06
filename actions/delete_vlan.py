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


class DeleteVlan(NosDeviceAction):
    """
       Implements the logic to Deletes vlans on VDX and SLX devices.
    """

    def run(self, mgmt_ip, username, password, vlan_id):
        """Run helper methods to implement the desired state.
        """

        try:
            self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        except Exception as e:
            self.logger.error(e.message)
            sys.exit(-1)
        changes = self.switch_operation(vlan_id)

        return changes

    @log_exceptions
    def switch_operation(self, vlan_id):
        changes = {}
        with self.pmgr(conn=self.conn, auth_snmp=self.auth_snmp) as device:
            self.logger.info(
                'Successfully connected to %s to delete interface vlans',
                self.host)

            # Check is the user input for VLANS is correct
            try:
                vlan_list = self.get_vlan_list(vlan_id, device)
            except Exception as e:
                error_msg = str(e.message)
                self.logger.error("Error deleting VLAN %s", error_msg)
                sys.exit(-1)
            changes["vlan"] = self._delete_vlan(device, vlan_list, vlan_id)
            self.logger.info('Closing connection to %s after '
                             'Deleting vlans -- all done!',
                             self.host)
        return changes

    def _delete_vlan(self, device, vlan_list, vlan_id):

        try:
            self.logger.info('Deleting Vlans %s', vlan_id)
            for vlan in vlan_list:
                device.interface.del_vlan_int(vlan)
        except (KeyError, ValueError) as e:
            self.logger.error('VLAN %s deletion failed due to %s' % (vlan, e.message))
            sys.exit(-1)

        return True
