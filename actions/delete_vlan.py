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
import itertools
from ne_base import NosDeviceAction
from ne_base import log_exceptions


class DeleteVlan(NosDeviceAction):
    """
       Implements the logic to Deletes vlans on VDX and SLX devices.
    """

    def run(self, mgmt_ip, username, password, vlan_id):
        """Run helper methods to implement the desired state.
        """

        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = self.switch_operation(vlan_id)

        return changes

    @log_exceptions
    def switch_operation(self, vlan_id):
        changes = {}
        with self.pmgr(conn=self.conn, auth=self.auth) as device:
            self.logger.info(
                'Successfully connected to %s to delete interface vlans',
                self.host)

            # Check is the user input for VLANS is correct
            vlan_list = []
            vlanlist = vlan_id.split(',')
            for val in vlanlist:
                temp = self.expand_vlan_range(vlan_id=val)
                if temp is None:
                    raise ValueError('Reserved/Control Vlans or Invalid Vlan Ids passed'
                                     ' in args `vlan_id` %s' % (vlan_id))
                vlan_list.append(temp)

            vlan_list = list(itertools.chain.from_iterable(vlan_list))

            changes["vlan"] = self._delete_vlan(device, vlan_list)

            self.logger.info('Closing connection to %s after '
                             'Deleting vlans -- all done!',
                             self.host)
        return changes

    def _delete_vlan(self, device, vlan_list):

        try:
            self.logger.info('Deleting Vlans %s', vlan_list)
            for vlan in vlan_list:
                device.interface.del_vlan_int(vlan)
        except (KeyError, ValueError) as e:
            self.logger.info('VLAN %s deletion failed due to %s' % (vlan, e.message))
            raise ValueError('VLAN deletion failed')

        return True
