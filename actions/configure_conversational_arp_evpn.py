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


class ConfigureConversationalArpEvpn(NosDeviceAction):
    """
       Implements the logic to configure converstaional arp on VDX switches
       This action acheives the below functionality
           Check for the existing configuration on the Device,if not present configure it
    """

    def run(self, mgmt_ip, username, password):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = {}
        with self.mgr(conn=self.conn, auth=self.auth) as device:
            self.logger.info('successfully connected to %s', self.host)
            rb_list = self._vlag_pair(device)
            changes['conv-arp'] = self._configure_conversational_arp_evpn(device, rb_list=rb_list)
            self.logger.info('closing connection to %s after configuring conversational arp '
                             '-- all done!', self.host)
        return changes

    def _configure_conversational_arp_evpn(self, device, rb_list):
        """Configuring converstaional arp under config mode.
        """
        is_conv_arp_exist = True
        for rb in rb_list:
            conv_arp = device.interface.conversational_arp(get=True, rbridge_id=rb)
            if conv_arp is not None:
                self.logger.info('Converstaional arp already configured on rbridge %s ', rb)
                is_conv_arp_exist = False
            else:
                self.logger.info('Configuring Converstaional arp on rbridge %s ', rb)
                device.interface.conversational_arp(rbridge_id=rb)

        if not is_conv_arp_exist:
            return False

        return True

    def _vlag_pair(self, device):
        """ Fetch the RB list if VLAG is configured"""

        rb_list = []
        result = device.vcs.vcs_nodes
        for each_rb in result:
            rb_list.append(each_rb['node-rbridge-id'])
        if len(rb_list) >= 3:
            raise ValueError('VLAG PAIR must be <= 2 leaf nodes')
        return list(set(rb_list))
