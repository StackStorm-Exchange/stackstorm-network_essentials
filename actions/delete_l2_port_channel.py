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
from pyswitch.device import Device
import sys


class DeletePortChannel(NosDeviceAction):
    """
       Implements the logic to delete port-channel configuration from all the member ports
       on VDX and SLX devices .
       This action achieves the below functionality
           1.Delete a port channel
           2.Verify whether the port-channel is really deleted
    """

    def run(self, mgmt_ip, username, password, port_channel_id):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = {}

        with Device(conn=self.conn, auth_snmp=self.auth_snmp) as device:
            self.logger.info('successfully connected to %s to delete l2 port channel',
                             self.host)
            changes['port_channel_configs'] = self._delete_l2_port_channel(device,
                                               portchannel_num=port_channel_id)

            self.logger.info('closing connection to %s after'
                         ' deleting l2 port channel -- all done!', self.host)
        return changes

    def _delete_l2_port_channel(self, device, portchannel_num):
        """ Deleting the port channel configuration from all the member ports"""

        is_po_present = True
        try:
            poChannel = device.interface.port_channels
            for po in poChannel:
                poNo = po['aggregator_id']
                if poNo == str(portchannel_num):
                    self.logger.info('Deleting port channel %s', portchannel_num)
                    device.interface.remove_port_channel(port_int=str(portchannel_num))
                    is_po_present = False
        except Exception as e:
            error_message = str(e.message)
            self.logger.error(error_message)
            self.logger.error('Failed to get/delete port-channel %s', portchannel_num)
            sys.exit(-1)

        if not is_po_present:
            return True
        else:
            self.logger.info('port-channel %s does not exist in the switch', portchannel_num)
            return False
