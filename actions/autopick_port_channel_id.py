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


class AutoPickPortChannel(NosDeviceAction):
    """
       Implements the logic to create port-channel on an interface on
        VDX/SLX Switches .
       This action acheives the below functionality
           1.Provides a port_channel number if port_channel id is not passed
    """

    def run(self, mgmt_ip, username, password):
        """Run helper methods to implement the desired state.
        """

        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = self.switch_operation()
        return changes

    @log_exceptions
    def switch_operation(self):
        changes = {}
        with self.pmgr(conn=self.conn, auth=self.auth) as device:
            self.logger.info(
                'successfully connected to %s to create port channel',
                self.host)
            changes['port_channel_id'] = str(
                self._no_port_channel_number(device))
            self.logger.info('closing connection to %s after'
                             ' configuring port channel -- all done!',
                             self.host)
        return changes

    def _no_port_channel_number(self, device):
        """ Port channel number is Null , provide a number between 1-6144
            which is not pre-existing
        """
        po_array = []
        try:
            result = device.interface.port_channels
        except Exception as e:
            raise ValueError(e)
        for res in result:
            port_channel_num = res['aggregator_id']
            po_array.append(port_channel_num)
        po_array = [int(i) for i in po_array]
        lag_id_max = self._get_lag_id_max(device)
        for num in range(1, lag_id_max):
            if num not in po_array:
                break
        return num

    def _get_lag_id_max(self, device):
        """
        Get the maximum port-channel id that can be configured
        """
        if device.os_type == 'nos':
            return 6144
        elif device.os_type == 'slxos':
            return 1024
        elif device.os_type == 'NI':
            return 256
        else:
            raise ValueError('Not a supported os_type %s' % (device.os_type))
