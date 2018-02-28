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
from ne_base import capture_exceptions
from ne_base import ValidateErrorCodes
from pyswitch.exceptions import InvalidInterfaceName


class ValidateL2PortChannelState(NosDeviceAction):
    """
       Implements the logic to Validate port-channel on an interface on VDX
       or SLX devices using PySwitchLib .
       This action achieves the below functionality
           1. Connecting VDX or SLX devices
           2. Validating Port-channel
           3. CLosing Connection with VDX or SLX devices
    """
    @capture_exceptions
    def run(self, mgmt_ip, username, password, port_channel_id):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        return self.switch_operation(port_channel_id)

    def switch_operation(self, port_channel_id):
        """connect to switch and perform desired action"""
        changes = {}

        with self.pmgr(conn=self.conn, auth_snmp=self.auth_snmp) as device:
            self.logger.info('successfully connected to %s to validate'
                             ' l2 port channel', self.host)

            changes = self._validate_l2_port_channel_state_(
                device, port_channel_id)
            self.logger.info('closing connection to %s after validation '
                             'of port channel -- all done!', self.host)

        return changes

    def _validate_l2_port_channel_state_(self, device, port_channel_id):
        """ Verify if the port channel already exists """
        if not device.interface.interface_exists(int_type='port_channel',
                                                 name=port_channel_id):
            reason = "Interface is not present on the device"
            self.logger.error(reason)
            raise InvalidInterfaceName(reason)
        port_channels = device.interface.port_channels

        members = next((pc['interfaces'] for pc in port_channels
                       if pc['aggregator_id'] == str(port_channel_id)), None)

        # Verify if the port channel to interface mapping is already existing
        changes = {}
        changes['member-ports'] = []
        changes['state'] = ''
        in_sync_cnt = 0

        if not members:
            msg = 'Port Channel cannot be validated, No member ports exist'
            self.logger.error(msg)
            raise ValueError(msg)
        else:
            for member in members:
                changes['member-ports'].append(
                    member['interface-type'] + ' ' + member['interface-name'])
                if member['sync'] == '0':
                    self.logger.info('{} {} is out of sync'
                                     .format(member['interface-type'],
                                             member['interface-name']))
                else:
                    in_sync_cnt += 1
                changes['state'] = 'out_of_sync' if in_sync_cnt == 0 else 'in_sync'
            reason_code = ValidateErrorCodes.SUCCESS
            changes['reason_code'] = reason_code.value
            return changes
