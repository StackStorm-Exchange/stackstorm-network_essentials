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


class ValidateL2PortChannelState(NosDeviceAction):
    """
       Implements the logic to Validate port-channel on an interface on VDX
       or SLX devices using PySwitchLib .
       This action achieves the below functionality
           1. Connecting VDX or SLX devices
           2. Validating Port-channel
           3. CLosing Connection with VDX or SLX devices
    """

    def run(self, mgmt_ip, username, password, port_channel_id):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)

        validation = {}

        with self.pmgr(conn=self.conn, auth=self.auth) as device:
            self.logger.info('successfully connected to %s to validate'
                             ' l2 port channel', self.host)

            validation = self._validate_l2_port_channel_state_(
                device, port_channel_id)
            self.logger.info('closing connection to %s after validation '
                             'of port channel -- all done!', self.host)

        return validation

    def _validate_l2_port_channel_state_(self, device, port_channel_id):
        """ Verify if the port channel already exists """
        port_channels = device.interface.port_channels

        members = next((pc['interfaces'] for pc in port_channels
                       if pc['aggregator_id'] == port_channel_id), None)

        # Verify if the port channel to interface mapping is already existing
        output = {}
        output['member-ports'] = []
        output['state'] = ''
        in_sync = True

        if not members:
            self.logger.info('Port Channel cannot be validated')
            return output
        else:
            for member in members:
                output['member-ports'].append(
                    member['interface-type'] + ' ' + member['interface-name'])
                if member['sync'] == '0':
                    self.logger.info('{} {} is out of sync'
                                     .format(member['interface-type'],
                                             member['interface-name']))
                    in_sync = False
                output['state'] = 'out_of_sync' if not in_sync else 'in_sync'
            return output
