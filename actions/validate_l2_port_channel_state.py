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

        try:
            device = self.asset(ip_addr=self.host, auth=self.auth)
            self.logger.info('successfully connected to %s to validate l2 port channel', self.host)
        except AttributeError as e:
            self.logger.error('Failed to connect to %s due to %s', self.host, e.message)
            raise ValueError('Failed to connect to %s due to %s', self.host, e.message)
        except ValueError as verr:
            self.logger.error("Error while logging in to %s due to %s",
                              self.host, verr.message)
            raise ValueError("Error while logging in to %s due to %s",
                             self.host, verr.message)
        except self.ConnectionError as cerr:
            self.logger.error("Connection failed while logging in to %s due to %s",
                              self.host, cerr.message)
            raise ValueError("Connection failed while logging in to %s due to %s",
                             self.host, cerr.message)
        except self.RestInterfaceError as rierr:
            self.logger.error("Failed to get a REST response while logging in "
                              "to %s due to %s", self.host, rierr.message)
            raise ValueError("Failed to get a REST response while logging in "
                             "to %s due to %s", self.host, rierr.message)
        validation = self._validate_l2_port_channel_state_(device, port_channel_id)
        self.logger.info('closing connection to %s after '
                         'validation of port channel -- all done!', self.host)

        return validation

    def _validate_l2_port_channel_state_(self, device, port_channel_id):
        """ Verify if the port channel already exists """
        port_channel_num = int(port_channel_id)
        members = self._get_port_channel_members(device, port_channel_num)
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
                                     .format(member['interface-type'], member['interface-name']))
                    in_sync = False
                output['state'] = 'out_of_sync' if not in_sync else 'in_sync'
            return output
