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


class ValidateInterfaceState(NosDeviceAction):
    def run(self, mgmt_ip, username, password, intf_type,
            intf_name, intf_state):
        """Run helper methods to implement the desired state.
        """

        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = self.switch_operation(intf_name, intf_state, intf_type)

        return changes

    @log_exceptions
    def switch_operation(self, intf_name, intf_state, intf_type):
        changes = {}
        with self.pmgr(conn=self.conn, auth=self.auth) as device:
            self.logger.info(
                'successfully connected to %s to validate interface state',
                self.host)

            valid_intf = self._check_interface_presence(device,
                                                        intf_type=intf_type,
                                                        intf_name=intf_name)

            temp_type = 'port-channel' if intf_type == 'port_channel' else\
                intf_type
            # switch expects the type as port-channel
            if valid_intf:
                changes = self._validate_interface_state(
                    device,
                    intf_type=temp_type,
                    intf_name=intf_name,
                    intf_state=intf_state)

            else:
                self.logger.error(
                    "'Input is not a valid interface type or name")
                raise ValueError('Input is not a valid interface type'
                                 ' or name')
            self.logger.info('closing connection to %s after Validating '
                             'interface state -- all done!',
                             self.host)
        return changes

    def _check_interface_presence(self, device, intf_type, intf_name):

        if intf_type not in device.interface.valid_int_types:
            self.logger.error('Iterface type is not valid. '
                              'Interface type must be one of %s'
                              % device.interface.valid_int_types)
            raise ValueError('Iterface type is not valid. '
                             'Interface type must be one of %s'
                             % device.interface.valid_int_types)

        if not self.validate_interface(intf_type, intf_name):
            raise ValueError('Interface %s is not valid' % (intf_name))

        if not device.interface.interface_exists(int_type=intf_type,
                                                 name=intf_name):
            self.logger.error('Interface %s %s not present on the Device'
                              % (intf_type, intf_name))
            raise ValueError('Interface %s %s not present on the Device'
                             % (intf_type, intf_name))

        return True

    def _validate_interface_state(
            self, device, intf_type, intf_name, intf_state):
        """validate interface state.
        """

        interfaces = device.interface.single_interface_detail(
            int_type=intf_type,
            name=intf_name)

        proto_state = next((pc['interface-proto-state']
                            for pc in interfaces if pc[
                                'interface-name'] == intf_name and
                            pc['interface-type'] == intf_type), None)
        changes = {}
        if proto_state:
            changes['intf'] = True
            if proto_state == intf_state:
                changes['state'] = proto_state
                self.logger.info(
                    'Successfully Validated port channel/physical interface'
                    ' state as %s' % proto_state)
            else:
                self.logger.error(
                    "Invalid port channel/physical interface state %s"
                    % proto_state)
                changes['state'] = False
        else:
            self.logger.error(
                "Invalid port channel/physical interface name/type")
            changes['intf'] = False

        return changes
