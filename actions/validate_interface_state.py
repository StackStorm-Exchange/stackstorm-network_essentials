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
            intf_name, intf_state, rbridge_id):
        """Run helper methods to implement the desired state.
        """

        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = self.switch_operation(intf_name, intf_state, intf_type,
                                        rbridge_id)
        return changes

    @log_exceptions
    def switch_operation(self, intf_name, intf_state, intf_type, rbridge_id):
        changes = {}
        with self.pmgr(conn=self.conn, auth=self.auth) as device:
            self.logger.info(
                'successfully connected to %s to validate interface state',
                self.host)

            if intf_type == "port-channel":
                temp_type = "port_channel"
            else:
                temp_type = intf_type

            valid_intf = self.validate_interface(intf_type=temp_type,
                                                 intf_name=intf_name,
                                                 rbridge_id=rbridge_id)

            if valid_intf:
                changes = self._validate_interface_state(device,
                                                         intf_type=intf_type,
                                                         intf_name=intf_name,
                                                         intf_state=intf_state,
                                                         rbridge_id=rbridge_id)
            else:
                self.logger.error(
                    "'Input is not a valid interface type or name")
                raise ValueError('Input is not a valid interface type'
                                 ' or name')
            self.logger.info('closing connection to %s after Validating '
                             'interface state -- all done!',
                             self.host)
        return changes

    def _validate_interface_state(
            self, device, intf_type, intf_name, intf_state, rbridge_id):
        """validate interface state.
        """

        interfaces = device.interface.interface_detail

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
                    "Invalid port channel/physical interface state")
                changes['state'] = False
        else:
            self.logger.error(
                "Invalid port channel/physical interface name/type")
            changes['intf'] = False

        return changes
