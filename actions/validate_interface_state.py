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
import pynos.utilities


class ValidateInterfaceState(NosDeviceAction):
    """
       Implements the logic to Validate port-channel/physical interface state on VDX switches.
    """

    def run(self, host, user, passwd, intf_type, intf_name, intf_state):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=host, user=user, passwd=passwd)
        changes = {}

        with self.mgr(conn=self.conn, auth=self.auth) as device:
            self.logger.info('successfully connected to %s to validate interface state', self.host)
            # Check is the user input for interface is correct
            if intf_type == "port-channel":
                temp_type = "port_channel"
            else:
                temp_type = intf_type

            valid_intf = pynos.utilities.valid_interface(int_type=temp_type, name=intf_name)

            if valid_intf:
                changes['intf'] = self._validate_interface_state(device, intf_type=intf_type,
                                                                 intf_name=intf_name,
                                                                 intf_state=intf_state)
            else:
                raise ValueError('Input is not a valid interface type or name')
            self.logger.info(
                'closing connection to %s after Validating interface state -- all done!', self.host)
        return changes

    def _validate_interface_state(self, device, intf_type, intf_name, intf_state):
        """validate interface state.
        """

        is_intf_name_present = False
        is_intf_state_present = False
        output = device.interface.interface_detail
        for out in output:
            if intf_name == out['interface-name'] and intf_type == out['interface-type']:
                is_intf_name_present = True
                if_adminstate = out['interface-state']
                if_operstate = out['interface-proto-state']
                if intf_state in out['interface-state'] and intf_state == out[
                   'interface-proto-state']:
                    is_intf_state_present = True
                    self.logger.info("Successfully Validated interface %s %s intf-state %s",
                                     intf_type, intf_name, intf_state)
                else:
                    continue
            else:
                continue

        if not is_intf_name_present:
            raise ValueError('Invalid port channel/physical interface name/type')
        if not is_intf_state_present:
            self.logger.info('User input for intf-state %s is not matching with '
                             'current intf-adminstate %s and intf-operstate %s',
                             intf_state, if_adminstate, if_operstate)
            return False

        return True
