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


class ValidateInterfaceState(NosDeviceAction):
    """
       Implements the logic to Validate port-channel/physical interface
       state on VDX and SLX devices.
    """

    def run(self, host, user, passwd, intf_type, intf_name, intf_state, rbridge_id):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=host, user=user, passwd=passwd)
        changes = {}
        try:
            device = self.asset(ip_addr=self.host, auth=self.auth)
            self.logger.info('successfully connected to %s to validate interface state', self.host)
        except AttributeError as e:
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
        # Check is the user input for interface is correct
        if intf_type == "port-channel":
            temp_type = "port_channel"
        else:
            temp_type = intf_type

        valid_intf = self.validate_interface(intf_type=temp_type,
                                             intf_name=intf_name,
                                             rbridge_id=rbridge_id)

        if valid_intf:
            changes['intf'] = self._validate_interface_state(device, intf_type=intf_type,
                                                             intf_name=intf_name,
                                                             intf_state=intf_state,
                                                             rbridge_id=rbridge_id)
        else:
            raise ValueError('Input is not a valid interface type or name')
        self.logger.info('closing connection to %s after Validating interface state -- all done!',
                         self.host)
        return changes

    def _validate_interface_state(self, device, intf_type, intf_name, intf_state, rbridge_id):
        """validate interface state.
        """

        is_intf_name_present = False
        is_intf_state_present = False
        output = device.get_interface_detail_rpc()
        intf_dict = output[1][0][self.host]['response']['json']['output']['interface']

        for out in intf_dict:
            if intf_name in out['if-name'] and intf_type == out['interface-type']:
                is_intf_name_present = True
                if intf_state in out['line-protocol-state-info']:
                    is_intf_state_present = True
                    self.logger.info("Successfully Validated interface %s %s intf-state %s",
                                     intf_type, intf_name, intf_state)
                else:
                    continue
            else:
                continue

        if not is_intf_name_present:
            self.logger.info("Invalid port channel/physical interface name/type")
            return False
        if not is_intf_state_present:
            self.logger.info("Invalid port channel/physical interface state")
            return False

        return True
