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


class ValidateInterfaceVlan(NosDeviceAction):
    """
       Implements the logic to Validate port channel or physical interface and \
       mode belongs to a VLAN on VDX switches.
    """

    virtual_fabric = "Fabric is not enabled to support Virtual Fabric configuration"

    def run(self, mgmt_ip, username, password, vlan_id, intf_name, intf_mode):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        return self.switch_operation(intf_mode, intf_name, vlan_id)

    @log_exceptions
    def switch_operation(self, intf_mode, intf_name, vlan_id):
        changes = {}
        with self.pmgr(conn=self.conn, auth=self.auth) as device:
            self.logger.info(
                'successfully connected to %s to validate interface vlan',
                self.host)
            # Check is the user input for VLANS is correct
            vlan_list = self.expand_vlan_range(vlan_id=vlan_id)

            if vlan_list:
                changes['vlan'] = self._validate_interface_vlan(device,
                                                                vlan_id=vlan_id,
                                                                intf_name=intf_name,
                                                                intf_mode=intf_mode)
            else:
                raise ValueError('Input is not a valid vlan')
            self.logger.info(
                'closing connection to %s after Validating interface vlan -- all done!',
                self.host)
        return changes

    def _validate_interface_vlan(self, device, vlan_id, intf_name, intf_mode):
        """validate interface vlan .
        """

        is_vlan_interface_present = False
        is_intf_name_mode_present = False
        output = device.interface.switchport_list
        for out in output:
            for vid in out['vlan-id']:
                if vlan_id == vid:
                    is_vlan_interface_present = True
                    if intf_name in out[
                            'interface-name'] and intf_mode in out['mode']:
                        is_intf_name_mode_present = True
                        self.logger.info("Successfully Validated port channel/physical interface %s \
                               and mode %s belongs to a VLAN %s", intf_name,
                                         intf_mode, vlan_id)
                    else:
                        continue
        if not is_vlan_interface_present:
            raise ValueError('Vlan does not exist on the interface')
        if not is_intf_name_mode_present:
            raise ValueError(
                'Invalid port channel/physical interface or mode belongs to a VLAN')

        return True


0
