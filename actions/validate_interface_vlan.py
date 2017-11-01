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
        with self.pmgr(conn=self.conn, auth_snmp=self.auth_snmp) as device:
            self.logger.info(
                'successfully connected to %s to validate interface vlan',
                self.host)
            # Check is the user input for VLANS is correct

            vlan_list = self.expand_vlan_range(vlan_id=vlan_id)

            if vlan_list:
                changes['vlan'] = self._validate_interface_vlan(device,
                                                                vlan_list=vlan_list,
                                                                intf_name=intf_name,
                                                                intf_mode=intf_mode)
            else:
                raise ValueError('Input is not a valid vlan')
            self.logger.info(
                'closing connection to %s after Validating interface vlan -- all done!',
                self.host)
        return changes

    def _validate_interface_vlan(self, device, vlan_list, intf_name,
                                 intf_mode):
        """validate interface vlan .
        """
        all_true = True
        output = device.interface.switchport_list
        for vlan_id in vlan_list:
            is_vlan_interface_present = False
            is_intf_name_present = False
            for out in output:
                for vid in out['vlan-id']:
                    if vlan_id == int(vid):
                        is_vlan_interface_present = True
                        if intf_name == out[
                                'interface-name']:
                            is_intf_name_present = True
                            if intf_mode in out['mode']:
                                self.logger.info(
                                    "Successfully Validated port channel/physical interface %s"
                                    " and mode %s belongs to  VLAN %s",
                                    intf_name,
                                    intf_mode, vlan_id)
                            else:
                                self.logger.error(
                                    "Port channel/physical interface %s "
                                    " and mode %s does not belong to VLAN %s",
                                    intf_name,
                                    intf_mode, vlan_id)
                                all_true = False
                        else:
                            continue
            if not is_vlan_interface_present:
                self.logger.error(
                    'Vlan %s does not exist on the interface %s' % (
                        vlan_id, intf_name))
                all_true = False
            if is_vlan_interface_present and not is_intf_name_present:
                self.logger.error(
                    'Invalid port channel/physical interface %s '
                    % (intf_name))

                all_true = False

        return all_true


0
