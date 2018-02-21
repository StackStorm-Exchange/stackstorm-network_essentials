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
from ne_base import ValidateErrorCodes


class ValidateInterfaceVlan(NosDeviceAction):
    """
       Implements the logic to Validate port channel or physical interface and \
       mode belongs to a VLAN on VDX switches.
    """

    virtual_fabric = "Fabric is not enabled to support Virtual Fabric configuration"

    def run(self, mgmt_ip, username, password, vlan_id, intf_type, intf_name, intf_mode):
        """Run helper methods to implement the desired state.
        """
        changes = {}
        try:
            self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        except Exception as e:
            self.logger.error(e.message)
            error_code = ValidateErrorCodes.DEVICE_CONNECTION_ERROR
            changes['reason_code'] = error_code.value
            changes['reason'] = e.message
            return (False, changes)
        return self.switch_operation(intf_mode, intf_type, intf_name, vlan_id)

    @log_exceptions
    def switch_operation(self, intf_mode, intf_type, intf_name, vlan_id):
        changes = {}
        with self.pmgr(conn=self.conn, auth_snmp=self.auth_snmp) as device:
            self.logger.info(
                'successfully connected to %s to validate interface vlan',
                self.host)
            # Check is the user input for VLANS is correct

            try:
                ifname = intf_type + " " + intf_name
                intf_exists = device.interface.interface_exists(int_type=intf_type,
                                                    name=intf_name)
                if not intf_exists:
                    reason = "Interface " + ifname +  \
                             " is not present on the device"
                    self.logger.error(reason)
                    error_code = ValidateErrorCodes.INVALID_USER_INPUT
                    changes['reason_code'] = error_code.value
                    changes['reason'] = reason
                    changes['intf_name'] = ifname
                    return (False, changes)
            except Exception as e:
                self.logger.error(e.message)
                error_code = ValidateErrorCodes.INVALID_USER_INPUT
                changes['reason_code'] = error_code.value
                changes['reason'] = e.message
                changes['intf_name'] = ifname
                return (False, changes)

            vlan_list = self.expand_vlan_range(vlan_id=vlan_id, device=device)
            if vlan_list:
                result, changes = self._validate_interface_vlan(device,
                                                                vlan_list=vlan_list,
                                                                intf_type=intf_type,
                                                                intf_name=intf_name,
                                                                intf_mode=intf_mode)
                changes['vlan'] = vlan_id
            else:
                error_code = ValidateErrorCodes.INVALID_USER_INPUT
                changes['reason_code'] = error_code.value
                changes['reason'] = "Invalid VLAN"
                changes['vlan'] = vlan_id
                return (False, changes)

            self.logger.info(
                'closing connection to %s after Validating interface vlan -- all done!',
                self.host)

        return result, changes

    def _validate_interface_vlan(self, device, vlan_list, intf_type, intf_name,
                                 intf_mode):
        """validate interface vlan .
        """
        changes = {}
        try:
            result = device.interface.validate_interface_vlan(vlan_list=vlan_list,
                        intf_type=intf_type, intf_name=intf_name, intf_mode=intf_mode)

        except Exception as e:
            reason = "Validate interface vlan failed " + e.message
            self.logger.error(reason)
            error_code = ValidateErrorCodes.DEVICE_VALIDATION_ERROR
            changes['reason_code'] = error_code.value
            changes['reason'] = reason
            return (False, changes)
        if not result:
            reason = "Interface to VLAN mapping doesnt exist"
            self.logger.error(reason)
            error_code = ValidateErrorCodes.DEVICE_VALIDATION_ERROR
            changes['reason_code'] = error_code.value
            changes['reason'] = reason
        else:
            error_code = ValidateErrorCodes.SUCCESS
            changes['reason_code'] = error_code.value
            reason = "Validate interface vlan is successful"
            changes['reason'] = reason
            self.logger.info(reason)
        return (result, changes)
