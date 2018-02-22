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


class ValidateInterfaceState(NosDeviceAction):
    def run(self, mgmt_ip, username, password, intf_type,
            intf_name, intf_state, rbridge_id):
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
        status, changes = self.switch_operation(intf_name, intf_state, intf_type, rbridge_id)

        return status, changes

    @log_exceptions
    def switch_operation(self, intf_name, intf_state, intf_type, rbridge_id):
        changes = {}
        with self.pmgr(conn=self.conn, auth_snmp=self.auth_snmp) as device:
            self.logger.info(
                'successfully connected to %s to validate interface state',
                self.host)

            ifname = intf_type + " " + intf_name
            valid_rbridge_int_types = ['ve', 'loopback']
            if device.os_type == 'nos':
                if intf_type in valid_rbridge_int_types and rbridge_id is None:
                    '''raise ValueError('rbridge-id should not be empty. '
                                     'Specify a valid value.')
                    '''
                    reason = "rbridge-id should not be empty. Specify a valid value"
                    self.logger.error(reason)
                    error_code = ValidateErrorCodes.INVALID_USER_INPUT
                    changes['reason_code'] = error_code.value
                    changes['reason'] = reason
                    changes['intf_name'] = ifname
                    return (False, changes)

            valid_intf, reason, error_code = self._check_interface_presence(device,
                                                    intf_type=intf_type,
                                                    intf_name=intf_name)

            temp_type = 'port-channel' if intf_type == 'port_channel' else\
                intf_type
            # switch expects the type as port-channel
            if valid_intf:
                status, changes = self._validate_interface_state(
                    device,
                    intf_type=temp_type,
                    intf_name=intf_name,
                    intf_state=intf_state,
                    rbridge_id=rbridge_id)

            else:
                self.logger.error(reason)
                changes['reason_code'] = error_code.value
                changes['intf_name'] = ifname
                changes['reason'] = reason
                return (False, changes)
            self.logger.info('closing connection to %s after Validating '
                             'interface state -- all done!',
                             self.host)
        return status, changes

    def _check_interface_presence(self, device, intf_type, intf_name):

        reason = "success"
        retVal = True
        error_code = ValidateErrorCodes.SUCCESS
        if intf_type not in device.interface.valid_int_types:
            reason = "Input is not a valid interface type"
            error_code = ValidateErrorCodes.INVALID_USER_INPUT
            retVal = False

        if not self.validate_interface(intf_type, intf_name, os_type=device.os_type):
            reason = "Invalid interface format " + intf_type + " " + intf_name
            error_code = ValidateErrorCodes.INVALID_USER_INPUT
            retVal = False

        if not device.interface.interface_exists(int_type=intf_type,
                                                 name=intf_name):
            reason = "Interface is not present on the device"
            error_code = ValidateErrorCodes.INVALID_USER_INPUT
            retVal = False

        return retVal, reason, error_code

    def _validate_interface_state(
            self, device, intf_type, intf_name, intf_state, rbridge_id):
        """validate interface state.
        """

        changes = {}
        retVal = True
        if device.os_type == 'NI':
            ifname = intf_type + " " + intf_name
            changes['intf_name'] = ifname
            try:
                oper_state = device.interface.get_oper_state(int_type=intf_type,
                                                       name=intf_name)
            except Exception as e:
                reason = e.message
                self.logger.error(reason)
                error_code = ValidateErrorCodes.DEVICE_VALIDATION_ERROR
                changes['reason_code'] = error_code.value
                changes['reason'] = reason
                status = False
                return (status, changes)

            if oper_state == intf_state:
                reason = "Successfully validated interface " + ifname + " state as " + oper_state
                self.logger.info(reason)
                error_code = ValidateErrorCodes.SUCCESS
                status = True
            else:
                reason = "Invalid interface " + ifname + " state " + oper_state
                self.logger.error(reason)
                error_code = ValidateErrorCodes.INVALID_USER_INPUT
                status = False
            changes['reason_code'] = error_code.value
            changes['reason'] = reason
            changes['state'] = oper_state
            return (status, changes)

        valid_rbridge_int_types = ['ve', 'loopback']
        if intf_type in valid_rbridge_int_types:
            if device.os_type == 'nos':
                iftype = str(intf_type).lower()
                ifname = iftype + " " + intf_name
                for rb in rbridge_id:
                    is_intf_present = False
                    is_intf_state_present = False
                    interfaces = device.interface.ve_interfaces(rbridge_id=rb)
                    for intf in interfaces:
                        intfname = intf['if-name'].lower()
                        if ifname == intfname:
                            changes['intf_name'] = ifname
                            is_intf_present = True
                            proto_state = intf['interface-proto-state']
                            if proto_state == intf_state:
                                changes['state'] = proto_state
                                error_code = ValidateErrorCodes.SUCCESS
                                changes['reason_code'] = error_code.value
                                reason = "Successfully Validated interface " + ifname + \
                                         " state as " + proto_state + " in rbridge-id " + rb
                                self.logger.info(reason)
                                is_intf_state_present = True
                                return (True, changes)
                            else:
                                changes['state'] = proto_state

                        else:
                            changes['intf_name'] = ifname

                    if not is_intf_present:
                        reason = "Invalid interface name/type in rbridge-id " + rb
                        self.logger.error(reason)
                        error_code = ValidateErrorCodes.INVALID_USER_INPUT
                        changes['reason_code'] = error_code.value
                        changes['reason'] = reason
                        retVal = False
                    else:
                        if not is_intf_state_present:
                            reason = "Invalid interface " + ifname + " state " + \
                                     proto_state + " in rb " + rb
                            self.logger.error(reason)
                            error_code = ValidateErrorCodes.DEVICE_VALIDATION_ERROR
                            changes['reason_code'] = error_code.value
                            changes['reason'] = reason
                            retVal = False
                if not retVal:
                    return (False, changes)
            else:
                is_intf_present = False
                is_intf_state_present = False
                iftype = str(intf_type).lower()
                ifname = iftype + " " + intf_name
                interfaces = device.interface.ve_interfaces()
                for intf in interfaces:
                    intfname = intf['if-name'].lower()
                    if ifname == intfname:
                        changes['intf_name'] = ifname
                        is_intf_present = True
                        proto_state = intf['interface-proto-state']
                        if proto_state == intf_state:
                            changes['state'] = proto_state
                            error_code = ValidateErrorCodes.SUCCESS
                            changes['reason_code'] = error_code.value
                            reason = "Successfully validated interface " +  \
                                     ifname + " state as " + proto_state
                            self.logger.info(reason)
                            is_intf_state_present = True
                            return (True, changes)
                        else:
                            changes['state'] = proto_state
                    else:
                        changes['intf_name'] = ifname

                if not is_intf_present:
                    reason = "Invalid interface name/type " + ifname
                    self.logger.error(reason)
                    error_code = ValidateErrorCodes.INVALID_USER_INPUT
                    changes['reason_code'] = error_code.value
                    changes['reason'] = reason
                    retVal = False
                else:
                    if not is_intf_state_present:
                        reason = "Invalid interface " + ifname + " state " + proto_state
                        self.logger.error(reason)
                        error_code = ValidateErrorCodes.DEVICE_VALIDATION_ERROR
                        changes['reason_code'] = error_code.value
                        changes['reason'] = reason
                        retVal = False
                if not retVal:
                    return (False, changes)

        else:
            interfaces = device.interface.single_interface_detail(
                int_type=intf_type,
                name=intf_name)

            proto_state = next((pc['interface-proto-state']
                                for pc in interfaces if pc[
                                    'interface-name'] == intf_name and
                                pc['interface-type'] == intf_type), None)
            changes = {}
            ifname = intf_type + " " + intf_name
            changes['intf_name'] = ifname
            if proto_state:
                if proto_state == intf_state:
                    changes['state'] = proto_state
                    reason = "Successfully validated interface " + ifname + \
                             " state as " + proto_state
                    self.logger.info(reason)
                    error_code = ValidateErrorCodes.SUCCESS
                    changes['reason_code'] = error_code.value
                    retVal = True
                else:
                    reason = "Invalid interface " + ifname + " state " + proto_state
                    self.logger.error(reason)
                    changes['state'] = proto_state
                    error_code = ValidateErrorCodes.DEVICE_VALIDATION_ERROR
                    changes['reason_code'] = error_code.value
                    retVal = False
            else:
                reason = "Invalid interface name/type " + ifname
                self.logger.error(reason)
                error_code = ValidateErrorCodes.INVALID_USER_INPUT
                changes['reason_code'] = error_code.value
                retVal = False
            changes['reason'] = reason
            if retVal:
                return True, changes
            else:
                return False, changes
