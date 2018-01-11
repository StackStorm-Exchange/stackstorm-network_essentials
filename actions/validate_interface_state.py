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
import sys
from ne_base import NosDeviceAction
from ne_base import log_exceptions


class ValidateInterfaceState(NosDeviceAction):
    def run(self, mgmt_ip, username, password, intf_type,
            intf_name, intf_state, rbridge_id):
        """Run helper methods to implement the desired state.
        """

        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = self.switch_operation(intf_name, intf_state, intf_type, rbridge_id)

        return changes

    @log_exceptions
    def switch_operation(self, intf_name, intf_state, intf_type, rbridge_id):
        changes = {}
        with self.pmgr(conn=self.conn, auth_snmp=self.auth_snmp) as device:
            self.logger.info(
                'successfully connected to %s to validate interface state',
                self.host)

            valid_rbridge_int_types = ['ve', 'loopback']
            if device.os_type == 'nos':
                if intf_type in valid_rbridge_int_types and rbridge_id is None:
                    raise ValueError('rbridge-id should not be empty. '
                                     'Specify a valid value.')

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

    def _check_interface_presence(self, device, intf_type, intf_name):

        if intf_type not in device.interface.valid_int_types:
            self.logger.error('Iterface type is not valid. '
                              'Interface type must be one of %s'
                              % device.interface.valid_int_types)
            raise ValueError('Iterface type is not valid. '
                             'Interface type must be one of %s'
                             % device.interface.valid_int_types)

        if not self.validate_interface(intf_type, intf_name, os_type=device.os_type):
            raise ValueError('Interface %s is not valid' % (intf_name))

        if not device.interface.interface_exists(int_type=intf_type,
                                                 name=intf_name):
            self.logger.error('Interface %s %s not present on the Device'
                              % (intf_type, intf_name))
            sys.exit(-1)

        return True

    def _validate_interface_state(
            self, device, intf_type, intf_name, intf_state, rbridge_id):
        """validate interface state.
        """

        changes = {}
        retVal = True
        if device.os_type == 'NI':
            oper_state = device.interface.get_oper_state(int_type=intf_type,
                                                       name=intf_name)
            changes['intf'] = True
            changes['state'] = oper_state
            ifname = intf_type + " " + intf_name
            if oper_state == intf_state:
                self.logger.info('Successfully validated interface %s'
                                ' state as %s' % (ifname, oper_state))
            else:
                self.logger.error("Invalid interface %s state %s"
                                % (ifname, oper_state))
                sys.exit(-1)
            return changes

        valid_rbridge_int_types = ['ve', 'loopback']
        if intf_type in valid_rbridge_int_types:
            if device.os_type == 'nos':
                for rb in rbridge_id:
                    is_intf_present = False
                    is_intf_state_present = False
                    interfaces = device.interface.ve_interfaces(rbridge_id=rb)
                    for intf in interfaces:
                        intfname = intf['if-name'].lower()
                        iftype = str(intf_type).lower()
                        ifname = iftype + " " + intf_name
                        if ifname == intfname:
                            changes['intf'] = True
                            is_intf_present = True
                            proto_state = intf['interface-proto-state']
                            if proto_state == intf_state:
                                changes['state'] = proto_state
                                self.logger.info(
                                    'Successfully Validated interface %s'
                                    ' state as %s in rbridge-id %s' % (ifname, proto_state, rb))
                                is_intf_state_present = True
                                break
                            else:
                                changes['state'] = False
                        else:
                            changes['intf'] = False

                    if not is_intf_present:
                        self.logger.error(
                            "Invalid port channel/physical interface name/type in rbridge-id %s"
                            % rb)
                        retVal = False
                    else:
                        if not is_intf_state_present:
                            self.logger.error(
                                "Invalid interface %s state %s in rbridge-id %s"
                                % (ifname, proto_state, rb))
                            retVal = False
                if not retVal:
                    sys.exit(-1)
            else:
                is_intf_present = False
                is_intf_state_present = False
                interfaces = device.interface.ve_interfaces()
                for intf in interfaces:
                    intfname = intf['if-name'].lower()
                    iftype = str(intf_type).lower()
                    ifname = iftype + " " + intf_name
                    if ifname == intfname:
                        changes['intf'] = True
                        is_intf_present = True
                        proto_state = intf['interface-proto-state']
                        if proto_state == intf_state:
                            changes['state'] = proto_state
                            self.logger.info(
                                'Successfully validated interface %s'
                                ' state as %s' % (ifname, proto_state))
                            is_intf_state_present = True
                            break
                        else:
                            changes['state'] = False
                    else:
                        changes['intf'] = False

                if not is_intf_present:
                    self.logger.error(
                        "Invalid interface name/type %s" % (ifname))
                    sys.exit(-1)
                else:
                    if not is_intf_state_present:
                        self.logger.error(
                            "Invalid interface %s state %s"
                            % (ifname, proto_state))
                        sys.exit(-1)

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
            if proto_state:
                changes['intf'] = True
                if proto_state == intf_state:
                    changes['state'] = proto_state
                    self.logger.info(
                        'Successfully validated interface %s'
                        ' state as %s' % (ifname, proto_state))
                else:
                    self.logger.error(
                        "Invalid interface %s state %s"
                        % (ifname, proto_state))
                    changes['state'] = False
                    sys.exit(-1)
            else:
                self.logger.error(
                    "Invalid interface name/type %s" % (ifname))
                changes['intf'] = False
                sys.exit(-1)

        return changes
