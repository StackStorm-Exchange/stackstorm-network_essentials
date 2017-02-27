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


class SetIntfAdminState(NosDeviceAction):
    """
       Implements the logic to enable ports/port-channel on VDX switches.
       This action acheives the below functionality
           1.Interface validation
           2.Enable physical interface/port-channel/ve/loopback on a device
    """

    def run(self, mgmt_ip, username, password, intf_type, intf_name, rbridge_id, enabled,
            intf_desc):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = {}

        intf_type = intf_type.lower()
        with self.mgr(conn=self.conn, auth=self.auth) as device:
            self.logger.info('successfully connected to %s to enable interface', self.host)
            # Check is the user input for Interface Name is correct
            interface_list = self.expand_interface_range(intf_type=intf_type, intf_name=intf_name,
                             rbridge_id=rbridge_id)
            valid_desc = True
            if intf_desc:
                # if description is passed we validate that the length is good.
                valid_desc = self.check_int_description(intf_description=intf_desc)
            if interface_list and valid_desc:
                changes['interface'] = self._set_intf_admin_state(device, intf_type=intf_type,
                                                                  intf_name=interface_list,
                                                                  rbridge_id=rbridge_id,
                                                                  enabled=enabled,
                                                                  intf_desc=intf_desc)
            else:
                raise ValueError('Input is not a valid Interface / description')
            self.logger.info('closing connection to %s after configuring enable interface -- \
                              all done!', self.host)
        return changes

    def _set_intf_admin_state(self, device, intf_type, intf_name, rbridge_id, enabled, intf_desc):
        """Configure the interface to be administratively up or down.
        """
        for intf in intf_name:
            is_intf_interface_present = False
            if rbridge_id:
                # This verification will not work if ve and loopback is not already configured
                intf = str(intf)
                conf = device.interface.admin_state(get=True, name=intf, int_type=intf_type,
                rbridge_id=rbridge_id)
                conf1 = conf.data.find('.//{*}shutdown')
                conf2 = conf.data.find('.//{*}interface')
                if conf1 is None and enabled:
                    self.logger.info('Interface %s %s is already enabled', intf_type, intf)
                    is_intf_interface_present = True
                elif conf1 is not None and not enabled and conf2 is not None:
                    self.logger.info('Interface %s %s is already disabled', intf_type, intf)
                    is_intf_interface_present = True

                if not is_intf_interface_present:
                    self.logger.info('Setting admin state int-type - %s int-name - %s \
                                      on %s', intf_type, intf, self.host)
                    device.interface.admin_state(enabled=enabled, name=intf, int_type=intf_type,
                    rbridge_id=rbridge_id)
            else:
                # This verification will not work if port-channel is not already configured or
                # interface is already enabled
                intf = str(intf)
                conf = device.interface.admin_state(get=True, name=intf, int_type=intf_type)
                conf1 = conf.data.find('.//{*}shutdown')
                conf2 = conf.data.find('.//{*}interface')
                if conf1 is None and enabled and conf2 is not None:
                    self.logger.info('Interface %s %s is already enabled', intf_type, intf)
                    is_intf_interface_present = True
                elif conf1 is None and enabled:
                    msg = 'Invalid Intf-type %s & intf-name %s on %s' % (intf_type, intf, self.host)
                    raise ValueError(msg)
                elif conf1 is None and conf2 is None and not enabled:
                    msg = 'Invalid Intf-type %s & intf-name %s on %s' % (intf_type, intf, self.host)
                    raise ValueError(msg)
                elif conf1 is not None and not enabled and conf2 is not None:
                    self.logger.info('Interface %s %s is already disabled on \
                                      %s', intf_type, intf, self.host)
                    is_intf_interface_present = True

                if not is_intf_interface_present:
                    self.logger.info('Setting admin state int-type - %s int-name \
                                    - %s', intf_type, intf)
                    device.interface.admin_state(enabled=enabled, name=intf, int_type=intf_type)

                if intf_desc:
                    device.interface.description(int_type=intf_type, name=intf,
                                                 desc=intf_desc)
                else:
                    self.logger.debug('Skipping description configuration')
        return True
