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


class DeleteSwitchport(NosDeviceAction):
    """
       Implements the logic to Delete SwitchPorts on DUT.
       This action achieves the below functionality
           1.Delete Switchport on an interface
    """

    def run(self, mgmt_ip, username, password, intf_type, intf_name):
        """Run helper methods to implement the desired state.
        """

        try:
            self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        except Exception as e:
            self.logger.error(e.message)
            sys.exit(-1)
        changes = self.switch_operation(intf_type, intf_name)

        return changes

    @log_exceptions
    def switch_operation(self, intf_type, intf_name):

        changes = {}
        with self.pmgr(conn=self.conn, auth_snmp=self.auth_snmp) as device:
            self.logger.info(
                'successfully connected to %s to Delete Switch Port on the interfaces'
                ' on the device', self.host)

            intf_list = self.expand_interface_range(intf_type=intf_type, intf_name=intf_name,
                                                    rbridge_id='')
            if intf_list is not None:
                int_list_present = self._check_interface_presence(device, intf_type,
                                                                  intf_list)
                if int_list_present != []:
                    changes['delete_switchport_intf'] = self._delete_switchport(device, intf_type,
                                                                                int_list_present)

            self.logger.info('Closing connection to %s after Deleting Switchports on the interface'
                             'on the device -- all done!',
                             self.host)
        return changes

    def _check_interface_presence(self, device, intf_type, intf_list):

        intf_list_present = intf_list[:]
        if intf_type not in device.interface.valid_int_types:
            self.logger.error('Interface type is not valid. '
                              'Interface type must be one of %s'
                              % device.interface.valid_int_types)
            raise ValueError('Interface type is not valid. '
                             'Interface type must be one of %s'
                             % device.interface.valid_int_types)
        for each_intf in intf_list:
            if not self.validate_interface(intf_type, str(each_intf)):
                raise ValueError('Interface %s is not valid' % (each_intf))

            if not device.interface.interface_exists(int_type=intf_type,
                                                     name=each_intf):
                self.logger.info('Interface %s %s not present on the Device'
                                 % (intf_type, each_intf))
                intf_list_present.remove(each_intf)

        return intf_list_present

    def _delete_switchport(self, device, intf_type, int_list_present):
        """ Delete Switch Port interfaces """

        try:
            self.logger.info('Deleting Switch Port on %s %s', intf_type,
                             int_list_present)
            for each_mg in int_list_present:
                device.interface.disable_switchport(inter_type=intf_type,
                                                    inter=each_mg)
        except (ValueError, KeyError):
            self.logger.exception("Deleting Switch Port %s Failed", each_mg)
            raise ValueError("Deleting Switch Ports Failed")

        return True
