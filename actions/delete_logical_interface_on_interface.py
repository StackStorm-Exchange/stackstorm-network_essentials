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


class DeleteLogicalInterface(NosDeviceAction):
    """
       Implements the logic to Delete LIFs under an interface.
       This action achieves the below functionality
           1.Delete a single/all the logical interface under an interface
    """

    def run(self, mgmt_ip, username, password, logical_interface_number,
            intf_type, intf_name):
        """Run helper methods to implement the desired state.
        """

        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = self.switch_operation(logical_interface_number,
                                        intf_type, intf_name)

        return changes

    @log_exceptions
    def switch_operation(self, logical_interface_number, intf_type, intf_name):
        changes = {}
        with self.pmgr(conn=self.conn, auth_snmp=self.auth_snmp) as device:
            self.logger.info(
                'successfully connected to %s to Delete Logical interfaces',
                self.host)
            if logical_interface_number == 'all':
                self._check_interface_presence(device, intf_type,
                                               intf_name, lif_name=None)
                changes['lif_delete'] = self._logical_interface_delete_all(device,
                                                                           intf_type,
                                                                           intf_name)

            else:
                lif_name = logical_interface_number.split(',')
                self._check_interface_presence(device, intf_type,
                                               intf_name, lif_name)

                changes['lif_delete'] = self._logical_interface_delete(device, intf_type,
                                                                       intf_name,
                                                                       lif_name)
            self.logger.info('Closing connection to %s after Deleting '
                             'logical interfaces -- all done!',
                             self.host)
        return changes

    def _check_interface_presence(self, device, intf_type, intf_name, lif_name):

        if intf_type not in device.interface.valid_int_types:
            self.logger.error('Interface type is not valid. '
                              'Interface type must be one of %s'
                              % device.interface.valid_int_types)
            raise ValueError('Interface type is not valid. '
                             'Interface type must be one of %s'
                             % device.interface.valid_int_types)

        if not self.validate_interface(intf_type, intf_name, os_type=device.os_type):
            raise ValueError('Interface %s is not valid' % (intf_name))

        if not device.interface.interface_exists(int_type=intf_type,
                                                 name=intf_name):
            self.logger.error('Interface %s %s is not present on the Device'
                              % (intf_type, intf_name))
            raise ValueError('Interface %s %s is not present on the Device'
                             % (intf_type, intf_name))

        return True


    def _logical_interface_delete(self, device, intf_type, intf_name, lif_name):
        """ Deleting logical interface under an interface """

        try:
            for each_lif in lif_name:
                self.logger.info('Deleting lif_name %s under intf_name %s', each_lif, intf_name)
                device.interface.logical_interface_create(delete=True, intf_type=intf_type,
                                                          intf_name=intf_name,
                                                          lif_name=each_lif)
        except ValueError as e:
                self.logger.exception("Deleting logical interface failed %s"
                                      % (e.message))
                raise ValueError("Deleting logical interface failed")
        return True

    def _logical_interface_delete_all(self, device, intf_type, intf_name):
        """ Deleting all logical interface under an interface """

        try:
            device.interface.logical_interface_create(delete=True, intf_type=intf_type,
                                                      intf_name=intf_name)
            self.logger.info('Deleted all lifs under intf_name %s', intf_name)
        except ValueError as e:
                self.logger.exception("Deleting logical interface failed %s"
                                      % (e.message))
                raise ValueError("Deleting logical interface failed")
        return True
