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
import re
import sys


class AutoPickLifID(NosDeviceAction):
    """
       Implements the logic to autofetch lif ids on SLXOS Switches .
       This action acheives the below functionality
           1. Provides single/list of next available lif ids
    """

    def run(self, mgmt_ip, username, password, intf_type, intf_name,
            length_of_the_range):
        """Run helper methods to implement the desired state.
        """

        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = self.switch_operation(intf_type, intf_name, length_of_the_range)
        return changes

    @log_exceptions
    def switch_operation(self, intf_type, intf_name, length_of_the_range):
        changes = {}
        with self.pmgr(conn=self.conn, auth_snmp=self.auth_snmp) as device:
            self.logger.info(
                'Successfully connected to %s to fetch LIF ID', self.host)

            if device.os_type == 'nos':
                self.logger.error('Operation is not supported on this device')
                raise ValueError('Operation is not supported on this device')

            changes['valid_lif'], lif_list = self._check_interface_presence(device,
                                                                            intf_type,
                                                                            intf_name)
            changes['lif_ids'] = self._lif_num(device, intf_type, intf_name, lif_list,
                                               length_of_the_range)
            self.logger.info('Closing connection to %s after'
                             ' autopicking Lif ID  -- all done!',
                             self.host)
        return changes

    def _check_interface_presence(self, device, intf_type, intf_name):

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

        lifs = device.interface.logical_interface_create(get=True, intf_type=intf_type,
                                                         intf_name=intf_name)
        return True, lifs

    def _lif_num(self, device, intf_type, intf_name, lif_list, length_of_the_range):

        re_pattern = r"^(\d+)$"

        if re.search(re_pattern, length_of_the_range):
            length_of_the_range = int(length_of_the_range)
        else:
            length_of_the_range = len(self.get_vlan_list(length_of_the_range, device))

        lifs = [int(e.split('.')[1]) for e in lif_list]
        lifs_list = []
        for i in xrange(1, sys.maxsize):
            if i not in lifs:
                tmp_id = intf_name + '.' + str(i)
                lifs_list.append(tmp_id)
            if len(lifs_list) == length_of_the_range:
                break
        # convert the list to string for the workflow
        tmp_str = ''
        for tmp in lifs_list:
            tmp_str = tmp_str + ',' + tmp
        num = tmp_str.lstrip(',')

        return num
