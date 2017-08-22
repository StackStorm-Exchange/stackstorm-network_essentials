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

MAX_DOT1Q_VLAN = 4095


class AutoPickPortChannel(NosDeviceAction):
    """
       Implements the logic to autofetch  vfab or network id on
        VDX Switches .
       This action acheives the below functionality
           1.Provides a vfab number if vfab or network id is not passed
    """

    def run(self, mgmt_ip, username, password, length_of_the_range):
        """Run helper methods to implement the desired state.
        """

        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = self.switch_operation(length_of_the_range)
        return changes

    @log_exceptions
    def switch_operation(self, length_of_the_range):
        changes = {}
        with self.pmgr(conn=self.conn, auth=self.auth) as device:
            if device.os_type != 'nos':
                self.logger.error('VF feature is supported only on VDX platform')
                raise TypeError('Action is valid only VDX platform')
            self.logger.info(
                'successfully connected to %s to fetch vfab id or network id',
                self.host)
            changes['vf_id'] = str(
                self._no_vfab_number(device, length_of_the_range))
            self.logger.info('closing connection to %s after'
                             ' autopicking vfab or network id  -- all done!',
                             self.host)
        return changes

    def _no_vfab_number(self, device, length_of_the_range):
        """ vfab number is Null , provide a number between 1-6144
            which is not pre-existing
        """
        vfab_array = []
        vfab_range = xrange(4096, 8192)
        re_pattern1 = r"^(\d+)$"
        re_pattern2 = r"^(\d+)\-(\d+)$"

        if re.search(re_pattern2, length_of_the_range):
            length = len(range(int(length_of_the_range.split('-')[0]),
                               int(length_of_the_range.split('-')[1]) + 1))
            length_of_the_range = int(length)
        elif re.search(re_pattern1, length_of_the_range):
            length_of_the_range = int(length_of_the_range)
        else:
            self.logger.error('Invalid format in args `length_of_the_range`')
            raise ValueError('Invalid format in args `length_of_the_range`')

        try:
            vfab_mode = device.interface.vfab_enable(get=True)
            if not vfab_mode:
                self.logger.info('vfab mode is disabled, hence autopicking'
                                 ' is not possible')
                return None
            if int(length_of_the_range) not in xrange(1, 4096):
                self.logger.error('length_of_the_range %s must be a value between 1 to 4095',
                                  length_of_the_range)
                raise ValueError('length_of_the_range %s must be a value between 1 to 4095' %
                                 (length_of_the_range))
            result = device.interface.vlans
        except Exception as e:
            raise ValueError(e)
        for res in result:
            vfab_num = int(res['vlan-id'])
            if vfab_num < MAX_DOT1Q_VLAN + 1:
                continue
            vfab_array.append(vfab_num)

        available_vlans_length = len(xrange(4096, 8192)) - len(vfab_array)
        if available_vlans_length < length_of_the_range:
            self.logger.error('Not enough VF IDs are available on the device for the range')
            raise ValueError('Not enough VF IDs are available on the device for the range')

        if length_of_the_range == 1:
            for num in vfab_range:
                if num not in vfab_array:
                    break
                elif num == 8191:
                    self.logger.info('No free VF ID available on the device')
                    num = ''
        else:
            tmp_list = []
            available_vlans = set(xrange(4096, 8192)).symmetric_difference(set(vfab_array))
            for numd in available_vlans:
                if len(tmp_list) == length_of_the_range:
                    break
                tmp_list.append(numd)

            # convert the list to string for the workflow
            vlan_str = ''
            for tmp in tmp_list:
                vlan_str = vlan_str + ',' + str(tmp)
            num = vlan_str.lstrip(',')
        return num
