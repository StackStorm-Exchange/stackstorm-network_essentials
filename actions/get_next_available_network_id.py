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


class AutoPickNetworkID(NosDeviceAction):
    """
       Implements the logic to autofetch vfab or network id on
       VDX/SLXOS Switches .
       This action acheives the below functionality
           1. Provides single/list of next available Network IDs
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
            self.logger.info(
                'Successfully connected to %s to fetch Network ID',
                self.host)
            changes['network_id'] = str(
                self._no_vfab_number(device, length_of_the_range))
            self.logger.info('Closing connection to %s after'
                             ' autopicking Network ID  -- all done!',
                             self.host)
        return changes

    def _no_vfab_number(self, device, length_of_the_range):
        """ vfab number is Null , provide a number between 1-6144
            which is not pre-existing
        """
        vfab_array = []
        if device.os_type == 'nos':
            vfab_range = xrange(4096, 8192)
        else:
            vfab_range = xrange(1, 4097)

        re_pattern = r"^(\d+)$"

        if re.search(re_pattern, length_of_the_range):
            length_of_the_range = int(length_of_the_range)
        else:
            length_of_the_range = len(self.get_vlan_list(length_of_the_range))

        if length_of_the_range > 4096:
            self.logger.error('length_of_the_range %s must be a value between 1 to 4095',
                              length_of_the_range)
            raise ValueError('length_of_the_range %s must be a value between 1 to 4095' %
                             (length_of_the_range))

        try:
            if device.os_type == 'nos':
                vfab_mode = device.interface.vfab_enable(get=True)
                if not vfab_mode:
                    self.logger.error('vfab mode is disabled, hence autopicking'
                                      ' is not possible')
                    raise ValueError('vfab mode is disabled, hence autopicking'
                                     ' is not possible')
                result = device.interface.vlans
            else:
                result = device.interface.bridge_domain_all()
        except Exception as e:
            raise ValueError(e)

        for res in result:
            vfab_num = int(res['vlan-id']) if device.os_type == 'nos' else res
            if vfab_num < MAX_DOT1Q_VLAN + 1:
                continue
            vfab_array.append(int(vfab_num))

        available_vlans_length = len(vfab_range) - len(vfab_array)
        if available_vlans_length < length_of_the_range:
            self.logger.error('Not enough Network IDs are available on the device for the range')
            raise ValueError('Not enough Network IDs are available on the device for the range')

        tmp_list = []
        available_vlans = set(vfab_range).symmetric_difference(set(vfab_array))
        for numd in available_vlans:
            tmp_list.append(numd)
            if len(tmp_list) == length_of_the_range:
                break
        # convert the list to string for the workflow
        vlan_str = ''
        for tmp in tmp_list:
            vlan_str = vlan_str + ',' + str(tmp)
        num = vlan_str.lstrip(',')
        return num
