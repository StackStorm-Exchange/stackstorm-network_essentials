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

MAX_DOT1Q_VLAN = 4095


class AutoPickPortChannel(NosDeviceAction):
    """
       Implements the logic to autofetch  vfab or network id on
        VDX/SLX Switches .
       This action acheives the below functionality
           1.Provides a vfab number if vfab or network id is not passed
    """

    def run(self, mgmt_ip, username, password):
        """Run helper methods to implement the desired state.
        """

        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = self.switch_operation()
        return changes

    @log_exceptions
    def switch_operation(self):
        changes = {}
        with self.pmgr(conn=self.conn, auth=self.auth) as device:
            self.logger.info(
                'successfully connected to %s to fetch vfab id or network id',
                self.host)
            changes['vf_id'] = str(
                self._no_vfab_number(device))
            self.logger.info('closing connection to %s after'
                             ' autopicking vfab or network id  -- all done!',
                             self.host)
        return changes

    def _no_vfab_number(self, device):
        """ vfab number is Null , provide a number between 1-6144
            which is not pre-existing
        """
        vfab_array = []
        vfab_range = xrange(4096, 8192)
        try:
            vfab_mode = device.interface.vfab_enable(get=True)
            if not vfab_mode:
                self.logger.info('vfab mode is disabled Hence autopicking'
                                 ' is not possible')
                return None
            result = device.interface.vlans
        except Exception as e:
            raise ValueError(e)
        for res in result:
            vfab_num = int(res['vlan-id'])
            if vfab_num < MAX_DOT1Q_VLAN + 1:
                continue
            vfab_array.append(vfab_num)
        for num in vfab_range:
            if num not in vfab_array:
                break
        return num
