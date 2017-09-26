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
import itertools


class DeleteMacGroup(NosDeviceAction):
    """
       Implements the logic to Delete mac group on VDX devices.
       This action achieves the below functionality
           1.Delete mac group.
    """

    def run(self, mgmt_ip, username, password, mac_group_id):
        """Run helper methods to implement the desired state.
        """

        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = self.switch_operation(mac_group_id)

        return changes

    @log_exceptions
    def switch_operation(self, mac_group_id):

        changes = {}
        with self.pmgr(conn=self.conn, auth=self.auth) as device:
            self.logger.info(
                'successfully connected to %s to Delete Mac Groups'
                ' on the device', self.host)

            mac_group_list = list(itertools.chain.from_iterable(range(int(ranges[0]),
                                  int(ranges[1]) + 1) for ranges in ((el + [el[0]])[:2]
                                  for el in (miniRange.split('-')
                                  for miniRange in mac_group_id.split(',')))))

            self._validate_inputs(mac_group_list)
            macs = self._pre_check_mac_group(device, mac_group_list)
            if macs != []:
                changes['delete_mac_group'] = self._delete_mac_group(device, mac_group_id=macs)

            self.logger.info('Closing connection to %s after Deleting Mac Groups'
                             'on the device -- all done!',
                             self.host)
        return changes

    def _validate_inputs(self, mac_group_list):
        """ Check if inputs are valid or not """

        for mac_group_id in mac_group_list:
            if mac_group_id not in range(1, 501):
                raise ValueError('Invalid MAC Group Id %s', mac_group_id)

        return True

    def _pre_check_mac_group(self, device, mac_group_list):
        """ Check if mac group is pre-configured or not """

        out = device.interface.mac_group_create(get=True)
        mg_list = mac_group_list[:]
        if out is not None:
            for mac_group_id in mac_group_list:
                if str(mac_group_id) not in out:
                    self.logger.info('Mac Group %s is not present on the device', mac_group_id)
                    mg_list.remove(mac_group_id)
        else:
            self.logger.info('No Mac Groups %s are not present on the device', mac_group_list)
            mg_list = []
        return mg_list

    def _delete_mac_group(self, device, mac_group_id):
        """ Delete mac groups """

        try:
            self.logger.info('Deleting Mac Groups %s', mac_group_id)
            for each_mg in mac_group_id:
                device.interface.mac_group_create(delete=True, mac_group_id=each_mg)
        except (ValueError, KeyError):
            self.logger.exception("Deleting Mac Group %s Failed", each_mg)
            raise ValueError("Deleting Mac Group Failed")

        return True
