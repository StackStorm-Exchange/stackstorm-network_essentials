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
import pyswitch.utilities
from pyswitch.device import Device


class DeleteVe(NosDeviceAction):
    """
       Implements the logic to delete ve configuration on VDX and SLX devices .
       This action achieves the below functionality
           1.Verify whether the ve is already exist in the switch or not.
           2.Delete ve
    """

    def run(self, mgmt_ip, username, password, vlan_id, rbridge_id):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = {}

        valid_vlan = pyswitch.utilities.valid_vlan_id(vlan_id=vlan_id)

        with Device(conn=self.conn, auth=self.auth) as device:
            self.logger.info('successfully connected to %s to Delete Ve',
                             self.host)
            changes['vrf'] = self._delete_ve(device, ve_name=vlan_id, rbridge_id=rbridge_id)

            self.logger.info('closing connection to %s after'
                         ' Deleting Ve -- all done!', self.host)
        return changes

    def _delete_ve(self, device, ve_name, rbridge_id):
        """ Deleting Ve"""

        is_ve_present = True
        user_ve = str(ve_name)
        if rbridge_id:
            for rbid in rbridge_id:
                rb = str(rbid)
                tmp_ve_name = device.interface.create_ve(get=True, ve_name=user_ve,
                                                         rbridge_id=rb)
                tmp_dut_ve = [str(item) for item in tmp_ve_name]
                for each_ve in tmp_dut_ve:
                    if each_ve == user_ve:
                        self.logger.info('Deleting Ve %s from rbridge_id %s ', user_ve, rb)
                        device.interface.create_ve(rbridge_id=rb, delete=True, ve_name=52)
                        is_ve_present = False
        else:
            tmp_ve_name = device.interface.create_ve(get=True, ve_name='100')
            tmp_dut_ve = [str(item) for item in tmp_ve_name]
            for each_ve in tmp_dut_ve:
                if each_ve == user_ve:
                    self.logger.info('Deleting Ve %s', user_ve)
                    device.interface.create_ve(delete=True, ve_name=52)
                    is_ve_present = False

        if not is_ve_present:
            return True
        else:
            self.logger.info('Ve %s does not exist in the switch', user_ve)
            return False
