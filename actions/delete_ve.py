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
import sys


class DeleteVe(NosDeviceAction):
    """
       Implements the logic to delete ve configuration on VDX and SLX devices .
       This action achieves the below functionality
           1.Verify whether the ve is already exist in the switch or not.
           2.Delete ve
    """

    def run(self, mgmt_ip, username, password, vlan_id, ve_id, rbridge_id):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = {}

        with Device(conn=self.conn, auth=self.auth) as device:
            if device.os_type == 'nos' and rbridge_id is None:
                rbridge_id = self.vlag_pair(device)
            self.validate_supports_rbridge(device, rbridge_id=rbridge_id)

            self.logger.info('successfully connected to %s to Delete Ve',
                             self.host)
            if device.interface.is_ve_id_required():
                if ve_id is None:
                    self.logger.error('VE interface id is required for VE deletion on MLX platform')
                    sys.exit(-1)
            else:
                # TBD change this for SLX as ve_id and vlan_id need not be same
                ve_id = vlan_id
            changes['pre_check'] = self._check_req(device, rbridge_id=rbridge_id,
                                                   vlan_id=vlan_id, ve_id=ve_id)
            if changes['pre_check']:
                changes['Ve'] = self._delete_ve(device, ve_name=ve_id, vlan_id=vlan_id,
                                                rbridge_id=rbridge_id)
            self.logger.info('closing connection to %s after'
                         ' Deleting Ve -- all done!', self.host)
        return changes

    def _check_req(self, device, rbridge_id, vlan_id, ve_id):

        if device.os_type == 'nos':
            valid_vlan = pyswitch.utilities.valid_vlan_id(vlan_id=vlan_id, extended=True)
        else:
            valid_vlan = pyswitch.utilities.valid_vlan_id(vlan_id=vlan_id, extended=False)

        if not valid_vlan:
            raise ValueError('Invalid vlan_id', vlan_id)

        if device.interface.is_vlan_rtr_ve_config_req():
            curr_ve_id = device.interface.vlan_router_ve(get=True, vlan_id=vlan_id)
            if curr_ve_id is None:
                self.logger.error('No VE %s exists for VLAN %s', ve_id, vlan_id)
                sys.exit(-1)
            elif ve_id != curr_ve_id:
                self.logger.error('vlan_id %s is mapped to a different router interface ve %s',
                                 vlan_id, curr_ve_id)
                sys.exit(-1)

        return True

    def _delete_ve(self, device, ve_name, vlan_id, rbridge_id):
        """ Deleting Ve"""

        user_ve = str(ve_name)

        if rbridge_id and device.os_type == 'nos':
            for rbid in rbridge_id:
                rb = str(rbid)
                tmp_ve_name = device.interface.create_ve(get=True, ve_name=user_ve,
                                                         rbridge_id=rb)
                tmp_dut_ve = [str(item) for item in tmp_ve_name]
                if user_ve in tmp_dut_ve:
                    self.logger.info('Deleting Ve %s from rbridge_id %s ', user_ve, rb)
                    device.interface.create_ve(rbridge_id=rb, enable=False, ve_name=user_ve)
                    return True
                else:
                    self.logger.info('Ve %s does not exist in the switch', user_ve)
                    return False
        else:
            try:
                tmp_ve_name = device.interface.create_ve(get=True, ve_name=user_ve)
                tmp_dut_ve = [str(item) for item in tmp_ve_name]
                if user_ve in tmp_dut_ve:
                    self.logger.info('Deleting router interface %s to vlan %s mapping and Ve %s',
                                     ve_name, ve_name, user_ve)
                    device.interface.vlan_router_ve(delete=True, vlan_id=vlan_id, ve_config=ve_name)
                    device.interface.create_ve(enable=False, ve_name=user_ve)
                    return True
                else:
                    self.logger.info('Ve %s does not exist in the switch', user_ve)
                    return False
            except (ValueError, KeyError) as e:
                self.logger.error('Invalid input value while deleting Ve %s %s'
                                % (ve_name, e.message))
                sys.exit(-1)
