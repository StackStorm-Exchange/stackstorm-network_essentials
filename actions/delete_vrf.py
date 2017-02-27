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
from pyswitch.device import Device


class DeleteVrf(NosDeviceAction):
    """
       Implements the logic to delete vrf configuration on VDX and SLX devices .
       This action achieves the below functionality
           1.Verify whether the vrf is already exist in the switch or not.
           2.Delete vrf
    """

    def run(self, mgmt_ip, username, password, vrf_name, rbridge_id):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = {}

        if len(vrf_name) > 32:
            raise ValueError('vrf_name length is greater than 32', vrf_name)

        with Device(conn=self.conn, auth=self.auth) as device:
            self.logger.info('successfully connected to %s to delete vrf',
                             self.host)
            changes['vrf'] = self._delete_vrf(device, vrf_name=vrf_name, rbridge_id=rbridge_id)

            self.logger.info('closing connection to %s after'
                         ' deleting vrf -- all done!', self.host)
        return changes

    def _delete_vrf(self, device, vrf_name, rbridge_id):
        """ Deleting the vrf"""

        is_vrf_present = True
        if rbridge_id:
            for rbid in rbridge_id:
                rb = str(rbid)
                vrfs = device.interface.vrf(rbridge_id=rb, get=True)
                for vrf in vrfs:
                    vrfname = vrf['vrf_name']
                    if vrfname == vrf_name:
                        self.logger.info('Deleting VRF %s from rbridge %s ', vrf_name, rb)
                        device.interface.vrf(rbridge_id=rb, delete=True, vrf_name=vrf_name)
                        is_vrf_present = False
        else:
            vrfs = device.interface.vrf(get=True)
            for vrf in vrfs:
                vrfname = vrf['vrf_name']
                if vrfname == vrf_name:
                    self.logger.info('Deleting VRF %s', vrf_name)
                    device.interface.vrf(delete=True, vrf_name=vrf_name)
                    is_vrf_present = False

        if not is_vrf_present:
            return True
        else:
            self.logger.info('VRF %s does not exist in the switch', vrf_name)
            return False
