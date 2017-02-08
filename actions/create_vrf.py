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
from execute_cli import CliCMD


class CreateVRF(NosDeviceAction):

    """
       Implements the logic to Create a VRF  on VDX Switches .
       This action acheives the below functionality
           1. Create VRF
    """

    def run(self, mgmt_ip, username, password, vrf_name, rbridge_id):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = {}

        with self.mgr(conn=self.conn, auth=self.auth) as device:
            self.logger.info('successfully connected to %s to Create VRF for tenants',
                             self.host)
            validation_VRF = self._check_requirements_VRF(device, rbridge_id,
                                                          vrf_name)
            if validation_VRF:
                changes['validation_Create_VRF'] = self._create_VRF(device, rbridge_id,
                                                                    vrf_name)
                if changes['validation_Create_VRF']:
                    self._fetch_VRF_state(device, vrf_name)
            self.logger.info('closing connection to %s after Create VRF - all done!',
                             self.host)
        return changes

    def _check_requirements_VRF(self, device, rbridge_id, vrf_name):
        """ pre-checks to identify the existing vrf configurations"""

        vrf_output = device.interface.vrf(get=True, rbridge_id=rbridge_id)
        if vrf_output is not None:
            for each_vrf in vrf_output:
                if each_vrf['vrf_name'] == vrf_name:
                    self.logger.info('VRF %s  already exists on rbridge_id %s',
                                 vrf_name, rbridge_id)
                    return False
        return True

    def _create_VRF(self, device, rbridge_id, vrf_name):
        """ create VRF """

        try:
            self.logger.info('Creating VRF %s on rbridge_id %s', vrf_name, rbridge_id)
            device.interface.vrf(vrf_name=vrf_name, rbridge_id=rbridge_id)
        except (ValueError, KeyError):
            self.logger.info('Invalid Input types while creating VRF %s on rbridge_id %s',
                             vrf_name, rbridge_id)
            return False
        return True

    def _fetch_VRF_state(self, device, vrf_name):
        """validate DAI state.
        """

        exec_cli = CliCMD()
        host_ip = self.host
        host_username = self.auth[0]
        host_password = self.auth[1]
        cli_cmd = 'show vrf ' + vrf_name

        raw_cli_output = exec_cli.execute_cli_command(mgmt_ip=host_ip, username=host_username,
                                                      password=host_password,
                                                      cli_cmd=cli_cmd)
        output = str(raw_cli_output)
        self.logger.info(output)
        return True
