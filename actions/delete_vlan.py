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
from execute_cli import CliCMD


class DeleteVlan(NosDeviceAction):
    """
       Implements the logic to Deletes vlans on VDX and SLX devices.
    """

    def run(self, mgmt_ip, username, password, vlan_id):
        """Run helper methods to implement the desired state.
        """

        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = self.switch_operation(vlan_id)

        return changes

    def switch_operation(self, vlan_id):
        changes = {}
        with Device(conn=self.conn, auth=self.auth) as device:
            self.logger.info(
                'successfully connected to %s to delete interface vlan',
                self.host)
            # Check is the user input for VLANS is correct

            vlan_list = self.expand_vlan_range(vlan_id=vlan_id)

            if vlan_list:
                changes['vlan'] = self._delete_vlan(
                    device, vlan_id=vlan_list)
                changes['show_vlan_brief'] = self._fetch_Vlan_state(device)
            else:
                raise ValueError('Input is not a valid vlan ')

            self.logger.info('Closing connection to %s after configuring '
                             'Delete vlan -- all done!',
                             self.host)
        return changes

    def _delete_vlan(self, device, vlan_id):

        for vlan in vlan_id:
            check_vlan = device.interface.get_vlan_int(vlan)
            if check_vlan is False:
                self.logger.info('VLAN %s does not exist', vlan)
                return False
            else:
                device.interface.del_vlan_int(vlan)
                self.logger.info('VLAN %s is deleted', vlan)
        return True

    def _fetch_Vlan_state(self, device):
        """validate Vlan state.
        """

        exec_cli = CliCMD()
        host_ip = self.host
        host_username = self.auth[0]
        host_password = self.auth[1]
        cli_arr = []
        cli_cmd = 'show vlan brief'
        cli_arr.append(cli_cmd)
        raw_cli_output = exec_cli.execute_cli_command(mgmt_ip=host_ip, username=host_username,
                                                      password=host_password,
                                                      cli_cmd=cli_arr)
        output = str(raw_cli_output)
        return output
