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
import re
from execute_cli import CliCMD


class ConfigureARPNDSuppression(NosDeviceAction):
    """
       Implements the logic to configure ARP/ND supression on VLAN .
       This action acheives the below functionality
           1.Check specified vlan has ARP/ND enabled.
           2.Configure configure ARP/ND supression
    """

    def run(self, mgmt_ip, user, passwd, vlan_id, suppression_type):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=mgmt_ip, user=user, passwd=passwd)
        changes = {}

        with self.mgr(conn=self.conn, auth=self.auth) as device:
            self.logger.info('successfully connected to %s to Configure ARP/ND supression on VLAN',
                             self.host)
            Supression_not_configured = self._Check_requirements_ARP_supress(device,
                                                                             vlan_id,
                                                                             suppression_type)
            if Supression_not_configured:
                changes['create_ARP_ND_sup'] = self._configure_ARP_supression(device, vlan_id,
                                                                              suppression_type)
            self.logger.info(
                'closing connection to %s after configuring ARP/ND supression on VLAN --all done!',
                self.host)
        return changes

    def _Check_requirements_ARP_supress(self, device, vlan_id, suppression_type):
        """Fail the task if ARP/ND supression is already configured .
        """
        if suppression_type == "ARP":
            get_code = device.interface.arp_suppression(get=True, name=vlan_id)
            get_code = get_code.data.find('.//{*}suppress-arp')
            if get_code is not None:
                self.logger.info("IP ARP supression is already configured")
                return False
        else:
            self.logger.info("ND and Both Options are not supported currently")
            return False
        return True

    def _configure_ARP_supression(self, device, vlan_id, suppression_type):
        """ Configuring ARP suppression on VLAN."""
        try:
            if suppression_type == "ARP":
                device.interface.arp_suppression(name=vlan_id)
            else:
                self.logger.info('Suppress-ND not supported currently')
        except ValueError:
            self.logger.info("Configuring ARP or ND supression on VLAN failed")
            return False
        self._fetch_DAI_state(device, vlan_id)
        return True

    def _fetch_DAI_state(self, device, vlan_id):
        """validate DAI state.
        """

        exec_cli = CliCMD()
        host_ip = self.host
        host_username = self.auth[0]
        host_password = self.auth[1]
        cli_cmd = 'show hardware-profile current'
        DAI_pattern = 'DNY-ARP-INSP'

        raw_cli_output = exec_cli.execute_cli_command(host=host_ip, user=host_username,
                                                      passwd=host_password,
                                                      cli_cmd=cli_cmd)
        cli_output = raw_cli_output.values()[0]
        DAI_pattern = re.search(DAI_pattern, cli_output)
        if not DAI_pattern:
            self.logger.info('Dynamic ARP inspection is not enabled,pls enabled for better scale')
        return True
