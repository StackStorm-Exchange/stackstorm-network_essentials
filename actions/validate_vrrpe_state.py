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
import pynos.utilities
import re
import sys
from execute_cli import CliCMD


class validate_vrrpe_state(NosDeviceAction):
    """
       Implements the logic to validate the vrrpe protocol state on VDX switches.
    """

    def run(self, mgmt_ip, username, password, vlan_id, vrrpe_group):
        """Run helper methods to implement the desired state.
        """

        changes = {}
        vrrpe_roles = []
        check_roles = []
        final_check = []
        for each_host in zip(mgmt_ip, username, password):
            host = each_host[0]
            user = each_host[1]
            passwd = each_host[2]
            self.setup_connection(host=host, user=user, passwd=passwd)
            device = self.mgr(conn=self.conn, auth=self.auth)
            changes['pre_check'] = self._validate_if_ve_exists(device, vlan_id, vrid=vrrpe_group)
            if changes['pre_check']:
                roles = self._fetch_vrrpe_state(device, vlan_id, vrid=vrrpe_group)
                vrrpe_roles.append(roles)
            else:
                raise ValueError('Vlan_id %s doesnt exist', vlan_id)
        # Check if there are more than one VRRPE master in the given IP list
        changes['vrrpe_group_details'] = vrrpe_roles
        for each_role in changes['vrrpe_group_details']:
            if each_role['vrrpe_role']:
                tmp_role = each_role['vrrpe_role']
                check_roles.append(tmp_role)
            final_check.append(each_role['check'])
        if check_roles.count('Master') != 1:
            self.logger.info('There are more than one VRRPe Master in the given IP list')
            return changes
            sys.exit(1)
        if False in final_check:
            return changes
            sys.exit(1)
        return changes

    def _validate_if_ve_exists(self, device, vlan_id, vrid):
        """validate vlan_id
        """

        valid_vlan = pynos.utilities.valid_vlan_id(vlan_id=vlan_id, extended=True)
        if not valid_vlan:
            raise ValueError('Invalid Vlan_id %s', vlan_id)
        is_exists = False
        vlan_list = device.interface.ve_interfaces()

        for each_ve in vlan_list:
            tmp_ve_name = 'Ve ' + vlan_id
            if each_ve['if-name'] == tmp_ve_name:
                is_exists = True
                break
        return is_exists

    def _fetch_vrrpe_state(self, device, vlan_id, vrid):
        """validate vrrpe state.
        """

        exec_cli = CliCMD()
        host_ip = self.host
        host_username = self.auth[0]
        host_password = self.auth[1]
        roles = []
        cli_cmd = 'show vrrp interface ve' + " " + str(vlan_id)

        mode = 'Mode: VRRPE'
        vrid_pattern = re.compile('VRID (.*)')
        ve_pattern = 'Interface: Ve ' + vlan_id + ';'
        vrrpe_role = '(Master|Backup)'
        vrrpe_state = 'Admin Status: Enabled'
        spf_state = 'Short-path-forwarding: Enabled'
        raw_cli_output = exec_cli.execute_cli_command(host=host_ip, user=host_username,
                                                      passwd=host_password,
                                                      cli_cmd=cli_cmd)
        cli_output = raw_cli_output[cli_cmd]
        vrid_match = vrid_pattern.findall(cli_output)
        ve_match = re.search(ve_pattern, cli_output)
        vrrpe_role_match = re.search(vrrpe_role, cli_output)
        vrrpe_state_match = re.search(vrrpe_state, cli_output)
        mode_match = re.search(mode, cli_output)
        spf_match = re.search(spf_state, cli_output)
        vrid_check = True
        mode_check = True
        role_check = True
        admin_check = True
        spf_check = True
        if str(vrid_match[0]) == str(vrid) and ve_match is not None:
            if mode_match is not None:
                if vrrpe_role_match is not None:
                    if vrrpe_state_match is not None:
                        if spf_match is not None:
                            self.logger.info('vrrpe state validation for vrrp-e group %s and'
                                             ' Vlan_id %s on mgmt IP %s is complete',
                                             vlan_id, vrid, host_ip)
                        else:
                            self.logger.info('SPF is disabled on Vlan_id %s on IP %s',
                                             vlan_id, host_ip)
                            spf_check = False
                    else:
                        self.logger.info('vrrpe admin is disabled on Vlan_id %s on IP %s',
                                         vlan_id, host_ip)
                        admin_check = False
                else:
                    self.logger.info('vrrpe role is either master/backup on Vlan_id %s on IP %s',
                                     vlan_id, host_ip)
                    role_check = False
            else:
                self.logger.info('vrrpe mode mis-match on Vlan_id %s on IP %s', vlan_id, host_ip)
                mode_check = False
        else:
            self.logger.info('vrrpe-group %s is not configured on Vlan_id %s on IP %s',
                             vrid, vlan_id, host_ip)
            vrid_check = False
        if vrid_check:
            vrrpe_role = vrrpe_role_match.group(1)
            vlan_id = vlan_id
            vrid = vrid
            tmproles = vrrpe_role
            check = True
            if False in [mode_check, role_check, admin_check, spf_check]:
                check = False
            roles = {'mgmt_ip': host_ip,
                     'vlan_id': vlan_id,
                     'vrrpe_group': vrid,
                     'vrrpe_role': tmproles,
                     'check': check}
        else:
            sys.exit(1)

        return roles
