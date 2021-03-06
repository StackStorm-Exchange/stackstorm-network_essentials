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

import re
from ne_base import NosDeviceAction
from ne_base import capture_exceptions
from ne_base import ValidateErrorCodes
from execute_cli import CliCMD
import pyswitch.utilities
from pyswitch.exceptions import InvalidInterfaceName
from pyswitch.exceptions import InvalidVlanId


class validate_vrrpe_state(NosDeviceAction):
    """
       Implements the logic to validate the vrrpe protocol state on VDX switches.
    """

    @capture_exceptions
    def run(self, mgmt_ip, username, password, intf_type, intf_name,
            vrrpe_group, afi):
        """Run helper methods to implement the desired state.
        """

        changes = {}
        reason_code = ValidateErrorCodes.SUCCESS
        changes['reason_code'] = reason_code.value
        vrrpe_roles = []
        check_roles = []
        final_check = []

        if username is None:
            username = []

        if username is None or len(mgmt_ip) != len(username):
            for index in range(len(mgmt_ip)):
                username.append(None)

        if password is None:
            password = []

        if password is None or len(mgmt_ip) != len(password):
            for index in range(len(mgmt_ip)):
                password.append(None)

        for each_host in zip(mgmt_ip, username, password):
            host = each_host[0]
            user = each_host[1]
            passwd = each_host[2]
            self.setup_connection(host=host, user=user, passwd=passwd)
            device = self.pmgr(conn=self.conn, auth_snmp=self.auth_snmp)

            # validate supported interface type for vrrpe
            device.interface.vrrpe_supported_intf(intf_type=intf_type)  # pylint: disable=no-member

            if intf_type == 've':
                changes['pre_check'] = self._validate_if_ve_exists(device,
                                                                   intf_name, vrid=vrrpe_group)
            else:
                changes['pre_check'] = self._validate_if_eth_exists(device,
                                                                    intf_name, vrid=vrrpe_group)

            if changes['pre_check']:

                if device.os_type == 'NI':
                    roles = self._ni_fetch_vrrpe_state(device, intf_type,
                                                       intf_name, afi, vrid=vrrpe_group)
                else:
                    roles = self._fetch_vrrpe_state(device, intf_name, afi,
                                                    vrid=vrrpe_group)
                vrrpe_roles.append(roles)
            else:
                raise ValueError('{0} intf_name {1} doesnt exist'.format(intf_type, intf_name))
        # Check if there are more than one VRRPE master in the given IP list
        changes['vrrpe_group_details'] = vrrpe_roles
        for each_role in changes['vrrpe_group_details']:
            if each_role['vrrpe_role']:
                tmp_role = each_role['vrrpe_role']
                check_roles.append(tmp_role)
            final_check.append(each_role['check'])
        if check_roles.count('Master') > 1:
            self.logger.info('There are more than one VRRPe Master in the given IP list')
            return changes
        if False in final_check:
            return changes

        return changes

    def _validate_if_ve_exists(self, device, vlan_id, vrid):
        """validate vlan_id
        """

        valid_vlan = pyswitch.utilities.valid_vlan_id(vlan_id=vlan_id, extended=True)
        if not valid_vlan:
            raise InvalidVlanId('Invalid interface %s', vlan_id)
        is_exists = False
        vlan_list = device.interface.ve_interfaces()

        for each_ve in vlan_list:
            tmp_ve_name = 'Ve ' + vlan_id
            if each_ve['if-name'] == tmp_ve_name:
                is_exists = True
                break
        return is_exists

    def _validate_if_eth_exists(self, device, intf_name, vrid):
        """validate ethernet interface
        """

        if not self.validate_interface('ethernet', intf_name, os_type=device.os_type):
            raise InvalidInterfaceName('Interface %s is not valid' % (intf_name))

        is_exists = False
        eth_list = device.interface.get_eth_l3_interfaces()

        for each_intf in eth_list:
            tmp_eth_name = 'eth ' + intf_name
            if each_intf['if-name'] == tmp_eth_name:
                is_exists = True
                break
        return is_exists

    def _fetch_vrrpe_state(self, device, vlan_id, afi, vrid):
        """validate vrrpe state.
        """

        exec_cli = CliCMD()
        host_ip = self.host
        host_username = self.auth_snmp[0]
        host_password = self.auth_snmp[1]
        roles = []
        if afi == 'ipv4':
            cli_cmd = 'show vrrp interface ve' + " " + str(vlan_id)
        else:
            cli_cmd = 'show ipv6 vrrp interface ve' + " " + str(vlan_id)

        mode = 'Mode: VRRPE'
        vrid_pattern = re.compile('VRID (.*)')
        ve_pattern = 'Interface: Ve ' + vlan_id + ';'
        vrrpe_role = 'State: (.+)'
        vrrpe_state = 'Admin Status: Enabled'
        spf_state = 'Short-path-forwarding: Enabled'
        device_type = 'ni' if device.os_type == 'NI' else 'nos'
        raw_cli_output = exec_cli.execute_cli_command(mgmt_ip=host_ip, username=host_username,
                                                      password=host_password,
                                                      cli_cmd=[cli_cmd],
                                                      device_type=device_type)
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
        if vrid_match and str(vrid_match[0]) == str(vrid) and ve_match is not None:
            if mode_match is not None:
                if vrrpe_role_match is not None:
                    if vrrpe_state_match is not None:
                        if spf_match is not None:
                            self.logger.info('vrrpe state validation for vrrp-e group %s and'
                                             ' Vlan_id %s on mgmt IP %s is complete',
                                             vrid, vlan_id, host_ip)
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
            msg = 'vrrpe-group {} is not configured'.format(vrid)
            ms = 'on intf_name {} on IP {}'.format(vlan_id, host_ip)
            log_msg = msg + ms
            self.logger.info(log_msg)
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
            raise ValueError(log_msg)

        return roles

    def _ni_fetch_vrrpe_state(self, device, intf_type, intf_name, afi, vrid):
        """validate vrrpe state.
        """

        exec_cli = CliCMD()
        host_ip = self.host
        host_username = self.auth_snmp[0]
        host_password = self.auth_snmp[1]
        roles = []
        if afi == 'ipv4':
            cli_cmd = 'show ip vrrp-extended vrid ' + vrid + " " + intf_type + " " + intf_name
        else:
            cli_cmd = 'show ipv6 vrrp-extended vrid ' + vrid + " " + intf_type + " " + intf_name

        vrid_pattern = r'VRID (.*)'
        intf_pattern = r'interface (.*)'
        vrrpe_role = 'state (.+)'
        vrrpe_state = 'administrative-status enabled'
        spf_state = 'short-path-forwarding enabled'
        device_type = 'ni' if device.os_type == 'NI' else 'nos'
        raw_cli_output = exec_cli.execute_cli_command(mgmt_ip=host_ip, username=host_username,
                                                      password=host_password,
                                                      cli_cmd=[cli_cmd],
                                                      device_type=device_type)
        cli_output = raw_cli_output[cli_cmd]

        vrid_match = re.search(vrid_pattern, cli_output)
        intf_match = re.search(intf_pattern, cli_output)
        vrrpe_role_match = re.search(vrrpe_role, cli_output)
        vrrpe_state_match = re.search(vrrpe_state, cli_output)
        mode_match = True
        spf_match = re.search(spf_state, cli_output)
        vrid_check = True
        mode_check = True
        role_check = True
        admin_check = True
        spf_check = True
        if vrid_match is not None and intf_match is not None:
            if mode_match is not None:
                if vrrpe_role_match is not None:
                    if vrrpe_state_match is not None:
                        if spf_match is not None:
                            self.logger.info('vrrpe state validation for vrrp-e group %s and'
                                             ' intf name %s on mgmt IP %s is complete',
                                             vrid, intf_name, host_ip)
                        else:
                            self.logger.info('SPF is disabled on intf_name %s on IP %s',
                                             intf_name, host_ip)
                            spf_check = False
                    else:
                        self.logger.info('vrrpe admin is disabled on intf_name %s on IP %s',
                                         intf_name, host_ip)
                        admin_check = False
                else:
                    self.logger.info('vrrpe role is either master/backup on intf_name %s on IP %s',
                                     intf_name, host_ip)
                    role_check = False
            else:
                self.logger.info('vrrpe mode mis-match on intf_name %s on IP %s',
                                 intf_name, host_ip)
                mode_check = False
        else:
            msg = 'vrrpe-group {} is not configured'.format(vrid)
            ms = 'on intf_name {} on IP {}'.format(intf_name, host_ip)
            log_msg = msg + ms
            vrid_check = False
        if vrid_check:
            vrrpe_role = vrrpe_role_match.group(1).title()
            intf_name = intf_name
            vrid = vrid
            tmproles = vrrpe_role
            check = True
            if False in [mode_check, role_check, admin_check, spf_check]:
                check = False
            roles = {'mgmt_ip': host_ip,
                     'intf_name': intf_name,
                     'vrrpe_group': vrid,
                     'vrrpe_role': tmproles,
                     'check': check}
        else:
            raise ValueError(log_msg)

        return roles
