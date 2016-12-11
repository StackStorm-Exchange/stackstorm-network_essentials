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
from ipaddress import ip_interface
import pynos.utilities


class ConfigureAnycastGatewayEVPN(NosDeviceAction):
    """
       Implements the logic to create anycast gateway on a given Ve interface .
       This action acheives the below functionality
           1.Check specified anycast ip and Ve are valid and exists.
           2.Configure anycast gateway on ve interface if anycast is not configured on Ve.
    """

    def run(self, mgmt_ip, username, password, vlan_id, anycast_address):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = {}

        with self.mgr(conn=self.conn, auth=self.auth) as device:
            self.logger.info('successfully connected to %s to create anycast gateway on Ve',
                             self.host)
            rb_list = self._vlag_pair(device)
            for rbridge_id in rb_list:
                vlan_anycast_check_pass = self._check_requirements_anycast(device,
                                                                           vlan_id,
                                                                           anycast_address,
                                                                           rbridge_id)
                if vlan_anycast_check_pass:
                    changes['create_anycast_gw'] = self._create_anycast_gateway(device, vlan_id,
                                                                                anycast_address,
                                                                                rbridge_id)
            self.logger.info(
                'closing connection to %s after configuring anycast gateway on ve -- all done!',
                self.host)
        return changes

    def _check_requirements_anycast(self, device, vlan_id, anycast_address, rbridge_id):
        """Fail the task if ve exists and anycast gateway exists .
        """
        try:
            valid_ve = self._validate_if_ve_exists(device, vlan_id)
            if not valid_ve:
                self.logger.info("Ve interface not configured for rbridge %s", rbridge_id)
                return False
            ipaddress = ip_interface(unicode(anycast_address))
            if ipaddress.version != 4 and ipaddress.version != 6:
                raise ValueError("IP %s Not Valid for rbridge %s", anycast_address, rbridge_id)
        except ValueError:
            self.logger.info("Invalid IP %s", anycast_address)
            return False
        get_code = device.interface.ip_anycast_gateway(get=True, int_type='ve', name=vlan_id,
                                                       rbridge_id=rbridge_id)
        if ipaddress.version == 4:
            if get_code[0].data.find('.//{*}ip-anycast-address') is not None:
                self.logger.info("IP anycast gateway already configured on rbridge %s", rbridge_id)
                return False
        if ipaddress.version == 6:
            if get_code[1].data.find('.//{*}ipv6-anycast-address') is not None:
                self.logger.info("IPV6 anycast gateway already configured on rbridge%s", rbridge_id)
                return False
        return True

    def _create_anycast_gateway(self, device, vlan_id, anycast_address, rbridge_id):
        """ Configuring anycast gateway on Ve interface."""
        try:
            device.interface.ip_anycast_gateway(int_type='ve', name=vlan_id,
                                                anycast_ip=anycast_address,
                                                rbridge_id=rbridge_id)
        except ValueError:
            self.logger.info("Configuring anycast gateway failed for rbridge %s", rbridge_id)
            return False
        self.logger.info("Configured anycast gateway for rbridge %s", rbridge_id)
        return True

    def _validate_if_ve_exists(self, device, vlan_id):
        """validate vlan_id exists.
        """

        valid_vlan = pynos.utilities.valid_vlan_id(vlan_id=vlan_id, extended=True)
        if not valid_vlan:
            self.logger.info('Invalid VLAN id %s', vlan_id)
            return False
        vlan_list = device.interface.ve_interfaces()
        for each_ve in vlan_list:
            if 'Ve' in each_ve['if-name'] and vlan_id in each_ve['if-name']:
                return True
        return False

    def _vlag_pair(self, device):
        """ Fetch the RB list if VLAG is configured"""

        rb_list = []
        result = device.vcs.vcs_nodes
        for each_rb in result:
            rb_list.append(each_rb['node-rbridge-id'])
        if len(rb_list) >= 3:
            raise ValueError('VLAG PAIR must be <= 2 leaf nodes')
        return list(set(rb_list))
