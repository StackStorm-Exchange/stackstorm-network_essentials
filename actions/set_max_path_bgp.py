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


class SetMaxPathBgp(NosDeviceAction):
    """
       Implements the logic to configure Max paths under bgp vrf address family
       under vrf address-family on VDX switches.
       This action acheives the below functionality
           1.max-path validation
           2.Check for the existing configuration on the Device,if not present configure it
    """

    def run(self, mgmt_ip, username, password, rbridge_id, ipv4_vrf_name, ipv6_vrf_name,
            ipv4_unicast, ipv6_unicast, maximum_paths):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = {}
        afi_list = []
        if ipv4_unicast is True:
            afi_list.append('ipv4')
        if ipv6_unicast is True:
            afi_list.append('ipv6')

        vrf_list = []
        if ipv4_vrf_name:
            vrf_list.append(ipv4_vrf_name)
        if ipv6_vrf_name:
            vrf_list.append(ipv6_vrf_name)
        if not ipv4_vrf_name:
            vrf_list.append(None)
        if not ipv6_vrf_name:
            vrf_list.append(None)

        if not afi_list:
            raise ValueError('User Input for Address family ipv4/ipv6 unicast is empty')

        if maximum_paths > 32 or maximum_paths < 1:
            raise ValueError('Input is not a valid Maximum-Paths value')

        max_paths = str(maximum_paths)
        with self.mgr(conn=self.conn, auth=self.auth) as device:
            self.logger.info('successfully connected to %s', self.host)
            if rbridge_id is None:
                rbridge_id = self._vlag_pair(device)
            changes['vrf'] = self._set_max_path_bgp(device, afi_list=afi_list,
                                                    rbridge_id=rbridge_id,
                                                    vrf_list=vrf_list,
                                                    max_paths=max_paths)
            self.logger.info(
                'closing connection to %s after configuring Maximum paths bgp'
                '-- all done!', self.host)
        return changes

    def _set_max_path_bgp(self, device, rbridge_id, vrf_list, afi_list,
                          max_paths):
        """Configuring max-paths under BGP VRF Address family
        """
        result = True
        for rb in rbridge_id:
            for temp in zip(afi_list, vrf_list):
                vrf_name = temp[1]
                afi = temp[0]
                if vrf_name:
                    vrf_output = device.bgp.vrf_unicast_address_family(
                        rbridge_id=rb, afi=afi,
                        vrf=vrf_name, get=True)
                    if vrf_output is not False:
                        # Configuring max-paths when address family vrf is already configured
                        mpaths = device.bgp.vrf_max_paths(rbridge_id=rb,
                                                          afi=afi,
                                                          vrf=vrf_name,
                                                          get=True)
                        if mpaths is None:
                            self.logger.info(
                                'Configuring Maximum-paths %s under Address-Family %s unicast'
                                ' vrf %s in rbridge %s', max_paths, afi, vrf_name, rb)
                            device.bgp.vrf_max_paths(rbridge_id=rb, afi=afi,
                                                     vrf=vrf_name,
                                                     paths=max_paths)
                        else:
                            self.logger.info(
                                'Maximum-paths %s already present under afi %s vrf %s'
                                ' in rbridge %s', mpaths['max_path'], afi, mpaths['vrf'], rb)
                            result = False
                    else:
                        try:
                            self.logger.info(
                                'Configuring Maximum paths %s under Address-Family %s unicast'
                                ' vrf %s on rb %s', max_paths, afi, vrf_name, rb)
                            device.bgp.vrf_unicast_address_family(
                                rbridge_id=rb, afi=afi, vrf=vrf_name)
                            device.bgp.vrf_max_paths(rbridge_id=rb, afi=afi,
                                                     vrf=vrf_name,
                                                     paths=max_paths)
                        except (ValueError, KeyError):
                            self.logger.info('Invalid Input values')
                else:
                    vrf_output = device.bgp.default_vrf_unicast_address_family(
                        rbridge_id=rb, afi=afi,
                        get=True)
                    if vrf_output is not False:
                        # Configuring max-paths when address family vrf is already configured
                        mpaths = device.bgp.default_vrf_max_paths(
                            rbridge_id=rb, afi=afi, get=True)
                        if mpaths is None:
                            self.logger.info(
                                'Configuring max path %s under default vrf Address-Family %s'
                                ' unicast in rbridge %s', max_paths, afi, rb)
                            device.bgp.default_vrf_max_paths(rbridge_id=rb,
                                                             afi=afi,
                                                             paths=max_paths)
                        else:
                            self.logger.info(
                                'Maximum-paths %s already present under default vrf afi %s'
                                ' in rbridge %s', mpaths['max_path'], afi, rb)
                            result = False
                    else:
                        try:
                            self.logger.info(
                                'Configuring max path %s under default vrf Address-Family %s'
                                ' unicast in rbridge %s', max_paths, afi, rb)
                            device.bgp.default_vrf_unicast_address_family(
                                rbridge_id=rb, afi=afi)
                            device.bgp.default_vrf_max_paths(rbridge_id=rb,
                                                             afi=afi,
                                                             paths=max_paths)
                        except (ValueError, KeyError):
                            self.logger.info('Invalid Input values')

        return result

    def _vlag_pair(self, device):
        """ Fetch the RB list if VLAG is configured"""

        rb_list = []
        result = device.vcs.vcs_nodes
        for each_rb in result:
            rb_list.append(each_rb['node-rbridge-id'])
        if len(rb_list) >= 3:
            raise ValueError('VLAG PAIR must be <= 2 leaf nodes')
        return list(set(rb_list))
