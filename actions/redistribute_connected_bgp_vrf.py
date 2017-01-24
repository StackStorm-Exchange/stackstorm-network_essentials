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


class RedistributeConnectedBgpVrf(NosDeviceAction):
    """
       Implements the logic to configure redistribure connected
       under default/non-default vrf address-family on VDX switches.
       This action acheives the below functionality
           1.redistribute connected validation
           2.Check for the existing configuration on the Device,if not present configure it
    """

    def run(self, mgmt_ip, username, password, rbridge_id, ipv4_vrf_name, ipv6_vrf_name,
            ipv4_unicast, ipv6_unicast):
        """Run helper methods to implement the desired state.
        """
        self.setup_connection(host=mgmt_ip, user=username, passwd=password)
        changes = {}
        afi_list = []
        if ipv4_unicast is True:
            afi_list.append('ipv4')
        if ipv6_unicast is True:
            afi_list.append('ipv6')
        if not afi_list:
            raise ValueError('User Input for Address family ipv4/ipv6 unicast is empty')

        vrf_list = []
        if ipv4_vrf_name:
            vrf_list.append(ipv4_vrf_name)
        if ipv6_vrf_name:
            vrf_list.append(ipv6_vrf_name)
        if not ipv4_vrf_name:
            vrf_list.append(None)
        if not ipv6_vrf_name:
            vrf_list.append(None)

        with self.mgr(conn=self.conn, auth=self.auth) as device:
            self.logger.info('successfully connected to %s', self.host)
            if rbridge_id is None:
                rbridge_id = self.vlag_pair(device)

            changes['vrf'] = self._redistribute_connected_bgp_vrf(device,
                                                                  afi_list=afi_list,
                                                                  rbridge_id=rbridge_id,
                                                                  vrf_list=vrf_list)
            self.logger.info(
                'closing connection to %s after configuring redistributed connected'
                ' -- all done!', self.host)
        return changes

    def _redistribute_connected_bgp_vrf(self, device, rbridge_id, vrf_list,
                                        afi_list):
        """Configuring redistribute connceted under VRF AFI under router bgp.
        """
        result = True
        for rbid in rbridge_id:
            rb = str(rbid)
            for temp in zip(afi_list, vrf_list):
                vrf_name = temp[1]
                afi = temp[0]
                if vrf_name:
                    # Configuring redistributed connected under vrf address family
                    vrf_output = device.bgp.vrf_unicast_address_family(
                        rbridge_id=rb, afi=afi,
                        vrf=vrf_name, get=True)

                    if vrf_output is not False:
                        redis = device.bgp.vrf_redistribute_connected(
                            rbridge_id=rb, afi=afi,
                            vrf=vrf_name, get=True)
                        if redis is False:
                            self.logger.info(
                                'Configuring redistribute connected under Address-Family'
                                ' %s unicast vrf %s in rbridge %s', afi, vrf_name,
                                rb)
                            redis = device.bgp.vrf_redistribute_connected(rbridge_id=rb,
                                                                          afi=afi,
                                                                          vrf=vrf_name)
                        else:
                            self.logger.info(
                                'redistribute connected config already present in rbridge %s',
                                rb)
                            result = False
                    else:
                        try:
                            self.logger.info(
                                'Configuring redistribute connected under Address-Family'
                                ' %s unicast vrf %s in rbridge %s', afi, vrf_name,
                                rb)
                            device.bgp.vrf_unicast_address_family(rbridge_id=rb,
                                                                  afi=afi,
                                                                  vrf=vrf_name)
                            device.bgp.vrf_redistribute_connected(rbridge_id=rb,
                                                                  afi=afi,
                                                                  vrf=vrf_name)
                        except (ValueError, KeyError):
                            self.logger.info('Invalid Input values')
                else:
                    # Configuring redistributed connected under address family
                    vrf_output = device.bgp.default_vrf_unicast_address_family(
                        rbridge_id=rb,
                        afi=afi, get=True)

                    if vrf_output is not False:
                        redis = device.bgp.default_vrf_redistribute_connected(
                            rbridge_id=rb, afi=afi,
                            get=True)
                        if redis is False:
                            self.logger.info(
                                'Configuring redistribute connected under Address-Family'
                                ' %s unicast default vrf in rbridge %s', afi, rb)
                            redis = device.bgp.default_vrf_redistribute_connected(
                                rbridge_id=rb,
                                afi=afi)
                        else:
                            self.logger.info(
                                'redistribute connected config already present in rbridge %s',
                                rb)
                            result = False
                    else:
                        try:
                            self.logger.info(
                                'Configuring redistribute connected under Address-Family'
                                ' %s unicast default vrf in rbridge %s', afi, rb)
                            device.bgp.default_vrf_unicast_address_family(
                                rbridge_id=rb, afi=afi)
                            device.bgp.default_vrf_redistribute_connected(
                                rbridge_id=rb, afi=afi)
                        except (ValueError, KeyError):
                            self.logger.info('Invalid Input values')
        return result
